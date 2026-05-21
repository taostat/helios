//! Forward inbound `Authorization` credentials to upstream RPC calls.
//!
//! Helios is often deployed behind a gateway that authenticates each
//! caller with a per-customer token. The same token must reach the
//! upstream `--execution-rpc` provider, otherwise the upstream rejects
//! every call Helios makes on the user's behalf.
//!
//! The flow is:
//!
//! 1. Inbound HTTP middleware ([`AuthCaptureLayer`]) reads the
//!    `Authorization` header (or, as a fallback, the `?authorization=`
//!    query parameter) off the inbound request and stores the value
//!    in the request's [`http::Extensions`].
//! 2. A JSON-RPC service middleware ([`AuthScopeLayer`]) lifts the
//!    captured value into the [`FORWARDED_AUTH`] task-local for the
//!    lifetime of a single JSON-RPC call.
//! 3. The outbound alloy transport layer ([`AuthForwardLayer`]) reads
//!    the task-local and attaches the value as an `Authorization`
//!    header on the upstream HTTP request.
//!
//! WebSocket subscriptions need extra care: each subscription event
//! is forwarded from a freshly spawned task that does not inherit
//! Tokio task-locals, so subscription handlers must re-establish the
//! scope themselves before doing upstream work — see
//! [`scope_with_auth`].

use std::env;
use std::task::{Context, Poll};

use alloy::rpc::json_rpc::{RequestPacket, ResponsePacket};
use alloy::transports::TransportError;
use futures::future::BoxFuture;
use http::{Extensions, HeaderValue};
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::Request as RpcRequest;
use url::form_urlencoded;

const AUTH_QUERY_KEY: &str = "authorization";
const ENV_VAR_NAME: &str = "HELIOS_FORWARD_AUTH";
const ENABLED_VALUE: &str = "1";

/// Wrapper around a captured `Authorization` header so it can be
/// distinguished from other [`http::Extensions`] values.
#[derive(Clone, Debug)]
pub struct AuthValue(HeaderValue);

impl AuthValue {
    /// Borrow the wrapped header value.
    pub fn header(&self) -> &HeaderValue {
        &self.0
    }
}

tokio::task_local! {
    /// The `Authorization` value currently in scope for outbound
    /// RPC calls. Set by [`AuthScopeLayer`] before a JSON-RPC method
    /// body runs, and re-established inside subscription spawns via
    /// [`scope_with_auth`].
    pub static FORWARDED_AUTH: Option<AuthValue>;
}

/// Returns `true` when `HELIOS_FORWARD_AUTH=1` is set.
///
/// Helios's RPC server only installs the forwarding middleware when
/// this returns `true`, so unconfigured deployments behave exactly
/// as before.
pub fn is_enabled() -> bool {
    matches!(env::var(ENV_VAR_NAME).as_deref(), Ok(v) if v == ENABLED_VALUE)
}

/// Look up the captured [`AuthValue`] from a JSON-RPC request's
/// extensions. Returns `None` if no inbound auth was captured.
pub fn auth_from_extensions(ext: &Extensions) -> Option<AuthValue> {
    ext.get::<AuthValue>().cloned()
}

/// Run `fut` with [`FORWARDED_AUTH`] set to `auth`.
///
/// Subscription handlers `tokio::spawn` event-forwarding loops; the
/// resulting task does not inherit task-locals from its parent, so
/// each spawned future that may call upstream must wrap its body in
/// this helper.
pub async fn scope_with_auth<F, T>(auth: Option<AuthValue>, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    FORWARDED_AUTH.scope(auth, fut).await
}

// ---------- Inbound capture: HTTP-level tower middleware ----------

/// Tower layer that captures `Authorization` (header or
/// `?authorization=` query parameter) from inbound HTTP requests
/// and stores the value in the request's [`http::Extensions`] as
/// an [`AuthValue`].
///
/// Works for both plain HTTP RPC and WebSocket upgrade requests:
/// jsonrpsee 0.24 clones the upgrade request's extensions onto the
/// per-frame RPC request, so the captured value remains available
/// for the lifetime of the WebSocket connection.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthCaptureLayer;

impl<S> tower::Layer<S> for AuthCaptureLayer {
    type Service = AuthCaptureService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthCaptureService { inner }
    }
}

#[derive(Clone, Debug)]
pub struct AuthCaptureService<S> {
    inner: S,
}

impl<S, ReqBody> tower::Service<http::Request<ReqBody>> for AuthCaptureService<S>
where
    S: tower::Service<http::Request<ReqBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<ReqBody>) -> Self::Future {
        if let Some(value) = extract_auth_from_request(&req) {
            req.extensions_mut().insert(AuthValue(value));
        }
        self.inner.call(req)
    }
}

fn extract_auth_from_request<B>(req: &http::Request<B>) -> Option<HeaderValue> {
    if let Some(value) = req.headers().get(http::header::AUTHORIZATION) {
        return Some(value.clone());
    }
    extract_auth_from_query(req.uri().query()?)
}

fn extract_auth_from_query(query: &str) -> Option<HeaderValue> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k.eq_ignore_ascii_case(AUTH_QUERY_KEY))
        .and_then(|(_, v)| HeaderValue::from_str(&v).ok())
}

// ---------- JSON-RPC scope: hoist captured value into task-local ----------

/// Layer that, for each JSON-RPC call, scopes [`FORWARDED_AUTH`]
/// to whatever [`AuthValue`] the inbound capture middleware
/// recorded in the request's extensions.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthScopeLayer;

impl<S> tower::Layer<S> for AuthScopeLayer {
    type Service = AuthScopeService<S>;

    fn layer(&self, service: S) -> Self::Service {
        AuthScopeService { service }
    }
}

#[derive(Clone, Debug)]
pub struct AuthScopeService<S> {
    service: S,
}

impl<'a, S> RpcServiceT<'a> for AuthScopeService<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'static,
{
    type Future = BoxFuture<'a, jsonrpsee::core::server::MethodResponse>;

    fn call(&self, request: RpcRequest<'a>) -> Self::Future {
        let auth = auth_from_extensions(request.extensions());
        let service = self.service.clone();
        Box::pin(async move { FORWARDED_AUTH.scope(auth, service.call(request)).await })
    }
}

// ---------- Outbound forwarding: alloy tower layer ----------

/// Alloy tower layer that attaches the in-scope [`FORWARDED_AUTH`]
/// value to every outbound request as an `Authorization` header.
///
/// Operates on alloy's [`RequestPacket`]: for both single and batch
/// packets, it inserts a [`http::HeaderMap`] into each request's
/// metadata extensions. The default `Http<reqwest::Client>` transport
/// reads that map and forwards the headers on the underlying HTTP
/// request.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthForwardLayer;

impl<S> tower::Layer<S> for AuthForwardLayer {
    type Service = AuthForwardService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthForwardService { inner }
    }
}

#[derive(Clone, Debug)]
pub struct AuthForwardService<S> {
    inner: S,
}

impl<S> tower::Service<RequestPacket> for AuthForwardService<S>
where
    S: tower::Service<RequestPacket, Response = ResponsePacket, Error = TransportError>,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: RequestPacket) -> Self::Future {
        let _ = FORWARDED_AUTH.try_with(|auth| {
            let Some(AuthValue(value)) = auth.as_ref() else {
                return;
            };
            let serialized: &mut [_] = match &mut req {
                RequestPacket::Single(s) => std::slice::from_mut(s),
                RequestPacket::Batch(b) => b.as_mut_slice(),
            };
            for s in serialized {
                let mut headers = http::HeaderMap::with_capacity(1);
                headers.insert(http::header::AUTHORIZATION, value.clone());
                s.meta_mut().extensions_mut().insert(headers);
            }
        });
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::rpc::json_rpc::Request;
    use std::sync::{Arc, Mutex};
    use tower::{Layer, ServiceExt};

    #[test]
    fn extract_query_finds_authorization_case_insensitive() {
        let v = extract_auth_from_query("foo=bar&Authorization=Bearer%20xyz&baz=qux").unwrap();
        assert_eq!(v.to_str().unwrap(), "Bearer xyz");
    }

    #[test]
    fn extract_query_decodes_plus_as_space() {
        let v = extract_auth_from_query("authorization=Bearer+abc").unwrap();
        assert_eq!(v.to_str().unwrap(), "Bearer abc");
    }

    #[test]
    fn extract_query_missing_returns_none() {
        assert!(extract_auth_from_query("foo=bar").is_none());
    }

    #[derive(Clone, Default)]
    struct CapturedExtensions(Arc<Mutex<Option<Option<HeaderValue>>>>);

    impl<B: Send + 'static> tower::Service<http::Request<B>> for CapturedExtensions {
        type Response = http::Response<()>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let value = req.extensions().get::<AuthValue>().map(|a| a.0.clone());
            *self.0.lock().unwrap() = Some(value);
            Box::pin(async move { Ok(http::Response::new(())) })
        }
    }

    #[tokio::test]
    async fn capture_layer_extracts_from_header() {
        let probe = CapturedExtensions::default();
        let svc = AuthCaptureLayer.layer(probe.clone());

        let req = http::Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer token-xyz")
            .body(())
            .unwrap();
        svc.oneshot(req).await.unwrap();

        let got = probe.0.lock().unwrap().clone().unwrap();
        assert_eq!(got.unwrap().to_str().unwrap(), "Bearer token-xyz");
    }

    #[tokio::test]
    async fn capture_layer_extracts_from_query() {
        let probe = CapturedExtensions::default();
        let svc = AuthCaptureLayer.layer(probe.clone());

        let req = http::Request::builder()
            .uri("/?authorization=Bearer%20abc")
            .body(())
            .unwrap();
        svc.oneshot(req).await.unwrap();

        let got = probe.0.lock().unwrap().clone().unwrap();
        assert_eq!(got.unwrap().to_str().unwrap(), "Bearer abc");
    }

    #[tokio::test]
    async fn capture_layer_prefers_header_over_query() {
        let probe = CapturedExtensions::default();
        let svc = AuthCaptureLayer.layer(probe.clone());

        let req = http::Request::builder()
            .uri("/?authorization=from-query")
            .header(http::header::AUTHORIZATION, "from-header")
            .body(())
            .unwrap();
        svc.oneshot(req).await.unwrap();

        let got = probe.0.lock().unwrap().clone().unwrap();
        assert_eq!(got.unwrap().to_str().unwrap(), "from-header");
    }

    #[tokio::test]
    async fn capture_layer_absent_is_none() {
        let probe = CapturedExtensions::default();
        let svc = AuthCaptureLayer.layer(probe.clone());

        let req = http::Request::builder().body(()).unwrap();
        svc.oneshot(req).await.unwrap();

        assert_eq!(probe.0.lock().unwrap().clone(), Some(None));
    }

    #[derive(Clone, Default)]
    struct PacketProbe(Arc<Mutex<Option<http::HeaderMap>>>);

    impl tower::Service<RequestPacket> for PacketProbe {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: RequestPacket) -> Self::Future {
            let observed = match &req {
                RequestPacket::Single(s) => s.meta().extensions().get::<http::HeaderMap>().cloned(),
                RequestPacket::Batch(_) => None,
            };
            *self.0.lock().unwrap() = observed;
            Box::pin(async move {
                Err::<ResponsePacket, _>(alloy::transports::TransportErrorKind::custom_str("probe"))
            })
        }
    }

    fn make_packet() -> RequestPacket {
        let req: Request<()> = Request::new("eth_blockNumber", 1u64.into(), ());
        RequestPacket::Single(req.serialize().unwrap())
    }

    #[tokio::test]
    async fn forward_layer_injects_header_when_task_local_set() {
        let probe = PacketProbe::default();
        let mut svc = AuthForwardLayer.layer(probe.clone());

        let value = HeaderValue::from_static("Bearer token-xyz");
        FORWARDED_AUTH
            .scope(Some(AuthValue(value.clone())), async {
                let _ = tower::Service::call(&mut svc, make_packet()).await;
            })
            .await;

        let observed = probe.0.lock().unwrap().clone().expect("HeaderMap injected");
        assert_eq!(observed.get(http::header::AUTHORIZATION), Some(&value));
    }

    #[tokio::test]
    async fn forward_layer_noop_when_task_local_unset() {
        let probe = PacketProbe::default();
        let mut svc = AuthForwardLayer.layer(probe.clone());

        let _ = tower::Service::call(&mut svc, make_packet()).await;
        assert!(probe.0.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn forward_layer_injects_for_each_batch_entry() {
        #[derive(Clone, Default)]
        struct BatchProbe(Arc<Mutex<Vec<Option<http::HeaderMap>>>>);

        impl tower::Service<RequestPacket> for BatchProbe {
            type Response = ResponsePacket;
            type Error = TransportError;
            type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: RequestPacket) -> Self::Future {
                let observed = match &req {
                    RequestPacket::Single(s) => {
                        vec![s.meta().extensions().get::<http::HeaderMap>().cloned()]
                    }
                    RequestPacket::Batch(b) => b
                        .iter()
                        .map(|s| s.meta().extensions().get::<http::HeaderMap>().cloned())
                        .collect(),
                };
                *self.0.lock().unwrap() = observed;
                Box::pin(async move {
                    Err::<ResponsePacket, _>(alloy::transports::TransportErrorKind::custom_str(
                        "probe",
                    ))
                })
            }
        }

        let probe = BatchProbe::default();
        let mut svc = AuthForwardLayer.layer(probe.clone());

        let mut packet = make_packet();
        packet.push(
            Request::<()>::new("eth_chainId", 2u64.into(), ())
                .serialize()
                .unwrap(),
        );

        let value = HeaderValue::from_static("Bearer batch-token");
        FORWARDED_AUTH
            .scope(Some(AuthValue(value.clone())), async {
                let _ = tower::Service::call(&mut svc, packet).await;
            })
            .await;

        let observed = probe.0.lock().unwrap().clone();
        assert_eq!(observed.len(), 2);
        for hm in observed {
            assert_eq!(hm.unwrap().get(http::header::AUTHORIZATION), Some(&value));
        }
    }

    #[test]
    fn is_enabled_reads_env_var() {
        let prior = env::var(ENV_VAR_NAME).ok();

        unsafe { env::set_var(ENV_VAR_NAME, ENABLED_VALUE) };
        assert!(is_enabled());

        unsafe { env::set_var(ENV_VAR_NAME, "0") };
        assert!(!is_enabled());

        unsafe { env::remove_var(ENV_VAR_NAME) };
        assert!(!is_enabled());

        match prior {
            Some(v) => unsafe { env::set_var(ENV_VAR_NAME, v) },
            None => unsafe { env::remove_var(ENV_VAR_NAME) },
        }
    }
}
