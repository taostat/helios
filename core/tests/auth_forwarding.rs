//! End-to-end checks for `Authorization` forwarding through the
//! Helios JSON-RPC server to the upstream alloy provider.
//!
//! These tests stand up:
//!
//! - a mock upstream HTTP server (`hyper`) that records every
//!   request it sees, plus the `Authorization` header attached;
//! - a real `jsonrpsee` 0.24 server configured with
//!   `AuthCaptureLayer` (http middleware) and `AuthScopeLayer`
//!   (rpc middleware);
//! - an outbound alloy client built with `AuthForwardLayer`;
//! - a real HTTP and WS client that exercises the server.
//!
//! Both the HTTP method path and the WS subscription path are
//! exercised end-to-end to catch regressions in jsonrpsee version
//! bumps that change how request `Extensions` flow.

#![cfg(not(target_arch = "wasm32"))]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use alloy::providers::{Provider, RootProvider};
use alloy::rpc::client::ClientBuilder;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use helios_core::auth_forwarding::{
    auth_from_extensions, scope_with_auth, AuthCaptureLayer, AuthForwardLayer, AuthScopeLayer,
};
use http::Extensions;
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn, Request as HyperRequest, Response as HyperResponse};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ServerConnBuilder;
use jsonrpsee::core::{async_trait, server::Methods, SubscriptionResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::middleware::rpc::RpcServiceBuilder;
use jsonrpsee::server::{
    PendingSubscriptionSink, ServerBuilder, ServerHandle, SubscriptionMessage,
};
use jsonrpsee::types::error::ErrorObjectOwned;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Default)]
struct UpstreamProbe {
    seen_headers: Arc<Mutex<Vec<Option<String>>>>,
}

impl UpstreamProbe {
    fn record(&self, auth: Option<String>) {
        self.seen_headers.lock().unwrap().push(auth);
    }

    fn snapshot(&self) -> Vec<Option<String>> {
        self.seen_headers.lock().unwrap().clone()
    }
}

async fn upstream_handler(
    probe: UpstreamProbe,
    req: HyperRequest<Incoming>,
) -> Result<HyperResponse<Full<Bytes>>, std::convert::Infallible> {
    let auth = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    probe.record(auth);

    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" });
    let response = HyperResponse::builder()
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    Ok(response)
}

async fn spawn_upstream() -> (SocketAddr, UpstreamProbe) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let probe = UpstreamProbe::default();
    let probe_clone = probe.clone();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let probe_inner = probe_clone.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| upstream_handler(probe_inner.clone(), req));
                let _ = ServerConnBuilder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    (addr, probe)
}

fn build_alloy_client(upstream_addr: SocketAddr) -> RootProvider {
    let url: reqwest::Url = format!("http://{upstream_addr}").parse().unwrap();
    let client = ClientBuilder::default()
        .layer(AuthForwardLayer)
        .http(url);
    RootProvider::new(client)
}

#[rpc(server)]
pub trait ProbeRpc {
    #[method(name = "probe_callUpstream")]
    async fn call_upstream(&self) -> Result<String, ErrorObjectOwned>;

    #[subscription(name = "probe_subscribe", unsubscribe = "probe_unsubscribe", item = String, with_extensions)]
    async fn subscribe(&self) -> SubscriptionResult;
}

#[derive(Clone)]
struct ProbeRpcImpl {
    provider: RootProvider,
}

#[async_trait]
impl ProbeRpcServer for ProbeRpcImpl {
    async fn call_upstream(&self) -> Result<String, ErrorObjectOwned> {
        let n = self.provider.get_block_number().await.map_err(|e| {
            ErrorObjectOwned::owned(1, e.to_string(), None::<()>)
        })?;
        Ok(format!("{n}"))
    }

    async fn subscribe(
        &self,
        pending: PendingSubscriptionSink,
        ext: &Extensions,
    ) -> SubscriptionResult {
        let auth = auth_from_extensions(ext);
        let provider = self.provider.clone();
        let sink = pending.accept().await?;

        tokio::spawn(async move {
            scope_with_auth(auth, async move {
                // Trigger one upstream call from inside the spawned subscription task.
                if let Ok(n) = provider.get_block_number().await {
                    let msg = SubscriptionMessage::from_json(&format!("{n}")).unwrap();
                    let _ = sink.send(msg).await;
                }
            })
            .await;
        });
        Ok(())
    }
}

async fn start_helios_like_server(provider: RootProvider) -> (SocketAddr, ServerHandle) {
    let rpc = ProbeRpcImpl { provider };
    let mut methods = Methods::new();
    let m: Methods = ProbeRpcServer::into_rpc(rpc).into();
    methods.merge(m).unwrap();

    let http_middleware = tower::ServiceBuilder::new().layer(AuthCaptureLayer);
    let rpc_middleware = RpcServiceBuilder::new().layer(AuthScopeLayer);
    let server = ServerBuilder::default()
        .set_http_middleware(http_middleware)
        .set_rpc_middleware(rpc_middleware)
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.start(methods);
    (addr, handle)
}

struct TestStack {
    helios_addr: SocketAddr,
    probe: UpstreamProbe,
    _handle: ServerHandle,
}

async fn setup() -> TestStack {
    let (upstream_addr, probe) = spawn_upstream().await;
    let provider = build_alloy_client(upstream_addr);
    let (helios_addr, handle) = start_helios_like_server(provider).await;
    TestStack {
        helios_addr,
        probe,
        _handle: handle,
    }
}

async fn post_rpc(addr: SocketAddr, auth: Option<&str>, url_suffix: &str) -> Value {
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}{url_suffix}"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "probe_callUpstream"
        }));
    if let Some(value) = auth {
        req = req.header(http::header::AUTHORIZATION, value);
    }
    let resp = req.send().await.unwrap();
    assert!(resp.status().is_success(), "status {}", resp.status());
    resp.json().await.unwrap()
}

#[tokio::test]
async fn http_call_forwards_auth_header_to_upstream() {
    let stack = setup().await;
    let json = post_rpc(stack.helios_addr, Some("Bearer http-token"), "").await;
    assert!(json.get("error").is_none(), "rpc error: {json}");
    assert_eq!(
        stack.probe.snapshot(),
        vec![Some("Bearer http-token".into())]
    );
}

#[tokio::test]
async fn http_call_forwards_query_auth_to_upstream() {
    let stack = setup().await;
    let _ = post_rpc(
        stack.helios_addr,
        None,
        "/?authorization=Bearer%20query-token",
    )
    .await;
    assert_eq!(
        stack.probe.snapshot(),
        vec![Some("Bearer query-token".into())]
    );
}

#[tokio::test]
async fn http_call_without_auth_propagates_no_header() {
    let stack = setup().await;
    let _ = post_rpc(stack.helios_addr, None, "").await;
    assert_eq!(stack.probe.snapshot(), vec![None]);
}

#[tokio::test]
async fn ws_subscription_forwards_auth_inside_spawn() {
    let stack = setup().await;

    let mut req = format!("ws://{}", stack.helios_addr)
        .into_client_request()
        .unwrap();
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer ws-token"),
    );

    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let sub_call = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "probe_subscribe"
    });
    ws.send(Message::Text(sub_call.to_string())).await.unwrap();

    let mut got_notif = false;
    let read_loop = async {
        while let Some(Ok(Message::Text(t))) = ws.next().await {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v.get("method").and_then(|m| m.as_str()) == Some("probe_subscribe") {
                got_notif = true;
                return;
            }
        }
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), read_loop).await;
    assert!(got_notif, "did not receive subscription notification");

    assert_eq!(
        stack.probe.snapshot(),
        vec![Some("Bearer ws-token".into())],
        "upstream did not see the WS Authorization"
    );
}
