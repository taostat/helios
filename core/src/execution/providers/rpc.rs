use std::collections::{HashMap, HashSet};

use alloy::{
    consensus::BlockHeader,
    eips::{BlockId, BlockNumberOrTag},
    network::{
        primitives::HeaderResponse, BlockResponse, ReceiptResponse, TransactionBuilder,
        TransactionResponse,
    },
    primitives::{Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rlp,
    rpc::{
        client::ClientBuilder,
        types::{AccessListItem, Filter, FilterBlockOption, Log},
    },
    transports::layers::RetryBackoffLayer,
};
use alloy_trie::{TrieAccount, KECCAK_EMPTY};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::future::{join_all, try_join_all};
use reqwest::Url;

use helios_common::{
    execution_provider::{
        AccountProvider, BlockProvider, ExecutionHintProvider, ExecutionProvider, LogProvider,
        ReceiptProvider, TransactionProvider,
    },
    network_spec::NetworkSpec,
    types::Account,
};

use crate::execution::{
    constants::PARALLEL_QUERY_BATCH_SIZE,
    errors::ExecutionError,
    proof::{
        verify_account_proof, verify_block_receipts, verify_code_hash_proof, verify_storage_proof,
    },
    providers::historical::HistoricalBlockProvider,
};

use super::utils::ensure_logs_match_filter;

// Implementation for unit type to provide no historical block support
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec> HistoricalBlockProvider<N> for () {
    async fn get_historical_block<E>(
        &self,
        _block_id: BlockId,
        _full_tx: bool,
        _execution_provider: &E,
    ) -> Result<Option<N::BlockResponse>>
    where
        E: BlockProvider<N> + AccountProvider<N>,
    {
        Ok(None)
    }
}

pub struct RpcExecutionProvider<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>>
{
    provider: RootProvider<N>,
    block_provider: B,
    historical_provider: Option<H>,
}

impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> ExecutionProvider<N>
    for RpcExecutionProvider<N, B, H>
{
}

impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>>
    RpcExecutionProvider<N, B, H>
{
    pub fn new(rpc_url: Url, block_provider: B) -> RpcExecutionProvider<N, B, ()> {
        #[cfg(not(target_arch = "wasm32"))]
        let client = ClientBuilder::default()
            .layer(crate::auth_forwarding::AuthForwardLayer)
            .layer(RetryBackoffLayer::new(100, 50, 300))
            .http(rpc_url);
        #[cfg(target_arch = "wasm32")]
        let client = ClientBuilder::default()
            .layer(RetryBackoffLayer::new(100, 50, 300))
            .http(rpc_url);

        let provider = ProviderBuilder::<_, _, N>::default().connect_client(client);

        RpcExecutionProvider {
            provider,
            block_provider,
            historical_provider: None,
        }
    }

    pub fn with_historical_provider(
        rpc_url: Url,
        block_provider: B,
        historical_provider: H,
    ) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let client = ClientBuilder::default()
            .layer(crate::auth_forwarding::AuthForwardLayer)
            .layer(RetryBackoffLayer::new(100, 50, 300))
            .http(rpc_url);
        #[cfg(target_arch = "wasm32")]
        let client = ClientBuilder::default()
            .layer(RetryBackoffLayer::new(100, 50, 300))
            .http(rpc_url);

        let provider = ProviderBuilder::<_, _, N>::default().connect_client(client);

        Self {
            provider,
            block_provider,
            historical_provider: Some(historical_provider),
        }
    }

    async fn verify_logs(&self, logs: &[Log]) -> Result<()> {
        // get latest block
        let latest = self
            .get_block(BlockId::Number(BlockNumberOrTag::Latest), false)
            .await?
            .ok_or(eyre!("block not found"))?
            .header()
            .number();

        // Collect all (unique) block numbers
        let block_nums = logs
            .iter()
            .filter_map(|log| log.block_number.filter(|number| *number <= latest))
            .collect::<HashSet<u64>>();

        // Collect all (proven) tx receipts for all block numbers
        let blocks_receipts_fut = block_nums
            .into_iter()
            .map(|block_num| async move { self.get_block_receipts(block_num.into()).await });

        let blocks_receipts = try_join_all(blocks_receipts_fut).await?;
        let receipts = blocks_receipts
            .into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<_>>();

        // Map tx hashes to encoded logs
        let receipts_logs_encoded = receipts
            .into_iter()
            .filter_map(|receipt| {
                let logs = N::receipt_logs(&receipt);
                if logs.is_empty() {
                    None
                } else {
                    let tx_hash = logs[0].transaction_hash.unwrap();
                    let encoded_logs = logs
                        .iter()
                        .map(|l| rlp::encode(&l.inner))
                        .collect::<Vec<_>>();
                    Some((tx_hash, encoded_logs))
                }
            })
            .collect::<HashMap<_, _>>();

        for log in logs {
            // Check if the receipt contains the desired log
            // Encoding logs for comparison
            let tx_hash = log.transaction_hash.unwrap();
            let log_encoded = rlp::encode(&log.inner);
            let receipt_logs_encoded = receipts_logs_encoded.get(&tx_hash).unwrap();

            if !receipt_logs_encoded.contains(&log_encoded) {
                return Err(ExecutionError::MissingLog(
                    tx_hash,
                    U256::from(log.log_index.unwrap()),
                )
                .into());
            }
        }
        Ok(())
    }

    async fn resolve_block_number(&self, block: Option<BlockNumberOrTag>) -> Result<u64> {
        match block {
            Some(BlockNumberOrTag::Latest) | None => {
                let number = self
                    .get_block(BlockId::Number(BlockNumberOrTag::Latest), false)
                    .await?
                    .ok_or(eyre!("block not found"))?
                    .header()
                    .number();

                Ok(number)
            }
            Some(BlockNumberOrTag::Finalized) => {
                let number = self
                    .get_block(BlockId::Number(BlockNumberOrTag::Finalized), false)
                    .await?
                    .ok_or(eyre!("block not found"))?
                    .header()
                    .number();

                Ok(number)
            }
            Some(BlockNumberOrTag::Number(number)) => Ok(number),
            _ => Err(eyre!("block not found")),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> AccountProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_account(
        &self,
        address: Address,
        slots: &[B256],
        with_code: bool,
        block_id: BlockId,
    ) -> Result<Account> {
        let block = self
            .get_block(block_id, false)
            .await?
            .ok_or(eyre!("block not found"))?;

        // Pin every state read for this account to the same block the header
        // came from, so the code we verify is the code the proof commits to.
        let block_ref: BlockId = block.header().hash().into();

        let proof = self
            .provider
            .get_proof(address, slots.to_vec())
            .block_id(block_ref)
            .await?;

        verify_account_proof(&proof, block.header().state_root())?;
        verify_storage_proof(&proof)?;

        let code = if with_code {
            if proof.code_hash == KECCAK_EMPTY || proof.code_hash == B256::ZERO {
                Some(Bytes::new())
            } else {
                let code = self
                    .provider
                    .get_code_at(address)
                    .block_id(block_ref)
                    .await?;
                verify_code_hash_proof(&proof, &code)?;
                Some(code)
            }
        } else {
            None
        };

        Ok(Account {
            account: TrieAccount {
                nonce: proof.nonce,
                balance: proof.balance,
                storage_root: proof.storage_hash,
                code_hash: proof.code_hash,
            },
            code,
            account_proof: proof.account_proof,
            storage_proof: proof.storage_proof,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> BlockProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_block(
        &self,
        block_id: BlockId,
        full_tx: bool,
    ) -> Result<Option<N::BlockResponse>> {
        // 1. Try block cache first
        if let Some(block) = self.block_provider.get_block(block_id, full_tx).await? {
            return Ok(Some(block));
        }

        // 2. Try historical provider if available and only for block numbers or hashes (not tags)
        if let Some(historical) = &self.historical_provider {
            if super::utils::should_use_historical_provider(&block_id) {
                if let Some(block) = historical
                    .get_historical_block(block_id, full_tx, self)
                    .await?
                {
                    // Note: Do NOT cache historical blocks to avoid interfering with consistency detection
                    return Ok(Some(block));
                }
            }
        }

        Ok(None)
    }

    async fn get_untrusted_block(
        &self,
        block_id: BlockId,
        full_tx: bool,
    ) -> Result<Option<<N>::BlockResponse>> {
        if full_tx {
            Ok(self.provider.get_block(block_id).full().await?)
        } else {
            Ok(self.provider.get_block(block_id).hashes().await?)
        }
    }

    async fn push_block(&self, block: N::BlockResponse, block_id: BlockId) {
        self.block_provider.push_block(block, block_id).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> TransactionProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_transaction(&self, hash: B256) -> Result<Option<N::TransactionResponse>> {
        let tx = self.provider.get_transaction_by_hash(hash).await?;
        if let Some(tx) = tx {
            let block_hash = tx.block_hash().ok_or(eyre!("block not found"))?;
            let block = self.get_block(block_hash.into(), true).await?;

            let block = block.ok_or(eyre!("block not found"))?;
            let txs = block.transactions().clone().into_transactions_vec();
            Ok(txs.iter().find(|v| v.tx_hash() == tx.tx_hash()).cloned())
        } else {
            Ok(None)
        }
    }

    async fn get_transaction_by_location(
        &self,
        block_id: BlockId,
        index: u64,
    ) -> Result<Option<N::TransactionResponse>> {
        let block = self.get_block(block_id, true).await?;

        let block = block.ok_or(eyre!("block not found"))?;
        let txs = block.transactions().clone().into_transactions_vec();
        Ok(txs.get(index as usize).cloned())
    }

    async fn send_raw_transaction(&self, bytes: &[u8]) -> Result<B256> {
        let tx = self.provider.send_raw_transaction(bytes).await?;
        Ok(*tx.tx_hash())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> ReceiptProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_receipt(&self, hash: B256) -> Result<Option<N::ReceiptResponse>> {
        let receipt = self
            .provider
            .get_transaction_receipt(hash)
            .await?
            .ok_or(eyre!("receipt not found"))?;

        let block_hash = receipt.block_hash().ok_or(eyre!("block not found"))?;
        let block = self
            .get_block(block_hash.into(), false)
            .await?
            .ok_or(eyre!("block not found"))?;

        let receipts = self
            .provider
            .get_block_receipts(block_hash.into())
            .await?
            .ok_or(eyre!("block not found"))?;

        verify_block_receipts::<N>(&receipts, &block)?;
        Ok(receipts
            .iter()
            .find(|receipt| receipt.transaction_hash() == hash)
            .cloned())
    }

    async fn get_block_receipts(
        &self,
        block_id: BlockId,
    ) -> Result<Option<Vec<N::ReceiptResponse>>> {
        let Some(block) = self.get_block(block_id, false).await? else {
            return Ok(None);
        };

        let receipts = self
            .provider
            .get_block_receipts(block.header().hash().into())
            .await?
            .ok_or(eyre!("receipt fetch failed"))?;

        verify_block_receipts::<N>(&receipts, &block)?;
        Ok(Some(receipts))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> LogProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        let block_option = match filter.block_option {
            FilterBlockOption::Range {
                from_block,
                to_block,
            } => {
                let from = self.resolve_block_number(from_block).await?;
                let to = self.resolve_block_number(to_block).await?;
                FilterBlockOption::Range {
                    from_block: Some(BlockNumberOrTag::Number(from)),
                    to_block: Some(BlockNumberOrTag::Number(to)),
                }
            }
            FilterBlockOption::AtBlockHash(hash) => FilterBlockOption::AtBlockHash(hash),
        };

        let mut filter = filter.clone();
        filter.block_option = block_option;

        let logs = self.provider.get_logs(&filter).await?;
        self.verify_logs(&logs).await?;
        ensure_logs_match_filter(&logs, &filter)?;
        Ok(logs)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> ExecutionHintProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_execution_hint(
        &self,
        tx: &N::TransactionRequest,
        _validate: bool,
        block_id: BlockId,
    ) -> Result<HashMap<Address, Account>> {
        let block = self
            .get_block(block_id, false)
            .await?
            .ok_or(eyre!("block not found"))?;

        let mut list = self
            .provider
            .create_access_list(tx)
            .block_id(block_id)
            .await?
            .access_list
            .0;

        let from_access_entry = AccessListItem {
            address: tx.from().unwrap_or_default(),
            storage_keys: Vec::default(),
        };
        let to_access_entry = AccessListItem {
            address: tx.to().unwrap_or_default(),
            storage_keys: Vec::default(),
        };
        let producer_access_entry = AccessListItem {
            address: block.header().beneficiary(),
            storage_keys: Vec::default(),
        };

        let mut list_addresses = list.iter().map(|elem| elem.address).collect::<HashSet<_>>();

        if list_addresses.insert(from_access_entry.address) {
            list.push(from_access_entry)
        }
        if list_addresses.insert(to_access_entry.address) {
            list.push(to_access_entry)
        }
        if list_addresses.insert(producer_access_entry.address) {
            list.push(producer_access_entry)
        }

        let mut account_map = HashMap::new();
        for chunk in list.chunks(PARALLEL_QUERY_BATCH_SIZE) {
            let account_chunk_futs = chunk.iter().map(|account| {
                let account_fut =
                    self.get_account(account.address, &account.storage_keys, true, block_id);
                async move { (account.address, account_fut.await) }
            });

            let account_chunk = join_all(account_chunk_futs).await;

            for (address, value) in account_chunk {
                let account = value?;
                account_map.insert(address, account);
            }
        }

        Ok(account_map)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use alloy::network::Network;
    use alloy::primitives::bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes as HyperBytes;
    use hyper::service::service_fn;
    use hyper::{Request as HttpRequest, Response as HttpResponse};
    use hyper_util::rt::TokioIo;
    use serde_json::{json, Value};
    use tokio::net::TcpListener;

    use helios_ethereum::spec::Ethereum;
    use helios_test_utils::{rpc_account, rpc_block, rpc_proof};

    use super::*;

    /// Serves the one fixture block for every block id, so the test exercises
    /// only the account/code path of `get_account`.
    struct StaticBlockProvider(<Ethereum as Network>::BlockResponse);

    #[async_trait]
    impl BlockProvider<Ethereum> for StaticBlockProvider {
        async fn push_block(&self, _block: <Ethereum as Network>::BlockResponse, _id: BlockId) {}

        async fn get_block(
            &self,
            _block_id: BlockId,
            _full_tx: bool,
        ) -> Result<Option<<Ethereum as Network>::BlockResponse>> {
            Ok(Some(self.0.clone()))
        }

        async fn get_untrusted_block(
            &self,
            _block_id: BlockId,
            _full_tx: bool,
        ) -> Result<Option<<Ethereum as Network>::BlockResponse>> {
            Ok(Some(self.0.clone()))
        }
    }

    /// A local JSON-RPC server that records every (method, params) it is asked
    /// for, so a test can assert on the requests helios *makes*, not only on
    /// the answers it happens to accept.
    struct MockRpc {
        url: Url,
        calls: Arc<Mutex<Vec<(String, Value)>>>,
    }

    impl MockRpc {
        async fn spawn<F>(respond: F) -> Self
        where
            F: Fn(&str, &Value) -> Value + Send + Sync + 'static,
        {
            let calls: Arc<Mutex<Vec<(String, Value)>>> = Arc::new(Mutex::new(Vec::new()));
            let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let respond = Arc::new(respond);
            let calls_srv = calls.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let respond = respond.clone();
                    let calls = calls_srv.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |req: HttpRequest<hyper::body::Incoming>| {
                            let respond = respond.clone();
                            let calls = calls.clone();
                            async move {
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let req: Value = serde_json::from_slice(&body).unwrap();
                                let method = req["method"].as_str().unwrap().to_string();
                                let params = req["params"].clone();
                                calls.lock().unwrap().push((method.clone(), params.clone()));
                                let result = respond(&method, &params);
                                let resp = json!({
                                    "jsonrpc": "2.0",
                                    "id": req["id"].clone(),
                                    "result": result,
                                });
                                Ok::<_, Infallible>(HttpResponse::new(Full::new(HyperBytes::from(
                                    serde_json::to_vec(&resp).unwrap(),
                                ))))
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });

            MockRpc {
                url: Url::parse(&format!("http://{addr}")).unwrap(),
                calls,
            }
        }

        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().unwrap().clone()
        }
    }

    fn provider_for(mock: &MockRpc) -> RpcExecutionProvider<Ethereum, StaticBlockProvider, ()> {
        RpcExecutionProvider::<Ethereum, StaticBlockProvider, ()>::new(
            mock.url.clone(),
            StaticBlockProvider(rpc_block()),
        )
    }

    /// The code an account carries is not fixed for all time — EIP-7702 lets an
    /// EOA gain, change and drop a delegation designator — so code read at
    /// `latest` cannot be checked against a code hash proven at some other
    /// block. This mock answers `eth_getCode` correctly only when the request
    /// names the fixture block, and returns different (but well-formed) code
    /// for any other block reference.
    fn code_only_at_fixture_block(method: &str, params: &Value) -> Value {
        match method {
            "eth_getProof" => serde_json::to_value(rpc_proof()).unwrap(),
            "eth_getCode" => {
                let asked_for = &params[1];
                let block_hash = rpc_block().header().hash();
                let names_fixture_block = *asked_for == json!({ "blockHash": block_hash });
                if names_fixture_block {
                    json!(rpc_account().code.unwrap())
                } else {
                    // Stands in for "the account's code has changed since".
                    json!(bytes!("0xef0100000000000000000000000000000000000000ff"))
                }
            }
            other => panic!("unexpected upstream call: {other}"),
        }
    }

    /// Regression: helios must read the account's code at the block whose state
    /// root it verifies the code hash against. Reading it at `latest` makes
    /// every historical query fail for any account whose code has since changed.
    #[tokio::test]
    async fn code_is_read_at_the_requested_block_not_at_latest() {
        let mock = MockRpc::spawn(code_only_at_fixture_block).await;
        let provider = provider_for(&mock);

        let block = rpc_block();
        let proof = rpc_proof();
        let result = provider
            .get_account(
                proof.address,
                &[],
                true,
                BlockId::number(block.header().number()),
            )
            .await;

        // Assert the requests first: this is the invariant, and it is what goes
        // red the moment the block reference is dropped from either read.
        let block_ref = json!({ "blockHash": block.header().hash() });
        assert_eq!(
            mock.calls(),
            vec![
                (
                    "eth_getProof".to_string(),
                    json!([proof.address, [], block_ref]),
                ),
                ("eth_getCode".to_string(), json!([proof.address, block_ref])),
            ],
            "both the proof and the code must be read at the requested block"
        );

        let account = result.expect("account must verify when code is read at the right block");
        assert_eq!(
            account.code.expect("code requested"),
            rpc_account().code.unwrap(),
            "the code returned must be the code at the requested block"
        );
    }

    /// The fix must not weaken the check: code that does not hash to the
    /// state-root-proven code hash is still rejected, whatever block it came
    /// from and whatever it looks like.
    #[tokio::test]
    async fn code_that_does_not_match_the_proven_hash_is_still_rejected() {
        let mock = MockRpc::spawn(|method, _params| match method {
            "eth_getProof" => serde_json::to_value(rpc_proof()).unwrap(),
            // Served for *every* block reference, including the right one.
            "eth_getCode" => json!(bytes!("0xef0100000000000000000000000000000000000000ff")),
            other => panic!("unexpected upstream call: {other}"),
        })
        .await;
        let provider = provider_for(&mock);

        let block = rpc_block();
        let proof = rpc_proof();
        let err = provider
            .get_account(
                proof.address,
                &[],
                true,
                BlockId::number(block.header().number()),
            )
            .await
            .expect_err("code that does not match the proven code hash must be rejected");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("code hash mismatch")
                && msg.contains(&proof.code_hash.to_string())
                && msg.contains(&proof.address.to_string()),
            "expected a code hash mismatch naming the address and the proven hash, got: {msg}"
        );
    }
}
