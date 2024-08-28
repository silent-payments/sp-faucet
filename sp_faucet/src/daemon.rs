use anyhow::{Context, Error, Result};

use bitcoincore_rpc::json::{
    CreateRawTransactionInput, ListUnspentQueryOptions, ListUnspentResultEntry,
    WalletCreateFundedPsbtOptions,
};
use bitcoincore_rpc::{json, jsonrpc, Auth, Client, RpcApi};
use log::info;
use sp_client::bitcoin::bip158::BlockFilter;
use sp_client::bitcoin::{
    block, Address, Amount, Block, BlockHash, Network, OutPoint, Psbt, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid,
};
use sp_client::bitcoin::{consensus::deserialize, hashes::hex::FromHex};
// use crossbeam_channel::Receiver;
// use parking_lot::Mutex;
use serde_json::{json, Value};

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

pub struct SensitiveAuth(pub Auth);

impl SensitiveAuth {
    pub(crate) fn get_auth(&self) -> Auth {
        self.0.clone()
    }
}

enum PollResult {
    Done(Result<()>),
    Retry,
}

fn rpc_poll(client: &mut Client, skip_block_download_wait: bool) -> PollResult {
    match client.get_blockchain_info() {
        Ok(info) => {
            if skip_block_download_wait {
                // bitcoind RPC is available, don't wait for block download to finish
                return PollResult::Done(Ok(()));
            }
            let left_blocks = info.headers - info.blocks;
            if info.initial_block_download || left_blocks > 0 {
                log::info!(
                    "waiting for {} blocks to download{}",
                    left_blocks,
                    if info.initial_block_download {
                        " (IBD)"
                    } else {
                        ""
                    }
                );
                return PollResult::Retry;
            }
            PollResult::Done(Ok(()))
        }
        Err(err) => {
            if let Some(e) = extract_bitcoind_error(&err) {
                if e.code == -28 {
                    log::debug!("waiting for RPC warmup: {}", e.message);
                    return PollResult::Retry;
                }
            }
            PollResult::Done(Err(err).context("daemon not available"))
        }
    }
}

fn read_cookie(path: &Path) -> Result<(String, String)> {
    // Load username and password from bitcoind cookie file:
    // * https://github.com/bitcoin/bitcoin/pull/6388/commits/71cbeaad9a929ba6a7b62d9b37a09b214ae00c1a
    // * https://bitcoin.stackexchange.com/questions/46782/rpc-cookie-authentication
    let mut file = File::open(path)
        .with_context(|| format!("failed to open bitcoind cookie file: {}", path.display()))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("failed to read bitcoind cookie from {}", path.display()))?;

    let parts: Vec<&str> = contents.splitn(2, ':').collect();
    anyhow::ensure!(
        parts.len() == 2,
        "failed to parse bitcoind cookie - missing ':' separator"
    );
    Ok((parts[0].to_owned(), parts[1].to_owned()))
}

fn rpc_connect(rpcwallet: Option<String>, network: Network, mut rpc_url: String) -> Result<Client> {
    match rpcwallet {
        Some(rpcwallet) => rpc_url.push_str(&rpcwallet),
        None => (),
    }

    // Allow `wait_for_new_block` to take a bit longer before timing out.
    // See https://github.com/romanz/electrs/issues/495 for more details.
    let builder = jsonrpc::simple_http::SimpleHttpTransport::builder()
        .url(&rpc_url)?
        .timeout(Duration::from_secs(30));
    let home = env::var("HOME")?;
    let mut cookie_path = PathBuf::from_str(&home)?;
    cookie_path.push(".bitcoin");
    cookie_path.push(network.to_core_arg());
    cookie_path.push(".cookie");
    let daemon_auth = SensitiveAuth(Auth::CookieFile(cookie_path));
    let builder = match daemon_auth.get_auth() {
        Auth::None => builder,
        Auth::UserPass(user, pass) => builder.auth(user, Some(pass)),
        Auth::CookieFile(path) => {
            let (user, pass) = read_cookie(&path)?;
            builder.auth(user, Some(pass))
        }
    };
    Ok(Client::from_jsonrpc(jsonrpc::Client::with_transport(
        builder.build(),
    )))
}

#[derive(Debug)]
pub struct Daemon {
    // p2p: Mutex<Connection>,
    rpc: Client,
}

impl Daemon {
    pub(crate) fn connect(
        rpcwallet: Option<String>,
        rpc_url: String,
        network: Network,
        // config: &Config,
        // exit_flag: &ExitFlag,
        // metrics: &Metrics,
    ) -> Result<Self> {
        let rpc_url = format!("{}/wallet/default", rpc_url);
        let mut rpc = rpc_connect(rpcwallet, network, rpc_url)?;

        //rpc.load_wallet("default").unwrap();

        loop {
            match rpc_poll(&mut rpc, false) {
                PollResult::Done(result) => {
                    result.context("bitcoind RPC polling failed")?;
                    break; // on success, finish polling
                }
                PollResult::Retry => {
                    std::thread::sleep(std::time::Duration::from_secs(1)); // wait a bit before polling
                }
            }
        }

        let network_info = rpc.get_network_info()?;
        // if network_info.version < 21_00_00 {
        //     bail!("electrs requires bitcoind 0.21+");
        // }
        if !network_info.network_active {
            anyhow::bail!("electrs requires active bitcoind p2p network");
        }
        let info = rpc.get_blockchain_info()?;
        if info.pruned {
            anyhow::bail!("electrs requires non-pruned bitcoind node");
        }

        // let p2p = tokio::sync::Mutex::new(Connection::connect(
        //     config.network,
        //     config.daemon_p2p_addr,
        //     metrics,
        //     config.signet_magic,
        // )?);
        Ok(Self { rpc })
    }

    pub(crate) fn estimate_fee(&self, nblocks: u16) -> Result<Amount> {
        let res = self
            .rpc
            .estimate_smart_fee(nblocks, None)
            .context("failed to estimate fee")?;
        if res.errors.is_some() {
            Err(Error::msg(serde_json::to_string(&res.errors.unwrap())?))
        } else {
            Ok(res.fee_rate.unwrap())
        }
    }

    pub(crate) fn get_relay_fee(&self) -> Result<Amount> {
        Ok(self
            .rpc
            .get_network_info()
            .context("failed to get relay fee")?
            .relay_fee)
    }

    pub(crate) fn get_current_height(&self) -> Result<u64> {
        Ok(self
            .rpc
            .get_block_count()
            .context("failed to get block count")?)
    }

    pub(crate) fn get_block(&self, block_hash: BlockHash) -> Result<Block> {
        Ok(self
            .rpc
            .get_block(&block_hash)
            .context("failed to get block")?)
    }

    pub(crate) fn get_filters(&self, block_height: u32) -> Result<(u32, BlockHash, BlockFilter)> {
        let block_hash = self.rpc.get_block_hash(block_height.try_into()?)?;
        let filter = self
            .rpc
            .get_block_filter(&block_hash)
            .context("failed to get block filter")?
            .into_filter();
        Ok((block_height, block_hash, filter))
    }

    pub(crate) fn list_unspent_min_sum(
        &self,
        minamt: Amount,
    ) -> Result<Vec<json::ListUnspentResultEntry>> {
        Ok(self.rpc.list_unspent(
            None,
            None,
            None,
            Some(false),
            Some(ListUnspentQueryOptions {
                minimum_sum_amount: Some(minamt),
                ..Default::default()
            }),
        )?)
    }

    pub(crate) fn create_psbt(
        &self,
        unspents: &[ListUnspentResultEntry],
        spk: ScriptBuf,
        network: Network,
    ) -> Result<String> {
        let inputs: Vec<CreateRawTransactionInput> = unspents
            .iter()
            .map(|utxo| CreateRawTransactionInput {
                txid: utxo.txid,
                vout: utxo.vout,
                sequence: None,
            })
            .collect();
        let address = Address::from_script(&spk, network)?;
        let total_amt = unspents
            .iter()
            .fold(Amount::from_sat(0), |acc, x| acc + x.amount);

        let mut outputs = HashMap::new();
        outputs.insert(address.to_string(), total_amt);

        let options = WalletCreateFundedPsbtOptions {
            subtract_fee_from_outputs: vec![0],
            ..Default::default()
        };

        let wallet_create_funded_result =
            self.rpc
                .wallet_create_funded_psbt(&inputs, &outputs, None, Some(options), None)?;

        Ok(wallet_create_funded_result.psbt.to_string())
    }

    pub(crate) fn process_psbt(&self, psbt: String) -> Result<String> {
        let processed_psbt = self.rpc.wallet_process_psbt(&psbt, None, None, None)?;
        match processed_psbt.complete {
            true => Ok(processed_psbt.psbt),
            false => Err(Error::msg("Failed to complete the psbt")),
        }
    }

    pub(crate) fn finalize_psbt(&self, psbt: String) -> Result<String> {
        let final_tx = self.rpc.finalize_psbt(&psbt, Some(false))?;

        match final_tx.complete {
            true => Ok(final_tx
                .psbt
                .expect("We shouldn't have an empty psbt for a complete return")),
            false => Err(Error::msg("Failed to finalize psbt")),
        }
    }

    pub(crate) fn get_network(&self) -> Result<Network> {
        let blockchain_info = self.rpc.get_blockchain_info()?;

        Ok(blockchain_info.chain)
    }

    pub(crate) fn test_mempool_accept(
        &self,
        tx: &Transaction,
    ) -> Result<crate::bitcoin_json::TestMempoolAcceptResult> {
        let res = self.rpc.test_mempool_accept(&vec![tx])?;

        Ok(res.get(0).unwrap().clone())
    }

    pub(crate) fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let txid = self.rpc.send_raw_transaction(tx)?;

        Ok(txid)
    }

    pub(crate) fn get_transaction_info(
        &self,
        txid: &Txid,
        blockhash: Option<BlockHash>,
    ) -> Result<Value> {
        // No need to parse the resulting JSON, just return it as-is to the client.
        self.rpc
            .call(
                "getrawtransaction",
                &[json!(txid), json!(true), json!(blockhash)],
            )
            .context("failed to get transaction info")
    }

    pub(crate) fn get_transaction_hex(
        &self,
        txid: &Txid,
        blockhash: Option<BlockHash>,
    ) -> Result<Value> {
        use sp_client::bitcoin::consensus::serde::{hex::Lower, Hex, With};

        let tx = self.get_transaction(txid, blockhash)?;
        #[derive(serde::Serialize)]
        #[serde(transparent)]
        struct TxAsHex(#[serde(with = "With::<Hex<Lower>>")] Transaction);
        serde_json::to_value(TxAsHex(tx)).map_err(Into::into)
    }

    pub(crate) fn get_transaction(
        &self,
        txid: &Txid,
        blockhash: Option<BlockHash>,
    ) -> Result<Transaction> {
        self.rpc
            .get_raw_transaction(txid, blockhash.as_ref())
            .context("failed to get transaction")
    }

    pub(crate) fn get_block_txids(&self, blockhash: BlockHash) -> Result<Vec<Txid>> {
        Ok(self
            .rpc
            .get_block_info(&blockhash)
            .context("failed to get block txids")?
            .tx)
    }

    pub(crate) fn get_mempool_txids(&self) -> Result<Vec<Txid>> {
        self.rpc
            .get_raw_mempool()
            .context("failed to get mempool txids")
    }

    pub(crate) fn get_mempool_entries(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Result<json::GetMempoolEntryResult>>> {
        let client = self.rpc.get_jsonrpc_client();
        log::debug!("getting {} mempool entries", txids.len());
        let args: Vec<_> = txids
            .iter()
            .map(|txid| vec![serde_json::value::to_raw_value(txid).unwrap()])
            .collect();
        let reqs: Vec<_> = args
            .iter()
            .map(|a| client.build_request("getmempoolentry", a))
            .collect();
        let res = client.send_batch(&reqs).context("batch request failed")?;
        log::debug!("got {} mempool entries", res.len());
        Ok(res
            .into_iter()
            .map(|r| {
                r.context("missing response")?
                    .result::<json::GetMempoolEntryResult>()
                    .context("invalid response")
            })
            .collect())
    }

    pub(crate) fn get_mempool_transactions(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Result<Transaction>>> {
        let client = self.rpc.get_jsonrpc_client();
        log::debug!("getting {} transactions", txids.len());
        let args: Vec<_> = txids
            .iter()
            .map(|txid| vec![serde_json::value::to_raw_value(txid).unwrap()])
            .collect();
        let reqs: Vec<_> = args
            .iter()
            .map(|a| client.build_request("getrawtransaction", a))
            .collect();
        let res = client.send_batch(&reqs).context("batch request failed")?;
        log::debug!("got {} mempool transactions", res.len());
        Ok(res
            .into_iter()
            .map(|r| -> Result<Transaction> {
                let tx_hex = r
                    .context("missing response")?
                    .result::<String>()
                    .context("invalid response")?;
                let tx_bytes = Vec::from_hex(&tx_hex).context("non-hex transaction")?;
                deserialize(&tx_bytes).context("invalid transaction")
            })
            .collect())
    }

    // pub(crate) fn get_new_headers(&self, chain: &Chain) -> Result<Vec<NewHeader>> {
    //     self.p2p.lock().get_new_headers(chain)
    // }

    // pub(crate) fn for_blocks<B, F>(&self, blockhashes: B, func: F) -> Result<()>
    // where
    //     B: IntoIterator<Item = BlockHash>,
    //     F: FnMut(BlockHash, SerBlock),
    // {
    //     self.p2p.lock().for_blocks(blockhashes, func)
    // }

    // pub(crate) fn new_block_notification(&self) -> Receiver<()> {
    //     self.p2p.lock().new_block_notification()
    // }
}

pub(crate) type RpcError = bitcoincore_rpc::jsonrpc::error::RpcError;

pub(crate) fn extract_bitcoind_error(err: &bitcoincore_rpc::Error) -> Option<&RpcError> {
    use bitcoincore_rpc::{
        jsonrpc::error::Error::Rpc as ServerError, Error::JsonRpc as JsonRpcError,
    };
    match err {
        JsonRpcError(ServerError(e)) => Some(e),
        _ => None,
    }
}
