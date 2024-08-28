use std::{
    collections::{HashMap, HashSet},
    env,
    fmt::Debug,
    fs,
    io::{Read, Write},
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::{Mutex, MutexGuard, OnceLock},
};

use bitcoincore_rpc::{
    bitcoin::OutPoint,
    json::{self as bitcoin_json},
};
use faucet::FaucetResponse;
use futures_util::{future, pin_mut, stream::TryStreamExt, FutureExt, StreamExt};
use log::{debug, error, warn};
use message::{broadcast_message, process_message, AddressCache, BroadcastType, ADDRESSCACHE};
use scan::compute_partial_tweak_to_transaction;
use sp_client::bitcoin::{consensus::deserialize, Amount, Network, Transaction};
use sp_client::{
    bitcoin::secp256k1::rand::{thread_rng, Rng},
    spclient::SpWallet,
};

use sp_client::spclient::{derive_keys_from_seed, SpClient, SpendKey};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_tungstenite::tungstenite::Message;

use anyhow::{Error, Result};
use zeromq::{Socket, SocketRecv};

mod blindbit;
mod config;
mod daemon;
mod faucet;
mod message;
mod scan;
mod silentpayments;

use crate::config::Config;
use crate::{daemon::Daemon, scan::scan_blocks};

type Tx = UnboundedSender<Message>;

type PeerMap = Mutex<HashMap<SocketAddr, Tx>>;

pub(crate) static PEERMAP: OnceLock<PeerMap> = OnceLock::new();

type SharedDaemon = tokio::sync::Mutex<Daemon>;

pub(crate) static DAEMON: OnceLock<SharedDaemon> = OnceLock::new();

pub static FREEZED_UTXOS: OnceLock<Mutex<HashSet<OutPoint>>> = OnceLock::new();

pub fn lock_freezed_utxos() -> Result<MutexGuard<'static, HashSet<OutPoint>>, Error> {
    FREEZED_UTXOS
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock_anyhow()
}

#[derive(Debug)]
struct WalletFile {
    path: PathBuf,
}

impl WalletFile {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn create(&self) -> Result<()> {
        let parent: PathBuf;
        if let Some(dir) = self.path.parent() {
            if !dir.ends_with(".4nk") {
                return Err(Error::msg("parent dir must be \".4nk\""));
            }
            parent = dir.to_path_buf();
        } else {
            return Err(Error::msg("wallet file has no parent dir"));
        }

        // check that parent exists
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }

        fs::File::create_new(&self.path)?;

        Ok(())
    }

    fn save(&self, new_value: &SpWallet) -> Result<()> {
        let mut f = fs::File::options()
            .write(true)
            .truncate(true)
            .open(&self.path)?;

        let json = serde_json::to_string(new_value)?;
        f.write_all(json.as_bytes())?;

        Ok(())
    }

    fn load(&self) -> Result<SpWallet> {
        let mut f = fs::File::open(&self.path)?;

        let mut content = vec![];
        f.read_to_end(&mut content)?;

        let res: SpWallet = serde_json::from_slice(&content)?;

        Ok(res)
    }
}

pub(crate) trait MutexExt<T> {
    fn lock_anyhow(&self) -> Result<MutexGuard<T>, Error>;
}

impl<T: Debug> MutexExt<T> for Mutex<T> {
    fn lock_anyhow(&self) -> Result<MutexGuard<T>, Error> {
        self.lock()
            .map_err(|e| Error::msg(format!("Failed to lock: {}", e)))
    }
}

#[derive(Debug)]
struct SilentPaymentWallet {
    sp_wallet: Mutex<SpWallet>,
    storage: Mutex<WalletFile>,
}

impl SilentPaymentWallet {
    pub fn get_wallet(&self) -> Result<MutexGuard<SpWallet>> {
        self.sp_wallet.lock_anyhow()
    }

    pub fn save(&self) -> Result<()> {
        let wallet = self.sp_wallet.lock_anyhow()?;
        self.storage.lock_anyhow()?.save(&wallet)
    }
}

pub(crate) static WALLET: OnceLock<SilentPaymentWallet> = OnceLock::new();

async fn handle_connection(raw_stream: TcpStream, addr: SocketAddr) {
    debug!("Incoming TCP connection from: {}", addr);

    let peers = PEERMAP.get().expect("Peer Map not initialized");

    let ws_stream = tokio_tungstenite::accept_async(raw_stream)
        .await
        .expect("Error during the websocket handshake occurred");
    debug!("WebSocket connection established");

    // Insert the write part of this peer to the peer map.
    let (tx, rx) = unbounded_channel();
    match peers.lock_anyhow() {
        Ok(mut peer_map) => peer_map.insert(addr, tx),
        Err(e) => {
            log::error!("{}", e);
            panic!();
        }
    };

    let (outgoing, incoming) = ws_stream.split();

    let broadcast_incoming = incoming.try_for_each(|msg| async move {
        if let Ok(raw_msg) = msg.to_text() {
            debug!("Received msg: {}", raw_msg);
            match process_message(raw_msg).await {
                Ok(result) => {
                    if let Err(e) = broadcast_message(
                        serde_json::to_string(&result).unwrap(),
                        BroadcastType::Sender(addr),
                    ) {
                        log::error!("{}", e.to_string());
                    }
                }
                Err(e) => {
                    if let Err(e) = broadcast_message(e.to_string(), BroadcastType::Sender(addr)) {
                        log::error!("{}", e.to_string());
                    }
                }
            }
        } else {
            debug!("Received non-text message {} from peer {}", msg, addr);
        }
        Ok(())
    });

    let receive_from_others = UnboundedReceiverStream::new(rx)
        .map(Ok)
        .forward(outgoing)
        .map(|result| {
            if let Err(e) = result {
                debug!("Error sending message: {}", e);
            }
        });

    pin_mut!(broadcast_incoming, receive_from_others);
    future::select(broadcast_incoming, receive_from_others).await;

    debug!("{} disconnected", &addr);
    peers.lock().unwrap().remove(&addr);
}

async fn create_new_tx_message(transaction: Vec<u8>) -> Result<FaucetResponse> {
    let tx: Transaction = deserialize(&transaction)?;

    if tx.is_coinbase() {
        return Err(Error::msg("Can't process coinbase transaction"));
    }

    let partial_tweak = compute_partial_tweak_to_transaction(&tx).await?;
    Ok(FaucetResponse::new(tx, Some(partial_tweak)))
}

async fn handle_zmq(zmq_url: String, blindbit_url: String) {
    debug!("Starting listening on Core");
    let mut socket = zeromq::SubSocket::new();
    socket.connect(&zmq_url).await.unwrap();
    socket.subscribe("hashblock").await.unwrap();
    loop {
        let core_msg = match socket.recv().await {
            Ok(m) => m,
            Err(e) => {
                error!("Zmq error: {}", e);
                continue;
            }
        };
        debug!("Received a message");

        let payload: String = if let (Some(topic), Some(data)) = (core_msg.get(0), core_msg.get(1))
        {
            debug!("topic: {}", std::str::from_utf8(&topic).unwrap());
            match std::str::from_utf8(&topic) {
                Ok("hashblock") => match scan_blocks(0, &blindbit_url).await {
                    Ok(_) => {
                        debug!("scanned blocks on zmq update");
                        continue;
                    }
                    Err(e) => {
                        error!("{}", e);
                        continue;
                    }
                },
                _ => {
                    error!("Unexpected message in zmq");
                    continue;
                }
            }
        } else {
            error!("Empty message");
            continue;
        };

        debug!("Broadcasting message {}", payload);
        if let Err(e) = broadcast_message(payload, BroadcastType::ToAll) {
            log::error!("{}", e.to_string());
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    env_logger::init();

    // todo: take the path to conf file as argument
    // default to "./.conf"
    let config = Config::read_from_file(".conf")?;

    if config.network == Network::Bitcoin {
        warn!("Running on mainnet, you're on your own");
    }

    ADDRESSCACHE
        .set(AddressCache::new())
        .expect("Message Cache initialization failed");

    PEERMAP
        .set(PeerMap::new(HashMap::new()))
        .expect("PeerMap initialization failed");

    // Connect the rpc daemon
    DAEMON
        .set(tokio::sync::Mutex::new(Daemon::connect(
            config.core_wallet,
            config.core_url,
            config.network,
        )?))
        .expect("DAEMON initialization failed");

    let current_tip: u32 = DAEMON
        .get()
        .unwrap()
        .lock()
        .await
        .get_current_height()?
        .try_into()?;

    let mut app_dir = PathBuf::from_str(&env::var("HOME")?)?;
    app_dir.push(".4nk");
    let mut wallet_file = app_dir.clone();
    wallet_file.push(&config.wallet_name);

    let wallet_file = WalletFile::new(wallet_file);

    // load an existing sp_wallet, or create a new one
    let sp_wallet = match wallet_file.load() {
        Err(_) => {
            wallet_file.create()?;
            let mut seed = [0u8; 64];
            thread_rng().fill(&mut seed);
            let (scan_sk, spend_sk) = derive_keys_from_seed(&seed, config.network)
                .expect("Couldn't generate a new sp_wallet");
            let new_client = SpClient::new(
                config.wallet_name,
                scan_sk,
                SpendKey::Secret(spend_sk),
                None,
                config.network,
            )
            .expect("Failed to create a new SpClient");

            let mut wallet = SpWallet::new(new_client, None, vec![])?;

            // set birthday to avoid unnecessary scanning
            let outputs = wallet.get_mut_outputs();
            outputs.set_birthday(current_tip);
            outputs.update_last_scan(current_tip);

            wallet
        }
        Ok(wallet) => wallet, // TODO check network
    };

    log::info!(
        "Using wallet {} with address {}",
        sp_wallet.get_client().label,
        sp_wallet.get_client().get_receiving_address()
    );

    log::info!(
        "Found {} outputs for a total balance of {}",
        sp_wallet.get_outputs().to_spendable_list().len(),
        sp_wallet.get_outputs().get_balance()
    );

    let last_scan = sp_wallet.get_outputs().get_last_scan();

    WALLET
        .set(SilentPaymentWallet {
            sp_wallet: Mutex::new(sp_wallet),
            storage: Mutex::new(wallet_file),
        })
        .expect("Failed to initialize WALLET");

    WALLET.get().unwrap().save().unwrap();

    if last_scan < current_tip {
        log::info!("Scanning for our outputs");
        scan_blocks(current_tip - last_scan, &config.blindbit_url).await?;
    }

    // Subscribe to Bitcoin Core
    tokio::spawn(handle_zmq(config.zmq_url, config.blindbit_url));

    // Create the event loop and TCP listener we'll accept connections on.
    let try_socket = TcpListener::bind(config.ws_url).await;
    let listener = try_socket.expect("Failed to bind");

    tokio::spawn(AddressCache::clean_up());

    // Let's spawn the handling of each connection in a separate task.
    while let Ok((stream, addr)) = listener.accept().await {
        tokio::spawn(handle_connection(stream, addr));
    }

    Ok(())
}
