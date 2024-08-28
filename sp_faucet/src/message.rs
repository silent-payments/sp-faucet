use anyhow::{Error, Result};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::time;
use tokio_tungstenite::tungstenite::Message;

use crate::{
    faucet::{handle_faucet_request, FaucetMessage, FaucetResponse},
    PEERMAP,
};

pub(crate) static ADDRESSCACHE: OnceLock<AddressCache> = OnceLock::new();

const ADDRESSCACHEDURATION: Duration = Duration::from_secs(600);
const ADDRESSCACHEINTERVAL: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub(crate) struct AddressCache {
    store: Mutex<HashMap<String, Instant>>,
}

impl AddressCache {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, key: String) {
        let mut store = self.store.lock().unwrap();
        store.insert(key.clone(), Instant::now());
    }

    pub fn contains(&self, key: &str) -> bool {
        let store = self.store.lock().unwrap();
        store.contains_key(key)
    }

    pub async fn clean_up() {
        let cache = ADDRESSCACHE.get().unwrap();

        let mut interval = time::interval(ADDRESSCACHEINTERVAL);

        loop {
            interval.tick().await;

            let mut store = cache.store.lock().unwrap();

            let now = Instant::now();
            let to_rm: Vec<String> = store
                .iter()
                .filter_map(|(entry, entrytime)| {
                    if let Some(duration) = now.checked_duration_since(*entrytime) {
                        if duration > ADDRESSCACHEDURATION {
                            Some(entry.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();

            for key in to_rm {
                store.remove(&key);
            }
        }
    }
}

pub(crate) enum BroadcastType {
    Sender(SocketAddr),
    #[allow(dead_code)]
    ExcludeSender(SocketAddr),
    #[allow(dead_code)]
    ToAll,
}

pub(crate) fn broadcast_message(payload: String, broadcast: BroadcastType) -> Result<()> {
    let peers = PEERMAP.get().ok_or(Error::msg("Unitialized peer map"))?;
    let msg = Message::Text(serde_json::to_string(&payload)?);
    log::debug!("Broadcasting message: {}", msg);
    match broadcast {
        BroadcastType::Sender(addr) => {
            peers
                .lock()
                .map_err(|e| Error::msg(format!("Failed to lock peers: {}", e.to_string())))?
                .iter()
                .find(|(peer_addr, _)| peer_addr == &&addr)
                .ok_or(Error::msg("Failed to find the sender in the peer_map"))?
                .1
                .send(msg)?;
        }
        BroadcastType::ExcludeSender(addr) => {
            peers
                .lock()
                .map_err(|e| Error::msg(format!("Failed to lock peers: {}", e.to_string())))?
                .iter()
                .filter(|(peer_addr, _)| peer_addr != &&addr)
                .for_each(|(_, peer_tx)| {
                    let _ = peer_tx.send(msg.clone());
                });
        }
        BroadcastType::ToAll => {
            peers
                .lock()
                .map_err(|e| Error::msg(format!("Failed to lock peers: {}", e.to_string())))?
                .iter()
                .for_each(|(_, peer_tx)| {
                    let _ = peer_tx.send(msg.clone());
                });
        }
    }
    Ok(())
}

pub async fn process_message(raw_msg: &str) -> Result<FaucetResponse> {
    log::debug!("Received msg: {}", raw_msg);
    if let Ok(content) = serde_json::from_str::<FaucetMessage>(raw_msg) {
        // Check if the address is black listed
        let address_cache = ADDRESSCACHE.get().unwrap();
        if address_cache.contains(&content.sp_address) {
            return Err(Error::msg(
                "Already sent tokens to this address, please wait",
            ));
        }
        match handle_faucet_request(&content).await {
            Ok(faucet_response) => Ok(faucet_response),
            Err(e) => Err(Error::msg(format!("Failed to send faucet tx: {}", e))),
        }
    } else {
        Err(Error::msg("Invalid content for faucet message"))
    }
}
