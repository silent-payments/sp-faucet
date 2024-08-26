use anyhow::{Error, Result};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::time;
use tokio_tungstenite::tungstenite::Message;

use crate::{faucet::{handle_faucet_request, FaucetMessage, FaucetResponse}, PEERMAP};

pub(crate) static MESSAGECACHE: OnceLock<MessageCache> = OnceLock::new();

const MESSAGECACHEDURATION: Duration = Duration::from_secs(10);
const MESSAGECACHEINTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(crate) struct MessageCache {
    store: Mutex<HashMap<String, Instant>>,
}

impl MessageCache {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }

    fn insert(&self, key: String) {
        let mut store = self.store.lock().unwrap();
        store.insert(key.clone(), Instant::now());
    }

    fn contains(&self, key: &str) -> bool {
        let store = self.store.lock().unwrap();
        store.contains_key(key)
    }

    pub async fn clean_up() {
        let cache = MESSAGECACHE.get().unwrap();

        let mut interval = time::interval(MESSAGECACHEINTERVAL);

        loop {
            interval.tick().await;

            let mut store = cache.store.lock().unwrap();

            let now = Instant::now();
            let to_rm: Vec<String> = store
                .iter()
                .filter_map(|(entry, entrytime)| {
                    if let Some(duration) = now.checked_duration_since(*entrytime) {
                        if duration > MESSAGECACHEDURATION {
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

pub(crate) fn broadcast_message(
    payload: String,
    broadcast: BroadcastType,
) -> Result<()> {
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

pub fn process_message(raw_msg: &str) -> Result<FaucetResponse> {
    log::debug!("Received msg: {}", raw_msg);
    if let Ok(content) = serde_json::from_str::<FaucetMessage>(raw_msg) {
        match handle_faucet_request(&content) {
            Ok(faucet_response) => {
                Ok(faucet_response)
            }
            Err(e) => {
                Err(Error::msg(format!("Failed to send faucet tx: {}", e)))
            }
        }
    } else {
        Err(Error::msg("Invalid content for faucet message"))
    }
}
