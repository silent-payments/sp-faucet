use electrum_client::{Client, ConfigBuilder};
use log::info;

const VALIDATE_DOMAIN: bool = false; // self-signed cert, so we don't validate

pub fn create_electrum_client(electrum_url: &str) -> anyhow::Result<Client> {
    let config = ConfigBuilder::new()
        .validate_domain(VALIDATE_DOMAIN)
        .build();
    let electrum_client = Client::from_config(electrum_url, config)?;
    info!("ssl client {}", electrum_url);

    Ok(electrum_client)
}
