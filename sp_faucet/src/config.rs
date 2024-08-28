use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};

use anyhow::{Error, Result};

use sp_client::bitcoin::Network;

#[derive(Debug)]
pub struct Config {
    pub core_url: String,
    pub core_wallet: Option<String>,
    pub ws_url: String,
    pub wallet_name: String,
    pub network: Network,
    pub blindbit_url: String,
    pub zmq_url: String,
}

impl Config {
    pub fn read_from_file(filename: &str) -> Result<Self> {
        let mut file_content = HashMap::new();
        if let Ok(file) = File::open(filename) {
            let reader = io::BufReader::new(file);

            // Read the file line by line
            for line in reader.lines() {
                if let Ok(l) = line {
                    // Ignore comments and empty lines
                    if l.starts_with('#') || l.trim().is_empty() {
                        continue;
                    }

                    // Split the line into key and value
                    if let Some((k, v)) = l.split_once('=') {
                        file_content.insert(k.to_owned(), v.trim_matches('\"').to_owned());
                    }
                }
            }
        } else {
            return Err(anyhow::Error::msg("Failed to find conf file"));
        }

        // Now set the Config
        let config = Config {
            core_url: file_content
                .remove("core_url")
                .ok_or(Error::msg("No \"core_url\""))?
                .to_owned(),
            core_wallet: file_content.remove("core_wallet").map(|s| s.to_owned()),
            ws_url: file_content
                .remove("ws_url")
                .ok_or(Error::msg("No \"ws_url\""))?
                .to_owned(),
            wallet_name: file_content
                .remove("wallet_name")
                .ok_or(Error::msg("No \"wallet_name\""))?
                .to_owned(),
            network: Network::from_core_arg(
                &file_content
                    .remove("network")
                    .ok_or(Error::msg("no \"network\""))?
                    .trim_matches('\"'),
            )?,
            blindbit_url: file_content
                .remove("blindbit_url")
                .ok_or(Error::msg("No \"blindbit_url\""))?
                .to_owned(),
            zmq_url: file_content
                .remove("zmq_url")
                .ok_or(Error::msg("No \"zmq_url\""))?
                .to_owned(),
        };

        Ok(config)
    }
}
