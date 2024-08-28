use std::collections::HashMap;

use anyhow::{Error, Result};
use hex::FromHex;
use sp_client::bitcoin::bip158::BlockFilter;
use sp_client::bitcoin::hex::DisplayHex;
use sp_client::bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use sp_client::bitcoin::{BlockHash, OutPoint, Transaction, TxOut, XOnlyPublicKey};
use sp_client::silentpayments::receiving::Receiver;
use sp_client::silentpayments::utils::receiving::{calculate_tweak_data, get_pubkey_from_input};
use sp_client::spclient::{OutputSpendStatus, OwnedOutput};
use tokio::time::Instant;

use crate::blindbit::client::BlindbitClient;
use crate::{DAEMON, WALLET};

pub async fn compute_partial_tweak_to_transaction(tx: &Transaction) -> Result<PublicKey> {
    let daemon = DAEMON.get().ok_or(Error::msg("DAEMON not initialized"))?;
    let mut outpoints: Vec<(String, u32)> = Vec::with_capacity(tx.input.len());
    let mut pubkeys: Vec<PublicKey> = Vec::with_capacity(tx.input.len());
    for input in tx.input.iter() {
        outpoints.push((
            input.previous_output.txid.to_string(),
            input.previous_output.vout,
        ));
        let prev_tx = daemon
            .lock()
            .await
            .get_transaction(&input.previous_output.txid, None)
            .map_err(|e| Error::msg(format!("Failed to find previous transaction: {}", e)))?;

        if let Some(output) = prev_tx.output.get(input.previous_output.vout as usize) {
            match get_pubkey_from_input(
                &input.script_sig.to_bytes(),
                &input.witness.to_vec(),
                &output.script_pubkey.to_bytes(),
            ) {
                Ok(Some(pubkey)) => pubkeys.push(pubkey),
                Ok(None) => continue,
                Err(e) => {
                    return Err(Error::msg(format!(
                        "Can't extract pubkey from input: {}",
                        e
                    )))
                }
            }
        } else {
            return Err(Error::msg("Transaction with a non-existing input"));
        }
    }

    let input_pub_keys: Vec<&PublicKey> = pubkeys.iter().collect();
    let partial_tweak = calculate_tweak_data(&input_pub_keys, &outpoints)?;
    Ok(partial_tweak)
}

fn get_script_to_secret_map(
    sp_receiver: &Receiver,
    tweak_data_vec: Vec<PublicKey>,
    scan_key_scalar: Scalar,
    secp: &Secp256k1<All>,
) -> Result<HashMap<[u8; 34], PublicKey>> {
    let mut res = HashMap::new();
    let shared_secrets: Result<Vec<PublicKey>> = tweak_data_vec
        .into_iter()
        .map(|x| x.mul_tweak(secp, &scan_key_scalar).map_err(Error::new))
        .collect();
    let shared_secrets = shared_secrets?;

    for shared_secret in shared_secrets {
        let spks = sp_receiver.get_spks_from_shared_secret(&shared_secret)?;

        for spk in spks.into_values() {
            res.insert(spk, shared_secret);
        }
    }
    Ok(res)
}

fn check_block(
    blkfilter: BlockFilter,
    blkhash: BlockHash,
    candidate_spks: Vec<&[u8; 34]>,
    owned_spks: Vec<Vec<u8>>,
) -> Result<bool> {
    // check output scripts
    let mut scripts_to_match: Vec<_> = candidate_spks.into_iter().map(|spk| spk.as_ref()).collect();

    // check input scripts
    scripts_to_match.extend(owned_spks.iter().map(|spk| spk.as_slice()));

    // note: match will always return true for an empty query!
    if !scripts_to_match.is_empty() {
        Ok(blkfilter.match_any(&blkhash, &mut scripts_to_match.into_iter())?)
    } else {
        Ok(false)
    }
}

fn scan_block_outputs(
    sp_receiver: &Receiver,
    txdata: &Vec<Transaction>,
    blkheight: u64,
    spk2secret: HashMap<[u8; 34], PublicKey>,
) -> Result<HashMap<OutPoint, OwnedOutput>> {
    let mut res: HashMap<OutPoint, OwnedOutput> = HashMap::new();

    // loop over outputs
    for tx in txdata {
        let txid = tx.txid();

        // collect all taproot outputs from transaction
        let p2tr_outs: Vec<(usize, &TxOut)> = tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, o)| o.script_pubkey.is_p2tr())
            .collect();

        if p2tr_outs.is_empty() {
            continue;
        }; // no taproot output

        let mut secret: Option<PublicKey> = None;
        // Does this transaction contains one of the outputs we already found?
        for spk in p2tr_outs.iter().map(|(_, o)| &o.script_pubkey) {
            if let Some(s) = spk2secret.get(spk.as_bytes()) {
                // we might have at least one output in this transaction
                secret = Some(*s);
                break;
            }
        }

        if secret.is_none() {
            continue;
        }; // we don't have a secret that matches any of the keys

        // Now we can just run sp_receiver on all the p2tr outputs
        let xonlykeys: Result<Vec<XOnlyPublicKey>> = p2tr_outs
            .iter()
            .map(|(_, o)| {
                XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..]).map_err(Error::new)
            })
            .collect();

        let ours = sp_receiver.scan_transaction(&secret.unwrap(), xonlykeys?)?;
        for (label, map) in ours {
            res.extend(p2tr_outs.iter().filter_map(|(i, o)| {
                match XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..]) {
                    Ok(key) => {
                        if let Some(scalar) = map.get(&key) {
                            match SecretKey::from_slice(&scalar.to_be_bytes()) {
                                Ok(tweak) => {
                                    let outpoint = OutPoint {
                                        txid,
                                        vout: *i as u32,
                                    };
                                    let label_str: Option<String>;
                                    if let Some(l) = &label {
                                        label_str =
                                            Some(l.as_inner().to_be_bytes().to_lower_hex_string());
                                    } else {
                                        label_str = None;
                                    }
                                    return Some((
                                        outpoint,
                                        OwnedOutput {
                                            blockheight: blkheight as u32,
                                            tweak: hex::encode(tweak.secret_bytes()),
                                            amount: o.value,
                                            script: hex::encode(o.script_pubkey.as_bytes()),
                                            label: label_str,
                                            spend_status: OutputSpendStatus::Unspent,
                                        },
                                    ));
                                }
                                Err(_) => {
                                    return None;
                                }
                            }
                        }
                        None
                    }
                    Err(_) => None,
                }
            }));
        }
    }
    Ok(res)
}

fn scan_block_inputs(
    our_outputs: HashMap<OutPoint, OwnedOutput>,
    txdata: Vec<Transaction>,
) -> Result<Vec<OutPoint>> {
    let mut found = vec![];

    for tx in txdata {
        for input in tx.input {
            let prevout = input.previous_output;

            if our_outputs.contains_key(&prevout) {
                found.push(prevout);
            }
        }
    }
    Ok(found)
}

pub async fn scan_blocks(mut n_blocks_to_scan: u32, blindbit_url: &str) -> anyhow::Result<()> {
    log::info!("Starting a rescan");

    let sp_wallet = WALLET.get().ok_or(Error::msg("Wallet not initialized"))?;

    let core = DAEMON
        .get()
        .ok_or(Error::msg("DAEMON not initialized"))?
        .lock()
        .await;

    let secp = Secp256k1::new();
    let scan_height = sp_wallet.get_wallet()?.get_outputs().get_last_scan();
    let tip_height: u32 = core.get_current_height()?.try_into()?;

    // 0 means scan to tip
    if n_blocks_to_scan == 0 {
        n_blocks_to_scan = tip_height - scan_height;
    }

    let start = scan_height + 1;
    let end = if scan_height + n_blocks_to_scan <= tip_height {
        scan_height + n_blocks_to_scan
    } else {
        tip_height
    };

    if start > end {
        return Ok(());
    }

    log::info!("start: {} end: {}", start, end);
    let mut filters: Vec<(u32, BlockHash, BlockFilter)> = vec![];
    for blkheight in start..=end {
        filters.push(core.get_filters(blkheight)?);
    }

    let blindbit_client = BlindbitClient::new(blindbit_url.to_owned());

    let scan_sk = sp_wallet.get_wallet()?.get_client().get_scan_key();

    let sp_receiver = sp_wallet.get_wallet()?.get_client().sp_receiver.clone();
    let start_time = Instant::now();

    for (blkheight, blkhash, blkfilter) in filters {
        let tweaks = blindbit_client.tweak_index(blkheight).await?;

        let spk2secret = if tweaks.len() > 0 {
            get_script_to_secret_map(&sp_receiver, tweaks, scan_sk.into(), &secp)?
        } else {
            HashMap::new()
        };

        // check if new possible outputs are payments to us
        let candidate_spks: Vec<&[u8; 34]> = spk2secret.keys().collect();

        // check if owned inputs are spent
        let our_outputs: HashMap<OutPoint, OwnedOutput> =
            sp_wallet.get_wallet()?.get_outputs().to_outpoints_list();

        let owned_spks: Result<Vec<Vec<u8>>> = our_outputs
            .iter()
            .map(|(_, output)| {
                let script = Vec::from_hex(&output.script).map_err(|e| Error::new(e));
                script
            })
            .collect();

        let matched = check_block(blkfilter, blkhash, candidate_spks, owned_spks?)?;

        if matched {
            let blk = core.get_block(blkhash)?;

            // scan block for new outputs, and add them to our list
            let utxo_created_in_block =
                scan_block_outputs(&sp_receiver, &blk.txdata, blkheight.into(), spk2secret)?;
            if !utxo_created_in_block.is_empty() {
                sp_wallet
                    .get_wallet()?
                    .get_mut_outputs()
                    .extend_from(utxo_created_in_block);
            }

            // update the list of outputs just in case
            // utxos may be created and destroyed in the same block
            let updated_outputs: HashMap<OutPoint, OwnedOutput> =
                sp_wallet.get_wallet()?.get_outputs().to_outpoints_list();

            // search inputs and mark as mined
            let utxo_destroyed_in_block = scan_block_inputs(updated_outputs, blk.txdata)?;
            if !utxo_destroyed_in_block.is_empty() {
                let mut wallet = sp_wallet.get_wallet()?;
                let outputs = wallet.get_mut_outputs();
                for outpoint in utxo_destroyed_in_block {
                    outputs.mark_mined(outpoint, blkhash)?;
                }
            }
        }
    }

    // time elapsed for the scan
    log::info!(
        "Scan complete in {} seconds",
        start_time.elapsed().as_secs()
    );

    // update last_scan height
    sp_wallet
        .get_wallet()?
        .get_mut_outputs()
        .update_last_scan(end);
    sp_wallet.save()?;

    Ok(())
}
