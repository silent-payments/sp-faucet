use std::{collections::HashMap, str::FromStr};

use bitcoincore_rpc::json::{self as bitcoin_json};
use bitcoincore_rpc::RawTx;
use serde::{Serialize, Deserialize};
use sp_client::bitcoin::secp256k1::PublicKey;
use sp_client::bitcoin::secp256k1::{
    rand::thread_rng, Keypair, Message as Secp256k1Message, Secp256k1, ThirtyTwoByteHash,
};
use sp_client::bitcoin::{
    absolute::LockTime,
    key::TapTweak,
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    transaction::Version,
    Amount, OutPoint, Psbt, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};

use sp_client::silentpayments::sending::generate_recipient_pubkeys;
use sp_client::silentpayments::utils::sending::calculate_partial_secret;
use sp_client::silentpayments::utils::SilentPaymentAddress;
use sp_client::spclient::Recipient;

use anyhow::{Error, Result};

use crate::lock_freezed_utxos;
use crate::message::ADDRESSCACHE;
use crate::{scan::compute_partial_tweak_to_transaction, MutexExt, DAEMON, WALLET};
use crate::silentpayments::create_transaction;

const MIN_AMOUNT: Amount = Amount::from_sat(10_000);
const MAX_AMOUNT: Amount = Amount::from_sat(100_000);
const FEE_PROVISION: Amount = Amount::from_sat(10_000);

#[derive(Debug, Serialize, Deserialize)]
pub struct FaucetMessage {
    pub sp_address: String,
    pub amount: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FaucetResponse {
    pub transaction: String,
    pub tweak_data: Option<String>,
}

impl FaucetResponse {
    pub fn new(transaction: Transaction, tweak_data: Option<PublicKey>) -> Self { 
        Self {
            transaction: transaction.raw_hex(),
            tweak_data: tweak_data.map(|p| p.to_string()),
        }
    }
}

fn spend_from_core(dest: XOnlyPublicKey, amt: Amount) -> Result<(Transaction, Amount)> {
    let core = DAEMON
        .get()
        .ok_or(Error::msg("DAEMON not initialized"))?
        .lock_anyhow()?;
    let unspent_list: Vec<bitcoin_json::ListUnspentResultEntry> =
        core.list_unspent_min_sum(amt)?;

    if !unspent_list.is_empty() {
        let network = core.get_network()?;

        let spk = ScriptBuf::new_p2tr_tweaked(dest.dangerous_assume_tweaked());

        let new_psbt = core.create_psbt(&unspent_list, spk, network)?;
        let processed_psbt = core.process_psbt(new_psbt)?;
        let finalize_psbt_result = core.finalize_psbt(processed_psbt)?;
        let final_psbt = Psbt::from_str(&finalize_psbt_result)?;
        let total_fee = final_psbt.fee()?;
        let final_tx = final_psbt.extract_tx()?;
        let fee_rate = total_fee
            .checked_div(final_tx.weight().to_vbytes_ceil())
            .unwrap();

        Ok((final_tx, fee_rate))
    } else {
        // we don't have enough available coins to pay for this faucet request
        Err(Error::msg("No spendable outputs"))
    }
}

fn faucet_send(sp_address: SilentPaymentAddress, amount: Amount) -> Result<Transaction> {
    let mut first_tx: Option<Transaction> = None;
    let final_tx: Transaction;

    let sp_wallet = WALLET.get().ok_or(Error::msg("Wallet not initialized"))?;
    // do we have a sp output available ?
    let available_outpoints = sp_wallet.get_wallet()?.get_outputs().to_spendable_list();

    let available_amt = available_outpoints
        .iter()
        .fold(Amount::from_sat(0), |acc, (_, x)| acc + x.amount);

    let expected_reserve = amount.checked_mul(2).expect("This shouldn't overflow");
    let amt_to_send = amount.checked_add(FEE_PROVISION).expect("This shouldn't overflow");

    // We take found out of Core if we have less than twice the amount requested left
    // This is kinda arbitrary
    if available_amt > expected_reserve {
        let mut total_amt = Amount::from_sat(0);
        let mut inputs = HashMap::new();
        for (outpoint, output) in available_outpoints {
            total_amt += output.amount;
            inputs.insert(outpoint, output);
            if total_amt >= amt_to_send {
                break;
            }
        }

        let recipient = Recipient {
            address: sp_address.into(),
            amount: amt_to_send,
            nb_outputs: 1,
        };

        let fee_estimate = DAEMON
            .get()
            .ok_or(Error::msg("DAEMON not initialized"))?
            .lock_anyhow()?
            .estimate_fee(6)
            .unwrap_or(Amount::from_sat(1000))
            .checked_div(1000)
            .unwrap();

        log::debug!("fee estimate for 6 blocks: {}", fee_estimate);

        let wallet = sp_wallet.get_wallet()?;

        let freezed_utxos = lock_freezed_utxos()?;

        let signed_psbt = create_transaction(
            &vec![],
            &freezed_utxos,
            &wallet,
            vec![recipient],
            None,
            fee_estimate,
            None
        )?;

        final_tx = signed_psbt.extract_tx()?;
    } else {
        // let's try to spend directly from the mining address
        let secp = Secp256k1::signing_only();
        let keypair = Keypair::new(&secp, &mut thread_rng());

        // we first spend from core to the pubkey we just created
        let (core_tx, fee_rate) = spend_from_core(keypair.x_only_public_key().0, MAX_AMOUNT.checked_mul(4).expect("This shouldn't overflow"))?;

        // check that the first output of the transaction pays to the key we just created
        debug_assert!(
            core_tx.output[0].script_pubkey
                == ScriptBuf::new_p2tr_tweaked(
                    keypair.x_only_public_key().0.dangerous_assume_tweaked()
                )
        );

        // This is ugly and can be streamlined
        // create a new transaction that spends the newly created UTXO to the sp_address
        let mut faucet_tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint::new(core_tx.txid(), 0),
                ..Default::default()
            }],
            output: vec![],
            version: Version::TWO,
            lock_time: LockTime::ZERO,
        };

        // now do the silent payment operations with the final recipient address
        let partial_secret = calculate_partial_secret(
            &[(keypair.secret_key(), true)],
            &[(core_tx.txid().to_string(), 0)],
        )?;

        let our_sp_address = sp_wallet.get_wallet()?.get_client().get_receiving_address();
        let output_keys =
            generate_recipient_pubkeys(vec![sp_address.into(), our_sp_address.clone()], partial_secret)?;

        let ext_output_key = output_keys.get::<String>(&sp_address.into())
            .expect("Failed to generate keys")
            .get(0)
            .expect("Failed to generate keys");
        let our_output_key = output_keys.get(&our_sp_address)
            .expect("Failed to generate keys")
            .get(0)
            .expect("Failed to generate keys");

        let ext_spk = ScriptBuf::new_p2tr_tweaked(ext_output_key.dangerous_assume_tweaked());
        let change_spk = ScriptBuf::new_p2tr_tweaked(our_output_key.dangerous_assume_tweaked());

        // Take some margin to pay for the fees
        if core_tx.output[0].value < expected_reserve {
            return Err(Error::msg("Not enough funds"));
        }

        let change_amt = core_tx.output[0].value.checked_sub(amt_to_send).unwrap();

        faucet_tx.output.push(TxOut {
            value: amt_to_send,
            script_pubkey: ext_spk,
        });
        faucet_tx.output.push(TxOut {
            value: change_amt,
            script_pubkey: change_spk,
        });

        // dummy signature only used for fee estimation
        faucet_tx.input[0].witness.push([1; 64].to_vec());

        let abs_fee = fee_rate
            .checked_mul(faucet_tx.weight().to_vbytes_ceil())
            .ok_or_else(|| Error::msg("Fee rate multiplication overflowed"))?;

        // reset the witness to empty
        faucet_tx.input[0].witness = Witness::new();

        faucet_tx.output[1].value -= abs_fee;

        let first_tx_outputs = vec![core_tx.output[0].clone()];
        let prevouts = Prevouts::All(&first_tx_outputs);

        let hash_ty = TapSighashType::Default;

        let mut cache = SighashCache::new(&faucet_tx);

        let sighash = cache.taproot_key_spend_signature_hash(0, &prevouts, hash_ty)?;

        let msg = Secp256k1Message::from_digest(sighash.into_32());

        let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut thread_rng());
        let final_sig = Signature { sig, hash_ty };

        faucet_tx.input[0].witness.push(final_sig.to_vec());

        first_tx = Some(core_tx);

        final_tx = faucet_tx;
    }

    {
        let daemon = DAEMON
            .get()
            .ok_or(Error::msg("DAEMON not initialized"))?
            .lock_anyhow()?;
        // broadcast one or two transactions
        if first_tx.is_some() {
            daemon.broadcast(&first_tx.unwrap())?;
        }
        let txid = daemon.broadcast(&final_tx)?;
        log::debug!("Sent tx {}", txid);
    }

    Ok(final_tx)
}

pub fn handle_faucet_request(faucet_request: &FaucetMessage) -> Result<FaucetResponse> {
    let sp_address = SilentPaymentAddress::try_from(faucet_request.sp_address.as_str())?;
    let amount = Amount::from_sat(faucet_request.amount.into());
    if amount < MIN_AMOUNT || amount > MAX_AMOUNT {
        return Err(Error::msg("amount must be comprised between 100,000 and 1,000,000 sats included"));
    }
    log::debug!("Sending {} sats to {}", amount, sp_address);
    // send bootstrap coins to this sp_address
    let tx = faucet_send(sp_address, amount)?;

    // Now that we're sure the tx is off, we add the address to the temporary black list
    let address_cache = ADDRESSCACHE.get().unwrap();
    address_cache.insert(sp_address.into());

    // get the tweak
    let partial_tweak = compute_partial_tweak_to_transaction(&tx)?;

    // get current blockheight
    let blkheight: u32 = DAEMON
        .get()
        .unwrap()
        .lock_anyhow()?
        .get_current_height()?
        .try_into()?;

    let sp_wallet = WALLET.get().ok_or(Error::msg("Wallet not initialized"))?;

    // update our sp_client with the change output(s)
    sp_wallet
        .get_wallet()?
        .update_wallet_with_transaction(&tx, blkheight, partial_tweak)?;

    log::debug!("updated the wallet");
    // save to disk
    sp_wallet.save()?;

    log::debug!("saved the wallet");
    Ok(FaucetResponse::new(
        tx,
        Some(partial_tweak)
    ))
}
