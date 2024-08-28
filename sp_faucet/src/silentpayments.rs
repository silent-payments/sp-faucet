use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::{Error, Result};

use sp_client::bitcoin::consensus::deserialize;
use sp_client::bitcoin::psbt::raw;
use sp_client::bitcoin::secp256k1::rand::{thread_rng, Rng};
use sp_client::bitcoin::Psbt;
use sp_client::bitcoin::{Amount, OutPoint};
use sp_client::constants::{
    self, DUST_THRESHOLD, PSBT_SP_ADDRESS_KEY, PSBT_SP_PREFIX, PSBT_SP_SUBTYPE,
};
use sp_client::silentpayments::utils::SilentPaymentAddress;
use sp_client::spclient::{OwnedOutput, Recipient, SpClient, SpWallet};

pub fn create_transaction(
    mandatory_inputs: &[&OutPoint],
    freezed_utxos: &HashSet<OutPoint>,
    sp_wallet: &SpWallet,
    mut recipients: Vec<Recipient>,
    payload: Option<Vec<u8>>,
    fee_rate: Amount,
    fee_payer: Option<String>, // None means sender pays everything
) -> Result<Psbt> {
    let mut available_outpoints: HashMap<OutPoint, OwnedOutput> = sp_wallet
        .get_outputs()
        .to_spendable_list()
        // filter out freezed utxos
        .into_iter()
        .filter(|(outpoint, _)| !freezed_utxos.contains(outpoint))
        .collect();

    // if we have a payload, it means we are notifying, so let's add a revokation output
    if payload.is_some() {
        recipients.push(Recipient {
            address: sp_wallet.get_client().get_receiving_address(),
            amount: DUST_THRESHOLD,
            nb_outputs: 1,
        })
    }

    let sum_outputs = recipients
        .iter()
        .fold(Amount::from_sat(0), |acc, x| acc + x.amount);

    let zero_value_recipient = recipients
        .iter_mut()
        .find(|r| r.amount == Amount::from_sat(0));

    let mut inputs: HashMap<OutPoint, OwnedOutput> = HashMap::new();
    let mut total_available = Amount::from_sat(0);
    for outpoint in mandatory_inputs {
        let (must_outpoint, must_output) = available_outpoints
            .remove_entry(&outpoint)
            .ok_or_else(|| Error::msg("Mandatory outpoint unknown"))?;
        total_available += must_output.amount;
        inputs.insert(must_outpoint, must_output);
    }

    for (outpoint, output) in available_outpoints {
        if total_available > sum_outputs {
            break;
        }
        total_available += output.amount;
        inputs.insert(outpoint, output);
    }

    if total_available < sum_outputs {
        return Err(Error::msg("Not enough available funds"));
    }

    if let Some(recipient) = zero_value_recipient {
        // update the amount for the recipient
        recipient.amount = total_available;
    }

    let mut commitment = [0u8; 32];
    if let Some(ref p) = payload {
        commitment.copy_from_slice(&p);
    } else {
        thread_rng().fill(&mut commitment);
    }

    let mut new_psbt =
        sp_wallet
            .get_client()
            .create_new_psbt(inputs, recipients, Some(&commitment))?;

    let sender_address = sp_wallet.get_client().get_receiving_address();
    let change_address = sp_wallet.get_client().sp_receiver.get_change_address();
    if let Some(address) = fee_payer {
        SpClient::set_fees(&mut new_psbt, fee_rate, address)?;
    } else {
        let candidates: Vec<Option<String>> = new_psbt
            .outputs
            .iter()
            .map(|o| {
                if let Some(value) = o.proprietary.get(&raw::ProprietaryKey {
                    prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                    subtype: PSBT_SP_SUBTYPE,
                    key: PSBT_SP_ADDRESS_KEY.as_bytes().to_vec(),
                }) {
                    let candidate: String =
                        SilentPaymentAddress::try_from(deserialize::<String>(value).unwrap())
                            .unwrap()
                            .into();
                    return Some(candidate);
                } else {
                    return None;
                }
            })
            .collect();

        let mut fee_set = false;
        for candidate in candidates {
            if let Some(c) = candidate {
                if c == change_address {
                    SpClient::set_fees(&mut new_psbt, fee_rate, change_address.clone())?;
                    fee_set = true;
                    break;
                } else if c == sender_address {
                    SpClient::set_fees(&mut new_psbt, fee_rate, sender_address.clone())?;
                    fee_set = true;
                    break;
                }
            }
        }

        if !fee_set {
            return Err(Error::msg("Must specify payer for fee"));
        }
    };

    let partial_secret = sp_wallet
        .get_client()
        .get_partial_secret_from_psbt(&new_psbt)?;

    sp_wallet
        .get_client()
        .fill_sp_outputs(&mut new_psbt, partial_secret)?;
    let mut aux_rand = [0u8; 32];
    thread_rng().fill(&mut aux_rand);
    let mut signed = sp_wallet.get_client().sign_psbt(new_psbt, &aux_rand)?;
    SpClient::finalize_psbt(&mut signed)?;

    Ok(signed)
}
