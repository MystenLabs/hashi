// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use anyhow::anyhow;
use hashi::onchain::types::Utxo;
use hashi::onchain::types::UtxoId;
use hashi_types::bitcoin_txid::BitcoinTxid;
use sui_sdk_types::Address;

pub fn write_csv(utxos: &[(UtxoId, Utxo)], mut w: impl Write) -> anyhow::Result<()> {
    writeln!(w, "txid,vout,derivation_path,amount")?;
    for (id, utxo) in utxos {
        let deriv = utxo
            .derivation_path
            .map_or(String::new(), |p| p.to_string());
        writeln!(w, "{},{},{},{}", id.txid, id.vout, deriv, utxo.amount)?;
    }
    Ok(())
}

pub fn parse_csv(path: &Path) -> anyhow::Result<Vec<Utxo>> {
    let mut reader = csv::Reader::from_path(path).context("failed to open CSV")?;
    let mut utxos = Vec::new();

    for (i, result) in reader.records().enumerate() {
        let row = i + 1;
        let record = result.with_context(|| format!("failed to read CSV row {row}"))?;

        let txid_str = record
            .get(0)
            .ok_or_else(|| anyhow!("row {row}: missing txid"))?;
        let vout_str = record
            .get(1)
            .ok_or_else(|| anyhow!("row {row}: missing vout"))?;
        let deriv_str = record
            .get(2)
            .ok_or_else(|| anyhow!("row {row}: missing derivation_path"))?;
        let amount_str = record
            .get(3)
            .ok_or_else(|| anyhow!("row {row}: missing amount"))?;

        let txid: BitcoinTxid = txid_str
            .parse()
            .with_context(|| format!("row {row}: bad txid"))?;
        let vout: u32 = vout_str
            .parse()
            .with_context(|| format!("row {row}: bad vout"))?;
        let derivation_path: Option<Address> = if deriv_str.is_empty() {
            None
        } else {
            Some(
                deriv_str
                    .parse()
                    .with_context(|| format!("row {row}: bad derivation_path"))?,
            )
        };
        let amount: u64 = amount_str
            .parse()
            .with_context(|| format!("row {row}: bad amount"))?;

        utxos.push(Utxo {
            id: UtxoId { txid, vout },
            amount,
            derivation_path,
        });
    }

    Ok(utxos)
}
