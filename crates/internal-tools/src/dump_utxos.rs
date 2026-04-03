// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use hashi::onchain::OnchainState;

pub fn run(onchain_state: &OnchainState) -> anyhow::Result<()> {
    let state = onchain_state.state();
    let utxo_pool = &state.hashi().utxo_pool;
    let utxos: Vec<_> = utxo_pool.active_utxos().collect();

    println!("=== Active UTXOs ({} entries) ===\n", utxos.len());

    let mut total_amount: u64 = 0;
    for (id, utxo) in &utxos {
        println!(
            "  txid: {}  vout: {}  amount: {} sat  derivation_path: {}",
            id.txid,
            id.vout,
            utxo.amount,
            utxo.derivation_path
                .map_or("none".to_string(), |p| p.to_string()),
        );
        total_amount += utxo.amount;
    }

    println!(
        "\nTotal: {} sat ({:.8} BTC)",
        total_amount,
        total_amount as f64 / 1e8
    );

    Ok(())
}
