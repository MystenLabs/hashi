// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use hashi::onchain::OnchainState;

pub fn run(onchain_state: &OnchainState) -> anyhow::Result<()> {
    let state = onchain_state.state();
    let utxo_pool = &state.hashi().utxo_pool;
    let utxos: Vec<_> = utxo_pool
        .active_utxos()
        .map(|(id, utxo)| (*id, utxo.clone()))
        .collect();

    eprintln!("{} active UTXOs", utxos.len());

    let total_amount: u64 = utxos.iter().map(|(_, u)| u.amount).sum();
    eprintln!(
        "Total: {} sat ({:.8} BTC)",
        total_amount,
        total_amount as f64 / 1e8
    );

    crate::utxo_csv::write_csv(&utxos, std::io::stdout().lock())
}
