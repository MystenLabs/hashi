// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;

pub fn run(_cfg: Config) -> anyhow::Result<()> {
    anyhow::bail!(
        "operator provision is not implemented yet.\n\
         Eventually this command will read operator provision config, build the \
         withdraw-mode guardian state, call OperatorInit, and print the state \
         hash that key-provisioners must verify."
    )
}
