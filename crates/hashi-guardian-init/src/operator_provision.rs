// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

pub fn run(config_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!(
        "operator provision is not implemented yet (config: {}).\n\
         Eventually this command will read operator provision config, build the \
         withdraw-mode guardian state, call OperatorInit, and print the state \
         hash that key-provisioners must verify.",
        config_path.display()
    )
}
