#!/usr/bin/env python3
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Make `review/sync-copy.patch`, the patch that gives the sync copy of the withdrawal handler.

Why it exists:
Aeneas cannot translate an `async` function or the `tracing` macros.
`review/extract.sh` applies the patch to a copy of the workspace before the translation.
The patch is the file that a person reviews. This script only helps to write the patch.
A change to the patch by hand is also correct.

How it works:
1. Each rule in `RULES` replaces text in one file. Rules do not touch test modules.
2. A rule that does not match the expected number of times stops the script.
3. The script writes the difference as a patch. It does not change the Rust files.

Usage: `python3 no-review/make_patch.py`, then review `review/sync-copy.patch`.
"""
import difflib
import re
import sys
from pathlib import Path

HANDLER = "crates/hashi-guardian/src/withdraw_mode/standard_withdrawal.rs"
ENCLAVE = "crates/hashi-guardian/src/enclave.rs"
SERVICE = "crates/hashi-guardian/src/service.rs"

# One rule: (file, regular expression, replacement, expected number of matches).
# `None` as the expected number means "one or more".
RULES = [
    # 1. The handler is a sync function.
    (HANDLER, r"pub async fn standard_withdrawal\(", "pub fn standard_withdrawal(", 1),
    (HANDLER, r"(\.log_withdraw\(msg\))\n\s*\.await", r"\1", 1),
    # 2. No `tracing` code. It has no effect on the result of the handler.
    (HANDLER, r"^[ \t]*(?:info|debug|warn|error)!\(.*?\);\n", "", None),
    (HANDLER, r"^[ \t]*tracing::Span::current\(\)\.record\(.*?\);\n", "", 1),
    (HANDLER, r"^use tracing::\w+;\n", "", None),
    # 3. The S3 log is a list of withdrawal records in the enclave.
    (
        ENCLAVE,
        r"(    log_writer: LogWriter,\n)(\})",
        r"\1    /// Mock S3 log: the withdrawal records, oldest first.\n"
        r"    pub mock_withdrawal_log: Vec<WithdrawalLogMessage>,\n\2",
        1,
    ),
    (
        ENCLAVE,
        r"(            log_writer: LogWriter::new\(\),\n)",
        r"\1            mock_withdrawal_log: Vec::new(),\n",
        1,
    ),
    (
        ENCLAVE,
        r"pub async fn log_withdraw(\(&mut self, msg: WithdrawalLogMessage\) -> GuardianResult<\(\)> \{\n)"
        r"        self\.write_log\(LogMessage::Withdrawal\(Box::new\(msg\)\)\)\.await\n",
        r"pub fn log_withdraw\1        self.mock_withdrawal_log.push(msg);\n        Ok(())\n",
        1,
    ),
    # 4. The service wraps the sync handler in a future. The proof does not include the service.
    (
        SERVICE,
        r"Box::pin\((standard_withdrawal::standard_withdrawal\([^()]*\))\)",
        r"Box::pin(async move { \1 })",
        1,
    ),
]

TEST_MODULE = "\n#[cfg(test)]\nmod "
PREAMBLE = """\
This patch makes the sync copy of the Guardian withdrawal handler for the Lean extraction.
`extract.sh` applies it to a copy of the workspace. It does not change the repository.
Review each line. `WithdrawalSpec.lean` gives the reasons why the copy has the same behaviour.
`no-review/make_patch.py` can write this file again after a change to the Rust code.

"""


def apply_rules(path: str, text: str) -> str:
    """Apply the rules for `path` to the part of `text` before the test module."""
    head, marker, tests = text.partition(TEST_MODULE)
    for rule_path, pattern, replacement, expected in RULES:
        if rule_path != path:
            continue
        head, count = re.subn(pattern, replacement, head, flags=re.MULTILINE | re.DOTALL)
        if count == 0 or (expected is not None and count != expected):
            sys.exit(f"make_patch: rule {pattern!r} matched {count} times in {path}")
    return head + marker + tests


def main() -> None:
    project = Path(__file__).resolve().parent.parent
    workspace = project.parent.parent
    patch = [PREAMBLE]
    for path in sorted({rule[0] for rule in RULES}):
        before = (workspace / path).read_text()
        after = apply_rules(path, before)
        patch += difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            f"a/{path}",
            f"b/{path}",
            n=2,
        )
    (project / "review" / "sync-copy.patch").write_text("".join(patch))


if __name__ == "__main__":
    main()
