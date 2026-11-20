#!/usr/bin/env python3
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Make `review/sync-copy.patch`, the patch that gives the sync copy of the withdrawal handler.

Why it exists:
Aeneas cannot translate an `async` function, the `tracing` macros, or the `serde` traits.
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
INTENT = "crates/hashi-types/src/intent.rs"
SIGNING = "crates/hashi-types/src/guardian/crypto/signing.rs"
COMMITTEE = "crates/hashi-types/src/committee.rs"
GUARDIAN_TYPES = "crates/hashi-types/src/guardian/mod.rs"
MOVE_TYPES = "crates/hashi-types/src/move_types/mod.rs"

# The method that each implementation of a signing trait gets in the copy.
PAYLOAD_BYTES = (
    "\n    fn payload_bytes(&self) -> Vec<u8> {\n"
    "        crate::intent::bcs_bytes(self)\n"
    "    }\n"
)
# An implementation of `IntentMessage` with only the `INTENT` constant.
INTENT_IMPL = r"(impl (?:crate::intent::)?IntentMessage for \w+ \{\n    const INTENT: [^;]+;\n)(\})"

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
    # 5. The signing traits have no `Serialize` supertrait. A method gives the BCS bytes.
    #    The signed bytes do not change: BCS writes a tuple as its fields in sequence.
    (
        INTENT,
        r"pub trait IntentMessage: serde::Serialize \{\n(    const INTENT: Intent;\n)\}\n",
        r"pub trait IntentMessage {\n\1\n"
        r"    /// Return the BCS bytes of the message.\n"
        r"    fn payload_bytes(&self) -> Vec<u8>;\n}\n\n"
        r"/// Return the BCS bytes of `value`.\n"
        r"pub fn bcs_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {\n"
        r'    bcs::to_bytes(value).expect("serialization should not fail")\n}\n',
        1,
    ),
    (
        INTENT,
        r"(impl<T: IntentMessage> IntentMessage for &T \{\n    const INTENT: Intent = T::INTENT;\n)(\})",
        r"\1\n    fn payload_bytes(&self) -> Vec<u8> {\n        (**self).payload_bytes()\n    }\n\2",
        1,
    ),
    (COMMITTEE, INTENT_IMPL, r"\1" + PAYLOAD_BYTES + r"\2", 1),
    (GUARDIAN_TYPES, INTENT_IMPL, r"\1" + PAYLOAD_BYTES + r"\2", 2),
    (MOVE_TYPES, INTENT_IMPL, r"\1" + PAYLOAD_BYTES + r"\2", 2),
    (
        COMMITTEE,
        r"    bcs::to_bytes\(&\(T::INTENT\.as_u16\(\), hashi_id, epoch, message\)\)\.unwrap\(\)\n",
        r"    let mut bytes = bcs::to_bytes(&(T::INTENT.as_u16(), hashi_id, epoch)).unwrap();\n"
        r"    bytes.extend_from_slice(&message.payload_bytes());\n"
        r"    bytes\n",
        1,
    ),
    (
        SIGNING,
        r"pub trait GuardianSigningIntent: Serialize \{\n(    const INTENT: GuardianSigningIntentType;\n)\}",
        r"pub trait GuardianSigningIntent {\n\1\n"
        r"    /// Return the BCS bytes of the payload.\n"
        r"    fn payload_bytes(&self) -> Vec<u8>;\n}",
        1,
    ),
    (
        SIGNING,
        r"(impl GuardianSigningIntent for [^{]+\{\n    const INTENT: GuardianSigningIntentType =\s+"
        r"GuardianSigningIntentType::\w+;\n)(\})",
        r"\1" + PAYLOAD_BYTES + r"\2",
        6,
    ),
    (
        SIGNING,
        r"(        T: GuardianSigningIntent,\n    \{\n)"
        r'        bcs::to_bytes\(&\(T::INTENT as u8, data\)\)\.expect\("serialization should not fail"\)\n',
        r"\1        let payload = data.payload_bytes();\n"
        r"        let mut bytes = Vec::with_capacity(1 + payload.len());\n"
        r"        bytes.push(T::INTENT as u8);\n"
        r"        bytes.extend_from_slice(&payload);\n"
        r"        bytes\n",
        1,
    ),
]

TEST_MODULE = "\n#[cfg(test)]\nmod "
PREAMBLE = """\
This patch makes the sync copy of the Guardian withdrawal handler for the Lean extraction.
`extract.sh` applies it to a copy of the workspace. It does not change the repository.
The patch has three kinds of edits: `async` to sync with a mock S3 log, no `tracing` lines,
and signing traits with a `payload_bytes` method in place of the `Serialize` supertrait.
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
