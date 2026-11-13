// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A reference Bitcoin source over the Esplora HTTP API, such as mempool.space.
//!
//! Why it exists: whoever controls the peers of the monitor's node can withhold
//! blocks from it. The node then cannot see an honest deposit, and a fake one
//! looks the same. The auditor counts a fresh deposit approval as paid when
//! either source shows its payment, so one stalled source cannot cause a pause
//! or hide a fake deposit.

use std::collections::HashMap;

use anyhow::Context;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use serde::Deserialize;

const REQUEST_TIMEOUT_SECS: u64 = 10;

/// What the reference source holds at an outpoint. See `OutpointState`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceOutput {
    /// The transaction is unknown or not confirmed deep enough, or it has no
    /// output at that vout.
    Missing,
    /// The output exists, and a transaction, also in the mempool, spent it.
    Spent,
    /// The output exists and is unspent.
    Unspent {
        amount: u64,
        script_pubkey: ScriptBuf,
    },
}

pub struct EsploraClient {
    url: String,
    /// Confirmations a transaction needs to count as confirmed.
    confirmations: u64,
}

#[derive(Deserialize)]
struct Transaction {
    status: TransactionStatus,
    vout: Vec<TransactionOutput>,
}

#[derive(Deserialize)]
struct TransactionStatus {
    confirmed: bool,
    block_height: Option<u64>,
}

#[derive(Deserialize)]
struct TransactionOutput {
    value: u64,
    scriptpubkey: String,
}

#[derive(Deserialize)]
struct Outspend {
    spent: bool,
}

impl EsploraClient {
    pub fn new(url: &str, confirmations: u64) -> Self {
        Self {
            url: url.trim_end_matches('/').to_owned(),
            confirmations,
        }
    }

    /// The state of each outpoint at the source's current tip.
    pub fn lookup_outputs(
        &self,
        outpoints: &[OutPoint],
    ) -> anyhow::Result<HashMap<OutPoint, ReferenceOutput>> {
        let tip_height = self
            .get("/blocks/tip/height")?
            .context("esplora has no tip height")?
            .as_str()?
            .trim()
            .parse::<u64>()
            .context("failed to parse the esplora tip height")?;
        outpoints
            .iter()
            .map(|outpoint| Ok((*outpoint, self.lookup(outpoint, tip_height)?)))
            .collect()
    }

    fn lookup(&self, outpoint: &OutPoint, tip_height: u64) -> anyhow::Result<ReferenceOutput> {
        let Some(response) = self.get(&format!("/tx/{}", outpoint.txid))? else {
            return Ok(ReferenceOutput::Missing);
        };
        let transaction: Transaction = response
            .json()
            .context("failed to parse an esplora transaction")?;
        let (true, Some(block_height)) = (
            transaction.status.confirmed,
            transaction.status.block_height,
        ) else {
            return Ok(ReferenceOutput::Missing);
        };
        if block_height.saturating_add(self.confirmations) > tip_height.saturating_add(1) {
            return Ok(ReferenceOutput::Missing);
        }
        let Some(output) = transaction.vout.get(outpoint.vout as usize) else {
            return Ok(ReferenceOutput::Missing);
        };
        let outspend: Outspend = self
            .get(&format!("/tx/{}/outspend/{}", outpoint.txid, outpoint.vout))?
            .with_context(|| format!("esplora has no outspend for {outpoint}"))?
            .json()
            .context("failed to parse an esplora outspend")?;
        if outspend.spent {
            return Ok(ReferenceOutput::Spent);
        }
        Ok(ReferenceOutput::Unspent {
            amount: output.value,
            script_pubkey: ScriptBuf::from_hex(&output.scriptpubkey)
                .context("failed to parse an esplora script")?,
        })
    }

    /// The response to `GET path`, or `None` on HTTP 404.
    fn get(&self, path: &str) -> anyhow::Result<Option<minreq::Response>> {
        let response = minreq::get(format!("{}{path}", self.url))
            .with_timeout(REQUEST_TIMEOUT_SECS)
            .send()
            .with_context(|| format!("esplora request {path} failed"))?;
        match response.status_code {
            200 => Ok(Some(response)),
            404 => Ok(None),
            code => anyhow::bail!("esplora request {path} answered HTTP {code}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::respond;
    use crate::test_utils::txid;
    use std::net::TcpListener;

    /// A URL whose next requests get `responses`, in order.
    fn esplora_answering(responses: Vec<String>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for response in responses {
                respond(&listener, &response);
            }
        });
        (url, server)
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn transaction(block_height: u64) -> String {
        ok(&format!(
            r#"{{"status":{{"confirmed":true,"block_height":{block_height}}},"vout":[{{"value":5000,"scriptpubkey":"51"}}]}}"#
        ))
    }

    #[test]
    fn outputs_are_read_at_the_confirmation_depth() {
        let not_found = "Transaction not found";
        let (url, server) = esplora_answering(vec![
            ok("100"),
            transaction(95),
            ok(r#"{"spent":false}"#),
            transaction(95),
            ok(r#"{"spent":true}"#),
            transaction(96),
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\r\n{not_found}",
                not_found.len()
            ),
        ]);
        let outpoint = |fill| OutPoint {
            txid: txid(fill),
            vout: 0,
        };
        let outpoints = [outpoint(1), outpoint(2), outpoint(3), outpoint(4)];

        let outputs = EsploraClient::new(&url, 6)
            .lookup_outputs(&outpoints)
            .unwrap();
        server.join().unwrap();

        assert_eq!(
            outputs[&outpoints[0]],
            ReferenceOutput::Unspent {
                amount: 5000,
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }
        );
        assert_eq!(outputs[&outpoints[1]], ReferenceOutput::Spent);
        // Five confirmations at tip 100.
        assert_eq!(outputs[&outpoints[2]], ReferenceOutput::Missing);
        assert_eq!(outputs[&outpoints[3]], ReferenceOutput::Missing);
    }
}
