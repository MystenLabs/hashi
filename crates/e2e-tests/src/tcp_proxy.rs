// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A severable TCP forwarding proxy.
//!
//! Tests interpose this between a Hashi node and the Sui fullnode to
//! simulate a network outage: [`TcpProxy::sever`] cuts every live
//! connection and refuses new ones (the node's streams break and its
//! reconnect attempts fail fast), and [`TcpProxy::restore`] lets the
//! next reconnect attempt through.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use anyhow::Result;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tracing::debug;

pub struct TcpProxy {
    local_addr: SocketAddr,
    enabled: Arc<AtomicBool>,
    /// Abort handles for the live connection-forwarding tasks; aborting
    /// one resets its client connection. Finished entries are pruned on
    /// each accept.
    live: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl TcpProxy {
    /// Start a proxy on an ephemeral local port, forwarding to `target`.
    pub async fn start(target: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        let enabled = Arc::new(AtomicBool::new(true));
        let live: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::new(Mutex::new(Vec::new()));

        let accept_enabled = enabled.clone();
        let accept_live = live.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((mut inbound, peer)) = listener.accept().await else {
                    return;
                };
                if !accept_enabled.load(Ordering::Relaxed) {
                    // Dropping the accepted socket closes it immediately,
                    // so the client's attempt fails fast instead of
                    // waiting out a stall timeout.
                    debug!(%peer, "severed proxy refused a connection");
                    continue;
                }
                let forward = tokio::spawn(async move {
                    let Ok(mut outbound) = TcpStream::connect(target).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                });
                let mut live = accept_live.lock().unwrap();
                live.retain(|handle| !handle.is_finished());
                live.push(forward.abort_handle());
            }
        });

        Ok(Self {
            local_addr,
            enabled,
            live,
            accept_task,
        })
    }

    /// The proxy's listening address, as an `http://` URL.
    pub fn url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// Cut every live connection and refuse new ones until
    /// [`TcpProxy::restore`].
    pub fn sever(&self) {
        self.enabled.store(false, Ordering::Relaxed);
        for handle in self.live.lock().unwrap().drain(..) {
            handle.abort();
        }
    }

    /// Accept connections again.
    pub fn restore(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }
}

impl Drop for TcpProxy {
    fn drop(&mut self) {
        self.accept_task.abort();
        for handle in self.live.lock().unwrap().drain(..) {
            handle.abort();
        }
    }
}
