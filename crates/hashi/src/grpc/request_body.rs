// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::ready;
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;

use super::peer_limit::RequestCharge;

pub(super) const PREFIX_LEN: u64 = 5;

const END_STREAM_WAIT: Duration = Duration::from_millis(100);

pub(super) struct LimitedBody {
    inner: axum::body::Body,
    charge: Arc<RequestCharge>,
    limit: usize,
    single_message: bool,
    state: State,
}

enum State {
    Prefix {
        bytes: [u8; PREFIX_LEN as usize],
        filled: usize,
    },
    Message {
        remaining: u64,
    },
    AwaitingEnd(Pin<Box<tokio::time::Sleep>>),
    Done,
}

impl State {
    fn prefix() -> Self {
        Self::Prefix {
            bytes: [0; PREFIX_LEN as usize],
            filled: 0,
        }
    }
}

impl LimitedBody {
    pub(super) fn new(
        inner: axum::body::Body,
        charge: Arc<RequestCharge>,
        limit: usize,
        single_message: bool,
    ) -> Self {
        Self {
            inner,
            charge,
            limit,
            single_message,
            state: State::prefix(),
        }
    }

    fn forwardable(&mut self, data: &[u8]) -> Result<usize, tonic::Status> {
        let mut consumed = 0;
        while consumed < data.len() {
            match &mut self.state {
                State::Prefix { bytes, filled } => {
                    let take = (bytes.len() - *filled).min(data.len() - consumed);
                    bytes[*filled..*filled + take]
                        .copy_from_slice(&data[consumed..consumed + take]);
                    *filled += take;
                    consumed += take;
                    if *filled == bytes.len() {
                        let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
                        self.admit(len)?;
                    }
                }
                State::Message { remaining } => {
                    let take = u64::try_from(data.len() - consumed)
                        .unwrap_or(u64::MAX)
                        .min(*remaining);
                    *remaining -= take;
                    consumed += take as usize;
                    if *remaining == 0 {
                        self.message_complete();
                    }
                }
                State::AwaitingEnd(_) | State::Done => break,
            }
        }
        Ok(consumed)
    }

    fn admit(&mut self, len: u32) -> Result<(), tonic::Status> {
        let limit = self.limit;
        if usize::try_from(len).is_ok_and(|len| len > limit) {
            self.charge.refuse_too_large();
            return Err(tonic::Status::out_of_range(format!(
                "declared message length {len} exceeds this route's limit of {limit} bytes"
            )));
        }
        if !self.charge.reserve(PREFIX_LEN + u64::from(len)) {
            return Err(tonic::Status::unavailable(super::PEER_INFLIGHT_LIMIT_MSG));
        }
        self.state = State::Message {
            remaining: u64::from(len),
        };
        if len == 0 {
            self.message_complete();
        }
        Ok(())
    }

    fn message_complete(&mut self) {
        self.state = if self.single_message {
            State::AwaitingEnd(Box::pin(tokio::time::sleep(END_STREAM_WAIT)))
        } else {
            State::prefix()
        };
    }
}

impl http_body::Body for LimitedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.get_mut();
        loop {
            if let State::AwaitingEnd(deadline) = &mut this.state {
                let polled = Pin::new(&mut this.inner).poll_frame(cx);
                if let Poll::Ready(Some(Ok(frame))) = &polled
                    && frame.data_ref().is_some_and(Bytes::is_empty)
                {
                    continue;
                }
                if polled.is_pending() && deadline.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                this.state = State::Done;
                return match polled {
                    Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => {
                        Poll::Ready(Some(Ok(frame)))
                    }
                    Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
                    _ => Poll::Ready(None),
                };
            }
            if matches!(this.state, State::Done) {
                return Poll::Ready(None);
            }
            let frame = match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => frame,
                other => {
                    this.state = State::Done;
                    return Poll::Ready(other);
                }
            };
            let data = match frame.into_data() {
                Ok(data) => data,
                Err(frame) => return Poll::Ready(Some(Ok(frame))),
            };
            match this.forwardable(&data) {
                Ok(0) => continue,
                Ok(forward) => return Poll::Ready(Some(Ok(Frame::data(data.slice(..forward))))),
                Err(status) => {
                    this.state = State::Done;
                    return Poll::Ready(Some(Err(axum::Error::new(status))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.state, State::Done)
    }
}
