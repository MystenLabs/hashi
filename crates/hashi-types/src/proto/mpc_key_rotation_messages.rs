// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use prost::DecodeError;
use prost::Message;
use prost::encoding::DecodeContext;
use prost::encoding::WireType;
use prost::encoding::decode_varint;
use prost::encoding::encode_key;
use prost::encoding::encode_varint;
use prost::encoding::encoded_len_varint;
use prost::encoding::key_len;
use std::ops::Range;
use sui_rpc::proto::sui::rpc::v2::Bcs;

#[derive(Clone, Debug, Default)]
pub struct RotationMessages {
    pairs: Vec<(u32, Bcs)>,
    held: Vec<u8>,
    held_count: usize,
}

#[derive(Clone, PartialEq, Message)]
struct Entry {
    #[prost(uint32, tag = "1")]
    key: u32,
    #[prost(message, optional, tag = "2")]
    value: Option<Bcs>,
}

impl RotationMessages {
    pub fn len(&self) -> usize {
        self.pairs.len() + self.held_count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = Result<(u32, Bcs), DecodeError>> + '_ {
        self.pairs
            .iter()
            .cloned()
            .map(Ok)
            .chain(self.held_entries().map(parse))
    }

    pub fn into_entries(self) -> impl Iterator<Item = Result<(u32, Bcs), DecodeError>> {
        let held = Bytes::from(self.held);
        let mut position = 0;
        self.pairs
            .into_iter()
            .map(Ok)
            .chain(std::iter::from_fn(move || {
                next_entry(&held, &mut position).map(|range| parse(held.slice(range)))
            }))
    }

    fn held_entries(&self) -> impl Iterator<Item = &[u8]> + '_ {
        let mut position = 0;
        std::iter::from_fn(move || {
            next_entry(&self.held, &mut position).map(|range| &self.held[range])
        })
    }
}

fn parse(entry: impl Buf) -> Result<(u32, Bcs), DecodeError> {
    Entry::decode(entry).map(|Entry { key, value }| (key, value.unwrap_or_default()))
}

fn next_entry(held: &[u8], position: &mut usize) -> Option<Range<usize>> {
    let mut rest = held.get(*position..)?;
    let len = usize::try_from(decode_varint(&mut rest).ok()?).ok()?;
    let start = held.len() - rest.len();
    let end = start.checked_add(len).filter(|end| *end <= held.len())?;
    *position = end;
    Some(start..end)
}

impl FromIterator<(u32, Bcs)> for RotationMessages {
    fn from_iter<I: IntoIterator<Item = (u32, Bcs)>>(pairs: I) -> Self {
        Self {
            pairs: pairs.into_iter().collect(),
            ..Self::default()
        }
    }
}

impl PartialEq for RotationMessages {
    fn eq(&self, other: &Self) -> bool {
        let sorted = |messages: &Self| {
            let mut entries = messages.iter().collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.as_ref().map(|(key, _)| *key).ok());
            entries
        };
        sorted(self) == sorted(other)
    }
}

impl Message for RotationMessages {
    fn encode_raw(&self, buf: &mut impl BufMut) {
        for (key, value) in &self.pairs {
            encode_key(1, WireType::LengthDelimited, buf);
            encode_varint(pair_len(*key, value) as u64, buf);
            if *key != 0 {
                prost::encoding::uint32::encode(1, key, buf);
            }
            if *value != Bcs::default() {
                prost::encoding::message::encode(2, value, buf);
            }
        }
        for entry in self.held_entries() {
            encode_key(1, WireType::LengthDelimited, buf);
            encode_varint(entry.len() as u64, buf);
            buf.put_slice(entry);
        }
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError> {
        if tag != 1 {
            return prost::encoding::skip_field(wire_type, tag, buf, ctx);
        }
        let mut entry = Bytes::new();
        prost::encoding::bytes::merge(WireType::LengthDelimited, &mut entry, buf, ctx)?;
        encode_varint(entry.len() as u64, &mut self.held);
        self.held.extend_from_slice(&entry);
        self.held_count += 1;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        self.pairs
            .iter()
            .map(|(key, value)| {
                let len = pair_len(*key, value);
                key_len(1) + encoded_len_varint(len as u64) + len
            })
            .sum::<usize>()
            + self.held_count * key_len(1)
            + self.held.len()
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

fn pair_len(key: u32, value: &Bcs) -> usize {
    let key_bytes = if key == 0 {
        0
    } else {
        prost::encoding::uint32::encoded_len(1, &key)
    };
    let value_bytes = if *value == Bcs::default() {
        0
    } else {
        prost::encoding::message::encoded_len(2, value)
    };
    key_bytes + value_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;
    use test_strategy::proptest;

    #[derive(Clone, PartialEq, Message)]
    struct GeneratedRotationMessages {
        #[prost(map = "uint32, message", tag = "1")]
        messages: HashMap<u32, Bcs>,
    }

    fn bcs(name: Option<String>, value: Option<Vec<u8>>) -> Bcs {
        let mut bcs = Bcs::default();
        bcs.name = name;
        bcs.value = value.map(Bytes::from);
        bcs
    }

    fn any_bcs() -> impl Strategy<Value = Bcs> {
        (
            proptest::option::of("[a-z]{0,3}"),
            proptest::option::of(prop::collection::vec(any::<u8>(), 0..4)),
        )
            .prop_map(|(name, value)| bcs(name, value))
    }

    fn any_field() -> impl Strategy<Value = Vec<u8>> {
        let entry = (0u32..4, proptest::option::of(any_bcs()))
            .prop_map(|(key, value)| Entry { key, value }.encode_to_vec());
        (
            prop_oneof![3 => Just(1u64), 1 => 0u64..4],
            prop_oneof![3 => Just(2u64), 1 => 0u64..6],
            prop_oneof![entry, prop::collection::vec(any::<u8>(), 0..6)],
        )
            .prop_map(|(tag, wire_type, content)| {
                let mut field = Vec::new();
                encode_varint(tag << 3 | wire_type, &mut field);
                encode_varint(content.len() as u64, &mut field);
                field.extend(content);
                field
            })
    }

    #[test]
    fn a_held_map_grows_with_its_entries() {
        let mut wire = Vec::new();
        let mut key = 0u32;
        while wire.len() < 32 << 20 {
            key += 1;
            encode_key(1, WireType::LengthDelimited, &mut wire);
            encode_varint(
                (key_len(1) + encoded_len_varint(key.into())) as u64,
                &mut wire,
            );
            prost::encoding::uint32::encode(1, &key, &mut wire);
        }
        let wire_len = wire.len();
        let held = RotationMessages::decode(Bytes::from(wire)).unwrap();
        assert_eq!(held.held_count, key as usize);
        assert!(held.held.capacity() <= 2 * wire_len);

        let mut wire = [(1, bcs(None, Some(vec![1; 16])))]
            .into_iter()
            .collect::<RotationMessages>()
            .encode_to_vec();
        let entry_len = wire.len();
        prost::encoding::bytes::encode(2, &vec![0u8; 8 << 20], &mut wire);
        let held = RotationMessages::decode(Bytes::from(wire)).unwrap();
        assert_eq!(held.held_count, 1);
        assert!(held.held.capacity() <= 2 * entry_len);
        let buffer = held.held.as_ptr_range();
        let (_, value) = held.into_entries().next().unwrap().unwrap();
        assert!(buffer.contains(&value.value.unwrap().as_ptr()));
    }

    #[proptest]
    fn a_held_map_reads_what_the_generated_map_decodes(
        #[strategy(prop::collection::vec(any_field(), 0..6))] fields: Vec<Vec<u8>>,
        #[strategy(prop::collection::vec(any::<u8>(), 0..3))] tail: Vec<u8>,
    ) {
        let wire = [fields.concat(), tail].concat();
        let held = RotationMessages::decode(wire.as_slice());
        if let Ok(held) = &held {
            prop_assert_eq!(
                held.iter().collect::<Vec<_>>(),
                held.clone().into_entries().collect::<Vec<_>>()
            );
        }
        if let Ok(generated) = GeneratedRotationMessages::decode(wire.as_slice()) {
            let entries = held.unwrap().iter().collect::<Result<Vec<_>, _>>().unwrap();
            prop_assert_eq!(
                entries.into_iter().collect::<HashMap<_, _>>(),
                generated.messages
            );
        }
    }

    #[proptest]
    fn both_forms_encode_what_the_generated_map_decodes(
        #[strategy(prop::collection::hash_map(prop_oneof![0u32..3, any::<u32>()], any_bcs(), 0..6))]
        pairs: HashMap<u32, Bcs>,
    ) {
        let sent = pairs.clone().into_iter().collect::<RotationMessages>();
        let wire = sent.encode_to_vec();
        prop_assert_eq!(sent.encoded_len(), wire.len());
        prop_assert_eq!(
            &GeneratedRotationMessages::decode(wire.as_slice())
                .unwrap()
                .messages,
            &pairs
        );

        let generated = GeneratedRotationMessages { messages: pairs }.encode_to_vec();
        let held = RotationMessages::decode(generated.as_slice()).unwrap();
        prop_assert_eq!(&held, &sent);
        prop_assert_eq!(held.encoded_len(), generated.len());
        prop_assert_eq!(held.encode_to_vec(), generated);
    }
}
