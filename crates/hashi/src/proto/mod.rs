// Include the generated proto definitions

pub mod sui {
    pub mod rpc {
        pub mod v2 {
            include!("generated/sui.rpc.v2.rs");
        }
    }
    pub mod hashi {
        pub mod v1alpha {
            include!("generated/sui.hashi.v1alpha.rs");
        }
    }
}

/// Byte encoded FILE_DESCRIPTOR_SET.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!("generated/sui.hashi.v1alpha.fds.bin");

#[cfg(test)]
mod tests {
    use super::FILE_DESCRIPTOR_SET;
    use prost::Message as _;

    #[test]
    fn file_descriptor_set_is_valid() {
        prost_types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    }
}
