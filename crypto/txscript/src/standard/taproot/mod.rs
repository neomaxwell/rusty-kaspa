use crate::opcodes::codes::{OpData32, OpTrue};
use borsh::BorshDeserialize;
use kaspa_consensus_core::tx::ScriptPublicKey;

pub struct Taproot {}

// impl TryFrom {}

#[derive(Debug)]
pub struct Witness {
    stack: Vec<Vec<u8>>,
}

impl TryFrom<&[u8]> for Witness {
    type Error = std::io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let stack = BorshDeserialize::try_from_slice(bytes)?;
        Ok(Self { stack })
    }
}
