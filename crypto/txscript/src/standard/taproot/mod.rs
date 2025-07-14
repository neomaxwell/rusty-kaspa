use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_consensus_core::tx::ScriptPublicKey;

pub struct Taproot {}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Witness {
    content: Vec<u8>,
    witness_elements: usize,
    indices_start: usize,
}

impl TryFrom<&[u8]> for Witness {
    type Error = std::io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let this = BorshDeserialize::try_from_slice(bytes)?;
        Ok(this)
    }
}

impl TryFrom<&Witness> for Vec<u8> {
    type Error = std::io::Error;

    fn try_from(witness: &Witness) -> Result<Self, Self::Error> {
        borsh::to_vec(witness)
    }
}
