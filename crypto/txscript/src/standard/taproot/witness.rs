use bitcoin::Witness as BtcWitness;
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug)]
pub struct Witness {
    inner: BtcWitness,
}

impl TryFrom<&[u8]> for Witness {
    type Error = std::io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let slice: Vec<Vec<u8>> = BorshDeserialize::try_from_slice(bytes)?;
        let inner = BtcWitness::from_slice(&slice);
        Ok(Self { inner })
    }
}

impl TryFrom<&Witness> for Vec<u8> {
    type Error = std::io::Error;

    fn try_from(witness: &Witness) -> Result<Self, Self::Error> {
        let slice = witness.inner.to_vec();
        borsh::to_vec(&slice)
    }
}
