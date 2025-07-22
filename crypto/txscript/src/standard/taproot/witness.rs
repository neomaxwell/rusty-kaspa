use bitcoin::{taproot::Signature as BtcTaprootSignature, witness::P2TrSpend, TapSighashType, Witness as BtcWitness};
use borsh::BorshDeserialize;
use kaspa_txscript_errors::TxScriptError;
use secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};

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

impl<'a> TryFrom<&'a Witness> for P2TrSpend<'a> {
    type Error = TxScriptError;

    fn try_from(witness: &'a Witness) -> Result<Self, Self::Error> {
        match P2TrSpend::from_witness(&witness.inner) {
            Some(p2tr) => Ok(p2tr),
            None => Err(TxScriptError::InvalidTaprootWitness),
        }
    }
}

impl Witness {
    pub fn p2tr_key_spend(signature: Signature, sighash_type: TapSighashType) -> Self {
        let taproot_signature = BtcTaprootSignature { signature, sighash_type };
        let inner = BtcWitness::p2tr_key_spend(&taproot_signature);
        Self { inner }
    }

    pub fn execute_taproot(&self, msg: &Message, pk: &[u8]) -> Result<bool, TxScriptError> {
        let p2tr = P2TrSpend::try_from(self)?;
        let signature = match p2tr {
            P2TrSpend::Key { signature, .. } => signature,
            P2TrSpend::Script { .. } => todo!("taproot script path spend unsupported"),
        };
        self.verify(signature, msg, pk).map_err(TxScriptError::InvalidSignature)?;
        Ok(false)
    }

    fn verify(&self, signature: &[u8], msg: &Message, pk: &[u8]) -> Result<(), secp256k1::Error> {
        let xpub = XOnlyPublicKey::from_slice(pk)?;
        let sig = Signature::from_slice(signature)?;
        let secp = Secp256k1::new();
        secp.verify_schnorr(&sig, &msg, &xpub)
    }
}
