use anyhow::Result;

/// Generic trait for proof systems used by ZK-ACK
pub trait ProofSystem {
    fn prove(addr_hash_b64: &str, msg_digest_b64: &str, nonce_b64: &str) -> Result<Vec<u8>>;
    fn verify(
        addr_hash_b64: &str,
        msg_digest_b64: &str,
        nonce_b64: &str,
        proof: &[u8],
    ) -> Result<bool>;
}

/// Mock proof system; replace with Halo2/Groth16
pub struct MockProof;
impl ProofSystem for MockProof {
    fn prove(_a: &str, _m: &str, _n: &str) -> Result<Vec<u8>> {
        Ok(b"mock-proof-ok".to_vec())
    }
    fn verify(_a: &str, _m: &str, _n: &str, proof: &[u8]) -> Result<bool> {
        Ok(proof == b"mock-proof-ok")
    }
}
