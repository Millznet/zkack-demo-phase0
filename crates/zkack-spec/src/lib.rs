use anyhow::{anyhow, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// URL-safe base64 helpers
fn b64e(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}
fn b64d(input: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub ack_by_secs: u64,
    pub fallbacks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatPayload {
    pub v: u8,
    pub salt_b64: String,       // 32B random salt (base64url)
    pub addr_hash_b64: String,  // H(salt || addr) -> base64url (placeholder hash)
    pub msg_digest_b64: String, // message digest -> base64url
    pub digest_alg: String,     // "blake3" (skeleton; swap for DKIM bh later)
    pub exp: String,            // ISO8601 UTC
    pub nonce_b64: String,      // 16-32B
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsHeader {
    pub alg: String, // "EdDSA"
    pub kid: String, // key id
}

/// Compact JWS: base64url(header).base64url(payload).base64url(signature)
pub fn jws_sign(payload_json: &str, kid: &str, sk: &SigningKey) -> String {
    let header = JwsHeader {
        alg: "EdDSA".into(),
        kid: kid.into(),
    };
    let header_b64 = b64e(&serde_json::to_vec(&header).unwrap());
    let payload_b64 = b64e(payload_json.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let sig: Signature = sk.sign(signing_input.as_bytes());
    let sig_b64 = b64e(&sig.to_bytes());
    format!("{}.{}", signing_input, sig_b64)
}

pub fn jws_verify(
    jws: &str,
    get_vk: &dyn Fn(&str) -> Option<VerifyingKey>,
) -> Result<(JwsHeader, DatPayload)> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("bad jws format"));
    }
    let header_json = String::from_utf8(b64d(parts[0])?)?;
    let header: JwsHeader = serde_json::from_str(&header_json)?;
    if header.alg != "EdDSA" {
        return Err(anyhow!("unsupported alg"));
    }
    let payload_json = String::from_utf8(b64d(parts[1])?)?;
    let vk = get_vk(&header.kid).ok_or_else(|| anyhow!("unknown kid"))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64d(parts[2])?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| anyhow!("sig parse: {}", e))?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|e| anyhow!("verify failed: {}", e))?;
    let payload: DatPayload = serde_json::from_str(&payload_json)?;
    Ok((header, payload))
}

/// Compute blake3 digest and return base64url
pub fn blake3_b64(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    b64e(hash.as_bytes())
}

/// Compute addr_hash = blake3(salt || addr)  (placeholder for Poseidon)
pub fn addr_hash_b64(salt: &[u8], addr: &str) -> String {
    let mut ctx = blake3::Hasher::new();
    ctx.update(salt);
    ctx.update(addr.as_bytes());
    let out = ctx.finalize();
    b64e(out.as_bytes())
}

/// Utility: parse ISO8601 -> OffsetDateTime
pub fn parse_iso(ts: &str) -> Result<OffsetDateTime> {
    Ok(OffsetDateTime::parse(
        ts,
        &time::format_description::well_known::Rfc3339,
    )?)
}

/// Generate a new Ed25519 keypair (dev)
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// Serialize private/public keys to small JSON files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivKeyJson {
    pub kid: String,
    pub sk_b64: String,
    pub vk_b64: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyEntry {
    pub kid: String,
    pub vk_b64: String,
}
