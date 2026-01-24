use anyhow::{anyhow, Result};
use base64::Engine;
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use regex::Regex;
use std::fs;
use time::OffsetDateTime;
use zkack_spec::*;

/// Simple signer: reads an RFC5322 message (.eml), injects X-ZK-DAT header, prints to stdout.
#[derive(Parser, Debug)]
struct Args {
    /// Path to private key JSON (kid, sk_b64, vk_b64)
    #[arg(long)]
    privkey: String,
    /// Key id to use (must match priv key file)
    #[arg(long)]
    kid: Option<String>,
    /// Recipient address (for addr_hash computation)
    #[arg(long)]
    to: String,
    /// From address (not used in skeleton hashing, but future DKIM alignment)
    #[arg(long)]
    from: String,
    /// Input .eml file path
    eml: String,
    /// ACK deadline seconds (default 900s)
    #[arg(long, default_value_t = 900)]
    ack_by_secs: u64,
}

fn find_dkim_bh(eml_str: &str) -> Option<String> {
    // grab DKIM-Signature header (with folded lines)
    let mut collecting = false;
    let mut buf = String::new();
    for line in eml_str.lines() {
        if !collecting {
            if line.to_ascii_lowercase().starts_with("dkim-signature:") {
                collecting = true;
                buf.push_str(line);
                buf.push_str("\r\n");
            }
        } else {
            if line.starts_with(' ') || line.starts_with('\t') {
                buf.push_str(line);
                buf.push_str("\r\n");
            } else {
                break;
            }
        }
    }
    if buf.is_empty() {
        return None;
    }
    // regex for bh=...; (no spaces, ends at ; or end)
    let re = Regex::new(r"(?i)\bbh=([^;\s\r\n]+)").ok()?;
    let caps = re.captures(&buf)?;
    Some(caps.get(1)?.as_str().to_string())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let eml = fs::read(&args.eml)?;
    let eml_str = String::from_utf8_lossy(&eml);

    // prefer DKIM body hash if present, else blake3 of the raw .eml
    let (digest_alg, msg_digest_b64) = if let Some(bh) = find_dkim_bh(&eml_str) {
        ("dkim-bh".to_string(), bh)
    } else {
        ("blake3".to_string(), blake3_b64(&eml))
    };

    // Load private key
    let raw = fs::read_to_string(&args.privkey)?;
    let pkj: PrivKeyJson = serde_json::from_str(&raw)?;

    let kid = match args.kid.clone() {
        Some(k) => {
            if k != pkj.kid {
                anyhow::bail!("kid mismatch between --kid and privkey file");
            }
            k
        }
        None => pkj.kid.clone(),
    };

    let sk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pkj.sk_b64)?;
    let sk = SigningKey::from_bytes(&sk_bytes.try_into().map_err(|_| anyhow!("bad sk length"))?);

    // Prepare DAT
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let addr_hash = addr_hash_b64(&salt, &args.to);
    let exp = (OffsetDateTime::now_utc() + time::Duration::seconds(args.ack_by_secs as i64))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let dat = DatPayload {
        v: 1,
        salt_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(salt),
        addr_hash_b64: addr_hash,
        msg_digest_b64,
        digest_alg,
        exp,
        nonce_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
        policy: Policy {
            ack_by_secs: args.ack_by_secs,
            fallbacks: vec!["portal".into(), "sms".into()],
        },
    };
    let dat_json = serde_json::to_string(&dat)?;
    let jws = jws_sign(&dat_json, &kid, &sk);

    // Inject header before headers/body blank line
    let mut out = String::new();
    let mut inserted = false;
    for line in eml_str.lines() {
        if !inserted && line.trim().is_empty() {
            out.push_str(&format!("X-ZK-DAT: {}\r\n", jws));
            inserted = true;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !inserted {
        out = format!("X-ZK-DAT: {}\r\n{}", jws, eml_str);
    }
    print!("{}", out);
    Ok(())
}
