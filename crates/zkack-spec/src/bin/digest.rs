use std::{env, fs};

use zkack_spec::blake3_b64;

/// Extract DKIM body hash (bh=) from DKIM-Signature header (very lightweight parser).
/// Returns base64url (no padding) to match other token fields.
fn find_dkim_bh(eml_str: &str) -> Option<String> {
    // headers are before the first blank line
    let (hdrs, _) = eml_str
        .split_once("\r\n\r\n")
        .or_else(|| eml_str.split_once("\n\n"))?;

    // Collect DKIM-Signature header value with continuations
    let mut in_dkim = false;
    let mut val = String::new();
    for line in hdrs.lines() {
        if line.to_ascii_lowercase().starts_with("dkim-signature:") {
            in_dkim = true;
            val.push_str(line.splitn(2, ':').nth(1).unwrap_or("").trim());
            val.push(' ');
            continue;
        }
        if in_dkim {
            // header continuation
            if line.starts_with(' ') || line.starts_with('\t') {
                val.push_str(line.trim());
                val.push(' ');
                continue;
            } else {
                break;
            }
        }
    }
    if val.is_empty() {
        return None;
    }

    // Find bh=...; inside the header value
    let lower = val.to_ascii_lowercase();
    let pos = lower.find("bh=")?;
    let after = &val[(pos + 3)..];
    let end = after.find(';').unwrap_or(after.len());
    let bh = after[..end].trim();

    if bh.is_empty() {
        return None;
    }

    // Normalize to base64url no pad
    let bh_url = bh
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string();
    Some(bh_url)
}

fn main() -> anyhow::Result<()> {
    let path = env::args().nth(1).expect("usage: digest <path.eml>");
    let eml = fs::read(&path)?;
    let eml_str = String::from_utf8_lossy(&eml);

    let (digest_alg, msg_digest_b64) = if let Some(bh) = find_dkim_bh(&eml_str) {
        ("dkim-bh", bh)
    } else {
        ("blake3", blake3_b64(&eml))
    };

    println!(
        "{{\"digest_alg\":\"{}\",\"msg_digest_b64\":\"{}\"}}",
        digest_alg, msg_digest_b64
    );
    Ok(())
}
