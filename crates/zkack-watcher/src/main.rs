use anyhow::{anyhow, Result};
use clap::Parser;
use mailparse::parse_mail;
use std::fs;
use time::OffsetDateTime;
use zkack_spec::*;

#[derive(Parser, Debug)]
struct Args {
    /// Verifier base URL (e.g., http://127.0.0.1:8080)
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    verifier: String,
    /// Path to a single .eml file to ACK (shortcut for pilots)
    #[arg(long)]
    eml: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let eml = fs::read(&args.eml)?;
    let parsed = parse_mail(&eml)?;

    // Extract X-ZK-DAT header
    let mut dat_jws = None;
    for h in parsed.get_headers() {
        if h.get_key_ref().eq_ignore_ascii_case("X-ZK-DAT") {
            dat_jws = Some(h.get_value());
            break;
        }
    }
    let dat_jws = dat_jws.ok_or_else(|| anyhow!("X-ZK-DAT not found"))?;

    // Recompute digest the same way the signer did (skeleton: whole .eml blake3)
    let _digest = blake3_b64(&eml);
    let now = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    // Post ACK (proof is mocked as "mock-proof-ok")
    let body = serde_json::json!({
        "dat_jws": dat_jws,
        "proof": "mock-proof-ok",
        "received_ts": now,
        "recv_domain": "local.test",
        "dkim_pass": true,
    });

    let url = format!("{}/zk-ack/v1/ack", args.verifier.trim_end_matches('/'));
    let resp = reqwest::Client::new().post(&url).json(&body).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    println!("Verifier {} -> {}", status, text);
    Ok(())
}
