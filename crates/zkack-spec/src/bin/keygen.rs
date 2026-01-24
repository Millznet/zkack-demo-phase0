use base64::Engine;
use serde_json::json;
use std::fs;
use zkack_spec::*;

fn main() -> anyhow::Result<()> {
    let (sk, vk) = generate_keypair();
    let kid = format!("dev-{}", uuid::Uuid::new_v4());
    let priv_json = PrivKeyJson {
        kid: kid.clone(),
        sk_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.to_bytes()),
        vk_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes()),
    };
    let pub_entry = PubKeyEntry {
        kid: kid.clone(),
        vk_b64: priv_json.vk_b64.clone(),
    };
    fs::create_dir_all("./keys")?;
    fs::write(
        "./keys/dev-priv.json",
        serde_json::to_string_pretty(&priv_json)?,
    )?;
    fs::write(
        "./keys/pubkeys.json",
        serde_json::to_string_pretty(&vec![pub_entry])?,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "message": "wrote ./keys/dev-priv.json and ./keys/pubkeys.json",
            "kid": kid
        }))?
    );
    Ok(())
}
