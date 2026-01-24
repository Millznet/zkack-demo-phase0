use axum::http::StatusCode;
use axum::{
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, net::SocketAddr, path::Path, sync::Arc};
use time::OffsetDateTime;
use tracing_subscriber::{fmt::Subscriber, EnvFilter};
use uuid::Uuid;

use zkack_spec::*; // jws_verify, DatPayload, JwsHeader, PubKeyEntry, etc.

#[derive(Clone)]
struct AppState {
    keys: Arc<HashMap<String, VerifyingKey>>,
    db: sled::Db,
}

#[derive(Debug, Deserialize)]
struct AckReq {
    dat_jws: String,
    proof: String,
    received_ts: String,
    recv_domain: String,
    recv_domain_sig: Option<String>,
    msg_id: Option<String>,
    dkim_pass: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
struct VerifyReq {
    dat_jws: String,
    // Optional: client-computed digest of the message; if provided, we compare to DAT payload.
    msg_digest_b64: Option<String>,
}

#[derive(Debug, Serialize)]
struct AckResp {
    ack_id: Uuid,
    status: &'static str,
}

fn unprocessable<T: std::fmt::Display>(e: T) -> (StatusCode, String) {
    (StatusCode::UNPROCESSABLE_ENTITY, format!("{e}"))
}

async fn handle_ack(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(req): Json<AckReq>,
) -> Result<Json<AckResp>, (StatusCode, String)> {
    // v0: proof is mocked; require non-empty so the field is used (and callers can't omit it).
    if req.proof.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty proof".to_string()));
    }

    // Verify JWS and parse DAT
    let (hdr, dat) =
        jws_verify(&req.dat_jws, &|kid| state.keys.get(kid).cloned()).map_err(unprocessable)?;

    // Check expiration
    let exp = OffsetDateTime::parse(&dat.exp, &time::format_description::well_known::Rfc3339)
        .map_err(unprocessable)?;
    if OffsetDateTime::now_utc() > exp {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "422 invalid: DAT expired".into(),
        ));
    }

    // Create record
    let ack_id = Uuid::new_v4();
    let now_iso = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let record = serde_json::json!({
        "ack_id": ack_id,
        "kid": hdr.kid,                   // <— store kid so ?kid= works
        "dat": dat,
        "received_ts": req.received_ts,
        "recv_domain": req.recv_domain,
        "recv_domain_sig": req.recv_domain_sig,
        "msg_id": req.msg_id,
        "dkim_pass": req.dkim_pass.unwrap_or(true),
        "stored_at": now_iso,
    });

    state
        .db
        .insert(ack_id.as_bytes(), serde_json::to_vec(&record).unwrap())
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("500 db insert: {e}"),
            )
        })?;
    state.db.flush().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("500 db flush: {e}"),
        )
    })?;

    Ok(Json(AckResp {
        ack_id,
        status: "DELIVERED",
    }))
}

async fn handle_verify(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Json(req): axum::Json<VerifyReq>,
) -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let (hdr, dat) = jws_verify(&req.dat_jws, &|kid| state.keys.get(kid).cloned())
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("bad DAT: {e}")))?;

    let digest_match = req
        .msg_digest_b64
        .as_ref()
        .map(|d| d == &dat.msg_digest_b64);

    Ok(axum::Json(serde_json::json!({
        "ok": true,
        "kid": hdr.kid,
        "dat": dat,
        "digest_match": digest_match
    })))
}

async fn list_receipts(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<serde_json::Value> {
    let mut items = Vec::new();
    for kv in state.db.iter() {
        if let Ok((_k, v)) = kv {
            if let Ok(s) = String::from_utf8(v.to_vec()) {
                if let Ok(j) = serde_json::from_str::<serde_json::Value>(&s) {
                    items.push(j);
                }
            }
        }
    }
    Json(serde_json::json!({ "receipts": items }))
}

use axum::extract::{Query, State};

#[derive(serde::Deserialize)]
struct ReceiptQuery {
    kid: Option<String>,   // requires we stored "kid" in record
    since: Option<String>, // RFC3339
    limit: Option<usize>,  // cap results
}

async fn search_receipts(
    State(state): State<AppState>,
    Query(q): Query<ReceiptQuery>,
) -> Json<serde_json::Value> {
    let mut items: Vec<serde_json::Value> = Vec::new();
    let since_ts = q.since.and_then(|s| {
        time::OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339).ok()
    });

    for kv in state.db.iter() {
        if let Ok((_k, v)) = kv {
            if let Ok(s) = String::from_utf8(v.to_vec()) {
                if let Ok(j) = serde_json::from_str::<serde_json::Value>(&s) {
                    // since filter
                    if let (Some(stxt), Some(sts)) =
                        (j.get("stored_at").and_then(|x| x.as_str()), since_ts)
                    {
                        if let Ok(st) = time::OffsetDateTime::parse(
                            stxt,
                            &time::format_description::well_known::Rfc3339,
                        ) {
                            if st < sts {
                                continue;
                            }
                        }
                    }
                    // kid filter
                    if let Some(ref want) = q.kid {
                        if let Some(k) = j.get("kid").and_then(|x| x.as_str()) {
                            if k != want {
                                continue;
                            }
                        }
                    }
                    items.push(j);
                }
            }
        }
    }

    // newest first by stored_at
    items.sort_by(|a, b| {
        let pa = a.get("stored_at").and_then(|x| x.as_str()).and_then(|s| {
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
        });
        let pb = b.get("stored_at").and_then(|x| x.as_str()).and_then(|s| {
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
        });
        pb.cmp(&pa)
    });

    if let Some(lim) = q.limit {
        if items.len() > lim {
            items.truncate(lim);
        }
    }

    Json(serde_json::json!({ "receipts": items }))
}

async fn healthz(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<serde_json::Value> {
    let count = state.db.iter().count();
    Json(serde_json::json!({
        "status": "ok",
        "receipts": count,
        "time": time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = Subscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // Load public keys
    let keys_json = fs::read_to_string("./keys/pubkeys.json")?;
    let entries: Vec<PubKeyEntry> = serde_json::from_str(&keys_json)?;
    let mut map = HashMap::new();
    for e in entries {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(e.vk_b64)?;
        let vk_bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("vk len"))?;
        let vk = VerifyingKey::from_bytes(&vk_bytes)?;
        map.insert(e.kid, vk);
    }

    // DB
    let db_dir = std::env::var("ZKACK_DB_DIR").unwrap_or_else(|_| "./data/receipts".into());
    fs::create_dir_all(&db_dir).ok();
    let db_path =
        std::env::var("ZKACK_DB_PATH").unwrap_or_else(|_| "./data/receipts/db".to_string());
    if let Some(parent) = Path::new(&db_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create db dir failed: {}", e))?;
    }
    let db = sled::open(&db_path)
        .map_err(|e| anyhow::anyhow!("open db failed (path={}): {}", db_path, e))?;
    tracing::info!(db_path=%db_path, "opened receipts db");

    let state = AppState {
        keys: Arc::new(map),
        db,
    };

    // Routes
    let app = Router::new()
        .route("/zk-ack/v1/ack", post(handle_ack))
        .route("/zk-ack/v1/verify", post(handle_verify))
        .route("/zk-ack/v1/receipts", get(list_receipts))
        .route("/zk-ack/v1/receipts/search", get(search_receipts))
        .route("/healthz", get(healthz))
        .with_state(state);

    // Listen
    let port: u16 = std::env::var("ZKACK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8787);
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("zkack-verifier listening on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
