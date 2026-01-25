#!/usr/bin/env bash
set -euo pipefail
set +H

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

SAMPLE="$ROOT/samples/sample.eml"
test -f "$SAMPLE" || { echo "Missing sample: $SAMPLE" >&2; exit 1; }

TS="$(date +%y%m%d_%H%M%S)"
OUTDIR="/tmp/zkack_demo_${TS}"
PORT="${ZKACK_PORT:-8787}"
DB_PATH="${ZKACK_DB_PATH:-$OUTDIR/receipts_db}"
VERIFIER_LOG="$OUTDIR/verifier.log"

mkdir -p "$OUTDIR" "$OUTDIR/keys"
KEY_PRIV="$OUTDIR/keys/dev-priv.json"
KEY_PUB="$OUTDIR/keys/pubkeys.json"

# These env vars are harmless if unused; helpful if verifier supports them.
export RUST_LOG="${RUST_LOG:-info}"
export ZKACK_PORT="$PORT"
export ZKACK_DB_PATH="$DB_PATH"
export ZKACK_PUBKEYS_PATH="$OUTDIR/keys/pubkeys.json"
export ZKACK_PUBKEYS="$OUTDIR/keys/pubkeys.json"
export PUBKEYS_PATH="$OUTDIR/keys/pubkeys.json"

echo "OUTDIR=$OUTDIR"
echo "PORT=$PORT"
echo "DB_PATH=$DB_PATH"
echo "VERIFIER_LOG=$VERIFIER_LOG"
echo

echo "== build once =="
cargo build -q -p zkack-verifier -p zkack-signer -p zkack-watcher -p zkack-spec
echo "built."
echo

keygen_maybe() {
  local keygen=""
  for c in "$ROOT/target/debug/keygen" "$ROOT/target/debug/zkack-spec-keygen"; do
    [[ -x "$c" ]] && keygen="$c" && break
  done
  [[ -n "$keygen" ]] || keygen="$(ls -1 "$ROOT"/target/debug/*keygen* 2>/dev/null | head -n 1 || true)"
  [[ -n "$keygen" ]] || { echo "keygen binary not found under target/debug" >&2; return 1; }

  if [[ -f "$OUTDIR/keys/dev-priv.json" && -f "$OUTDIR/keys/pubkeys.json" ]]; then
    return 0
  fi

  echo "== keygen (into OUTDIR) =="
  # Phase0 keygen writes ./keys/* relative to CWD, so run it inside OUTDIR
  ( cd "$OUTDIR" && "$keygen" )
  [[ -f "$OUTDIR/keys/dev-priv.json" && -f "$OUTDIR/keys/pubkeys.json" ]] || {
    echo "keygen did not produce OUTDIR keys" >&2
    ls -la "$OUTDIR/keys" || true
    return 1
  }
}

keygen_maybe


# If 8787 is taken, hop ports so we don't talk to an old process.
if ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then
  ALT_PORT="${ZKACK_ALT_PORT:-18787}"
  echo "PORT $PORT already in use; switching to $ALT_PORT"
  PORT="$ALT_PORT"
  export ZKACK_PORT="$PORT"
fi

# keygen writes to ./keys by default; mirror into OUTDIR for this run.
mkdir -p "$OUTDIR/keys"
if [[ -f "$ROOT/keys/dev-priv.json" && -f "$ROOT/keys/pubkeys.json" ]]; then
  cp -f "$ROOT/keys/dev-priv.json" "$KEY_PRIV"
  cp -f "$ROOT/keys/pubkeys.json" "$KEY_PUB"
fi

# Force verifier pubkeys path (covers multiple env var names)
export ZKACK_PUBKEYS_PATH="$KEY_PUB"
export ZKACK_PUBKEYS="$KEY_PUB"
export PUBKEYS_PATH="$KEY_PUB"

echo "== start verifier (CWD=OUTDIR so it loads OUTDIR/keys/pubkeys.json) =="
( cd "$OUTDIR" && "$ROOT/target/debug/zkack-verifier" ) >"$VERIFIER_LOG" 2>&1 &
VPID=$!
trap 'kill "$VPID" 2>/dev/null || true; wait "$VPID" 2>/dev/null || true' EXIT

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:${PORT}/healthz" | tee "$OUTDIR/healthz.json"
echo
echo

echo "== sign sample =="
cp "$SAMPLE" "$OUTDIR/sample.eml"
"$ROOT/target/debug/zkack-signer" \
  --privkey "$OUTDIR/keys/dev-priv.json" \
  --to you@example.com \
  --from agency@example.gov \
  "$OUTDIR/sample.eml" > "$OUTDIR/signed.eml"
echo "signed: $OUTDIR/signed.eml"
echo

echo "== extract DAT JWS (sanitize folding/whitespace) =="
DAT_JWS="$(python3 - <<PY
import email
from email import policy
from pathlib import Path
msg = email.message_from_bytes(Path("$OUTDIR/signed.eml").read_bytes(), policy=policy.default)
v = msg["X-ZK-DAT"] or ""
print("".join(str(v).split()))
PY
)"
[[ -n "$DAT_JWS" ]] || { echo "ERROR: X-ZK-DAT not found" >&2; exit 1; }

echo "== compute digest(original) =="
"$ROOT/target/debug/digest" "$OUTDIR/sample.eml" > "$OUTDIR/digest.json"
echo "digest(original): $(cat "$OUTDIR/digest.json")"
echo

python3 - <<PY >"$OUTDIR/verify_req.json"
import json
from pathlib import Path
d=json.loads(Path("$OUTDIR/digest.json").read_text())
print(json.dumps({"dat_jws": "$DAT_JWS", "msg_digest_b64": d["msg_digest_b64"]}, separators=(",",":")))
PY

echo "== verify =="
VERIFY_URL="http://127.0.0.1:${PORT}/zk-ack/v1/verify"
code="$(curl -sS -o "$OUTDIR/verify.json" -w '%{http_code}' \
  -H 'content-type: application/json' --data-binary @"$OUTDIR/verify_req.json" \
  "$VERIFY_URL" || true)"
echo "http: $code"
cat "$OUTDIR/verify.json" || true
echo

if [[ "$code" != "200" ]]; then
  echo "FAILED verify (show verifier log tail):"
  tail -n 80 "$VERIFIER_LOG" || true
  echo
  echo "OUTDIR artifacts: $OUTDIR"
  exit 1
fi

python3 - <<PY
import json
v=json.load(open("$OUTDIR/verify.json"))
dm=v.get("digest_match")
print("digest_match:", dm)
if dm is not True:
    raise SystemExit(2)
PY

echo
echo "OK ✅ demo passed. Artifacts:"
echo "  $OUTDIR"
