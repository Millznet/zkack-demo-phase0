#!/usr/bin/env bash
set -euo pipefail
set +H

cd "$(dirname "$0")"

TS="$(date +%y%m%d_%H%M%S)"
OUTDIR="/tmp/zkack_demo_${TS}"
mkdir -p "$OUTDIR"

PORT="${ZKACK_PORT:-8787}"
DB_PATH="${ZKACK_DB_PATH:-$OUTDIR/receipts_db}"
VERIFIER_LOG="$OUTDIR/verifier.log"

export RUST_LOG="${RUST_LOG:-info}"
export ZKACK_PORT="$PORT"
export ZKACK_DB_PATH="$DB_PATH"

echo "OUTDIR=$OUTDIR"
echo "PORT=$PORT"
echo "DB_PATH=$DB_PATH"
echo "VERIFIER_LOG=$VERIFIER_LOG"
echo

echo "== build once =="
cargo build -q -p zkack-verifier -p zkack-signer -p zkack-watcher -p zkack-spec
echo "built."
echo

echo "== start verifier =="
( target/debug/zkack-verifier ) >"$VERIFIER_LOG" 2>&1 &
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
cp ./samples/sample.eml "$OUTDIR/sample.eml"
target/debug/zkack-signer \
  --privkey ./keys/dev-priv.json \
  --to you@example.com \
  --from agency@example.gov \
  "$OUTDIR/sample.eml" > "$OUTDIR/signed.eml"
echo "signed: $OUTDIR/signed.eml"
echo

echo "== extract DAT JWS =="
DAT_JWS="$(python3 - <<PY
import email
from email import policy
from pathlib import Path
msg = email.message_from_bytes(Path("$OUTDIR/signed.eml").read_bytes(), policy=policy.default)
print(msg["X-ZK-DAT"] or "")
PY
)"
if [[ -z "$DAT_JWS" ]]; then
  echo "ERROR: X-ZK-DAT not found in signed.eml"
  exit 1
fi

echo "== compute digest(original) using same rules as signer =="
target/debug/digest "$OUTDIR/sample.eml" > "$OUTDIR/digest.json"
echo "digest(original): $(cat "$OUTDIR/digest.json")"
echo

python3 - <<PY >"$OUTDIR/verify_ok_req.json"
import json
from pathlib import Path
d=json.loads(Path("$OUTDIR/digest.json").read_text())
print(json.dumps({"dat_jws": """$DAT_JWS""", "msg_digest_b64": d["msg_digest_b64"]}, separators=(",",":")))
PY

curl -fsS "http://127.0.0.1:${PORT}/zk-ack/v1/verify" \
  -H "content-type: application/json" \
  --data-binary @"$OUTDIR/verify_ok_req.json" | tee "$OUTDIR/verify_ok.json"
echo

python3 - "$OUTDIR/verify_ok.json" <<'PY'
import sys, json
v=json.load(open(sys.argv[1]))
dm=v.get("digest_match")
if dm is not True:
    raise SystemExit(f"expected digest_match true, got {dm}")
print("verify(original) ✅ digest_match=true")
PY
echo

echo "== tamper original + verify should fail =="
python3 - <<PY
from pathlib import Path
p=Path("$OUTDIR/sample.eml")
s=p.read_text(errors="replace")
if "Subject:" in s:
    s = s.replace("Subject:", "Subject: [TAMPERED] ", 1)
else:
    s = s + "\nX-Tampered: 1\n"
Path("$OUTDIR/tampered.eml").write_text(s)
PY

target/debug/digest "$OUTDIR/tampered.eml" > "$OUTDIR/digest_tampered.json"
echo "digest(tampered): $(cat "$OUTDIR/digest_tampered.json")"
echo

python3 - <<PY >"$OUTDIR/verify_bad_req.json"
import json
from pathlib import Path
d=json.loads(Path("$OUTDIR/digest_tampered.json").read_text())
print(json.dumps({"dat_jws": """$DAT_JWS""", "msg_digest_b64": d["msg_digest_b64"]}, separators=(",",":")))
PY

curl -fsS "http://127.0.0.1:${PORT}/zk-ack/v1/verify" \
  -H "content-type: application/json" \
  --data-binary @"$OUTDIR/verify_bad_req.json" | tee "$OUTDIR/verify_bad.json"
echo

python3 - "$OUTDIR/verify_bad.json" <<'PY'
import sys, json
v=json.load(open(sys.argv[1]))
dm=v.get("digest_match")
if dm is not False:
    raise SystemExit(f"expected digest_match false, got {dm}")
print("verify(tampered) ✅ digest_match=false")
PY
echo

echo "== post ACK (watcher) + export receipts =="
target/debug/zkack-watcher \
  --verifier "http://127.0.0.1:${PORT}" \
  --eml "$OUTDIR/signed.eml" | tee "$OUTDIR/watcher.out"
echo
curl -fsS "http://127.0.0.1:${PORT}/zk-ack/v1/receipts" | tee "$OUTDIR/receipts.json"
echo
echo "DONE. Artifacts: $OUTDIR"
