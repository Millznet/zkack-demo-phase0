# Demo

Run:
  ./demo.sh

Expected highlights:
- verify(original) ✅ digest_match=true
- verify(tampered) ✅ digest_match=false
- ACK ingest success + receipts export

Artifacts are saved under /tmp/zkack_demo_<timestamp>/.
