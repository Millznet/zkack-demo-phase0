# ZK-ACK (Phase 0) — Public Proof Snapshot

> **What this is:** A minimal, safe, publishable proof snapshot (docs + demo walkthrough).
> **What this is NOT:** The full private repo or production deployment.

## What you can review quickly
- **One-pager:** `docs/ONE_PAGER.md`
- **Threat model:** `docs/THREAT_MODEL.md`
- **Protocol overview:** `docs/PROTOCOL.md`
- **Architecture:** `docs/ARCHITECTURE.md`
- **Operations notes:** `docs/OPERATIONS.md`
- **Demo walkthrough:** `docs/DEMO.md`

## Demo (walkthrough)
Follow the steps in `docs/DEMO.md`.

### Optional runnable bits detected
This snapshot also includes:
- `demo.sh`
- `Makefile`
- `Cargo.toml`

If `demo.sh` exists, try:
```bash
bash ./demo.sh
```

## Safety
- No private keys are included in this snapshot.
- Any API keys mentioned in docs are examples only.

ZK-ACK provides cryptographic verification + an audit trail for “certified notices” sent over normal email.
It does NOT promise inbox placement; it promises authenticity and tamper-evident binding.

Quickstart:
  cd zkack
  ./demo.sh

Artifacts:
  /tmp/zkack_demo_<timestamp>/

Docs: see docs/