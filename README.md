# ZK-ACK (Phase 0) — Public Proof Snapshot

A minimal, runnable proof-of-concept for **verifiable “certified notices” sent over normal email**.

This repo is intentionally small and safe to publish (no private repo history, no secrets). It’s meant for **portfolio links** and **early pilot conversations**.

---

## What it is (plain English)

**ZK-ACK** adds a cryptographic verification layer on top of ordinary email workflows.

A sender can produce a **signed, tamper-evident proof** of what was sent, and a receiver (or auditor) can later **verify authenticity and integrity** using the proof + a digest of the message.

This Phase 0 demo demonstrates:

- **Signing:** generate a proof for an email-like message (`.eml`)
- **Tamper detection:** modifying content breaks verification
- **Verification API:** a local verifier service confirms `ok` + `digest_match`

> ZK-ACK does **not** guarantee inbox delivery. It guarantees **authenticity** and **tamper-evident binding**.

---

## Why it matters (use cases)

- **Compliance / audit:** prove what notice was sent (and that it wasn’t altered)
- **Dispute resolution:** independently verify contents after the fact
- **Secure workflows:** add verification without replacing existing email systems
- **Archival evidence:** store verifiable artifacts for later review

---

## Quick start (runnable demo)

### Prereqs
- Rust toolchain installed (`cargo` available)

### Run
```bash
bash ./demo.sh
