# ZK-ACK (Phase 0) — Public Proof Snapshot
## What it is (in plain English)

ZK-ACK is a small verification layer for “certified notices” sent over normal email.  
It lets a sender produce a **signed, tamper-evident proof** of what was sent, and lets a receiver (or auditor) **verify authenticity and integrity** later.

This Phase 0 demo shows:
- **Signing:** generate a cryptographic proof for an email-like message
- **Tamper detection:** demonstrate that modifying content breaks verification
- **Audit trail:** produce verifiable artifacts you can archive or review

## Why it matters (use cases)
- Compliance/audit: prove what notice was sent and when
- Dispute resolution: verify contents weren’t altered after the fact
- Secure workflows: add verification without replacing existing email systems

> ZK-ACK does **not** guarantee inbox delivery; it guarantees **authenticity and tamper-evident binding**.

## Quick start (demo)

**Prereqs:** Rust toolchain (`cargo`) installed.

Run the Phase 0 demo:

```bash
bash ./demo.sh

