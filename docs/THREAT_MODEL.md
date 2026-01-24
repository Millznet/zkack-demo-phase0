# Threat Model (v0)

Proves:
- DAT was issued by trusted key (kid)
- Tamper-evidence via digest match (given correct bytes/canonical form)
- Receipts/audit trail in controlled environments

Does NOT prove:
- Inbox placement, provider delivery, or human read
- Universal semantics across provider rewriting (Phase 1+)

Planned mitigations:
- Replay/abuse: nonce windows, idempotency, rate limits
- Key compromise: rotation + revocation
- Receipt forgery: mTLS or receiver signing
