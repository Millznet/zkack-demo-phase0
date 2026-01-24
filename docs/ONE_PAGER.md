# ZK-ACK — Verified Notice Gateway (v0)

ZK-ACK is deployable tooling that lets an org send “certified notices” over normal email while providing:
- Authenticity (issuer-signed DAT)
- Tamper-evident binding (digest-match verification)
- Audit trail (receipts in controlled environments)

It does NOT promise inbox placement, provider delivery guarantees, or human-read semantics.

Buyers (v0): govtech/notice vendors, enterprise compliance teams, agencies via integrators.

Deployment modes:
- Mode A: Outbound signing (fastest sell)
- Mode B: Inbound verification (controlled lanes)
- Mode C: Citizen verification portal
