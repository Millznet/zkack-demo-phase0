# Integrations

Mode A — Outbound signing:
- Generate .eml from your notice system
- Run zkack-signer to inject X-ZK-DAT
- Send normally (SMTP/provider)

Mode C — Citizen portal:
- Extract X-ZK-DAT from .eml
- Call POST /zk-ack/v1/verify
