# Architecture (v0)

Components:
- zkack-signer (CLI): injects X-ZK-DAT JWS into RFC5322 .eml
- zkack-verifier (Axum): /verify + /ack + /receipts + /healthz
- zkack-watcher (CLI): posts ACK from .eml (proof mocked)
- zkack-spec: shared types/JWS/hash + digest helper tool
- zkack-circuits: proof interface + mock implementation

Config (verifier):
- ZKACK_PORT (default 8787)
- ZKACK_DB_PATH (DB location; demo uses unique per run)
