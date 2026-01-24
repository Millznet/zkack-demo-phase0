# Protocol (v0)

DAT is transported as: X-ZK-DAT: <JWS> (Ed25519 JWS).

Digest rules (v0):
- If DKIM bh= exists, use it (digest_alg=dkim-bh)
- Else msg_digest_b64 = blake3(raw_eml_bytes) (digest_alg=blake3)

Known limitation (v0): injecting X-ZK-DAT changes the .eml.
Phase 1 hardens canonicalization so verification can be computed from received mail robustly.

ACK (v0): POST /zk-ack/v1/ack accepts {dat_jws, proof}. Proof is mocked but required non-empty.
