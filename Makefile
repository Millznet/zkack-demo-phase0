.PHONY: build run-verifier sign ack receipts fmt clippy

build:
	cargo build --workspace

run-verifier:
	ZKACK_PORT?=8787 ; ZKACK_DB_DIR?=./data/receipts ; \
	ZKACK_PORT=$$ZKACK_PORT ZKACK_DB_DIR=$$ZKACK_DB_DIR \
		cargo run -p zkack-verifier --bin zkack-verifier

sign:
	cargo run -p zkack-signer -- --privkey ./keys/dev-priv.json --kid $(KID) \
		--to $(TO) --from $(FROM) ./samples/sample.eml > ./samples/signed.eml

ack:
	cargo run -p zkack-watcher -- --verifier http://127.0.0.1:$(PORT) \
		--eml ./samples/signed.eml

receipts:
	curl -s http://127.0.0.1:$(PORT)/zk-ack/v1/receipts | jq .

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace -- -D warnings
