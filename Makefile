BINARY_NAME = target/debug/monolith

.PHONY: e2e
e2e: stop run test stop

.PHONY: test
test: build
	cargo test --test e2e

.PHONY: stop
run: build
	./${BINARY_NAME} tests/tcp.ron &
	./${BINARY_NAME} tests/http.ron &
	./${BINARY_NAME} tests/grpc.ron &

.PHONY: stop
stop:
	pkill -f ${BINARY_NAME} || true

build: ${BINARY_NAME} $(wildcard src/*.rs) Cargo.*
	cargo build --all-targets
