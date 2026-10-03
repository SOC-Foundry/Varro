GO ?= go
BIN := varro

.PHONY: build test run-server run-agent cross clean

build:
	$(GO) build -o $(BIN) ./cmd/varro

test:
	$(GO) test ./...

# Local smoke test: collector on :9477 with a throwaway token.
run-server: build
	./$(BIN) server --token dev-token --db /tmp/varro-dev.db

run-agent: build
	./$(BIN) agent --server http://localhost:9477 --token dev-token --interval 5s

cross:
	GOOS=linux   GOARCH=amd64 $(GO) build -o dist/varro-linux-amd64 ./cmd/varro
	GOOS=linux   GOARCH=arm64 $(GO) build -o dist/varro-linux-arm64 ./cmd/varro
	GOOS=darwin  GOARCH=arm64 $(GO) build -o dist/varro-darwin-arm64 ./cmd/varro
	GOOS=windows GOARCH=amd64 $(GO) build -o dist/varro-windows-amd64.exe ./cmd/varro

clean:
	rm -rf $(BIN) dist
