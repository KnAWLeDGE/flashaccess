BINARY      := flashaccess
PKG         := ./cmd/flashaccess
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
PLATFORMS   := linux/amd64 linux/arm64

.PHONY: build install clean release tidy

build: ## Build for the host
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

install: build ## Install to /usr/local/bin (needs sudo)
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

release: tidy ## Cross-compile static binaries + checksums into dist/
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=dist/$(BINARY)_$(VERSION)_$${os}_$${arch}; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags "$(LDFLAGS)" -o $$out $(PKG); \
		( cd dist && sha256sum $$(basename $$out) >> checksums.txt ); \
	done

tidy:
	go mod tidy

clean:
	rm -rf bin dist