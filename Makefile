VERSION ?= dev
LDFLAGS := -s -w -X github.com/txchen/yunmen/internal/version.Version=$(VERSION)

.PHONY: web build test e2e image clean

web:
	cd web && npm ci && npm run build

build: web
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/yunmen-server ./cmd/yunmen-server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/yunmen ./cmd/yunmen

test:
	go vet ./...
	go test ./...
	cd web && npm test

e2e:
	WEB=1 scripts/e2e-pty.sh

image:
	docker build --build-arg VERSION=$(VERSION) -t yunmen:$(VERSION) .

clean:
	rm -rf dist
