issuer:
	CGO_ENABLED=0 go build -o bin/issuer ./cmd/issuer

new-certs: issuer
	mkdir -p certs/server
	mkdir -p certs/client
	./bin/issuer new

rotate-ca: issuer
	./bin/issuer rotate-ca

rotate-server: issuer
	./bin/issuer rotate-server

rotate-client: issuer
	./bin/issuer rotate-client

server:
	CGO_ENABLED=0 go build -o bin/server ./cmd/server

run-server: server
	./bin/server \
		--ca-bundle certs/ca-bundle.crt \
		--certificate certs/server/tls.crt \
		--key certs/server/tls.key \
		--port 8443
.PHONY: run-server

client:
	CGO_ENABLED=0 go build -o bin/client ./cmd/client
.PHONY: client

run-client: client
	./bin/client \
		--server-address https://localhost:8443/ping \
		--server-name mtls-server.zarvd.dev \
		--ca-bundle certs/ca-bundle.crt \
		--certificate certs/client/tls.crt \
		--key certs/client/tls.key
.PHONY: run-client

SERVER_IMG ?= ghcr.io/zarvd/mtls-demo/server:v0.0.1
image-server:
	docker build \
		--no-cache \
		--platform linux/amd64 \
		--tag $(SERVER_IMG) \
		--file docker/server.Dockerfile .
.PHONY: image-server

CLIENT_IMG ?= ghcr.io/zarvd/mtls-demo/client:v0.0.1
image-client:
	docker build \
		--no-cache \
		--platform linux/amd64 \
		--tag $(CLIENT_IMG) \
		--file docker/client.Dockerfile .
.PHONY: image-client
