issuer:
	CGO_ENABLED=0 go build -o bin/issuer ./cmd/issuer
.PHONY: issuer

generate-certs: issuer
	rm -rf certs
	mkdir certs
	./bin/issuer
.PHONY: generate-certs

server:
	CGO_ENABLED=0 go build -o bin/server ./cmd/server
.PHONY: server

run-server: server
	./bin/server \
		--certificate-authorities certs/ca.crt \
		--key-pairs certs/server.crt:certs/server.key \
		--port 8443
.PHONY: run-server

client:
	CGO_ENABLED=0 go build -o bin/client ./cmd/client
.PHONY: client

run-client: client
	./bin/client \
		--server-address https://localhost:8443/ping \
		--server-name mtls-server.zarvd.dev \
		--certificate-authorities certs/ca.crt \
		--key-pairs certs/client.crt:certs/client.key
.PHONY: run-client

SERVER_IMG=ghcr.io/zarvd/mtls-demo/server:v0.0.1
image-server:
	docker build \
		--no-cache \
		--platform linux/amd64 \
		--tag $(SERVER_IMG) \
		--file docker/server.Dockerfile .
.PHONY: image-server

CLIENT_IMG=ghcr.io/zarvd/mtls-demo/client:v0.0.1
image-client:
	docker build \
		--no-cache \
		--platform linux/amd64 \
		--tag $(CLIENT_IMG) \
		--file docker/client.Dockerfile .
.PHONY: image-client
