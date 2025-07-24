all: help

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

issuer: ## Build the issuer binary
	CGO_ENABLED=0 go build -o bin/issuer ./cmd/issuer

server: ## Build the server binary
	CGO_ENABLED=0 go build -o bin/server ./cmd/server

client: ## Build the client binary
	CGO_ENABLED=0 go build -o bin/client ./cmd/client

##@ Development

run-server: server ## Run the server
	./bin/server \
		--ca-bundle certs/ca-bundle.crt \
		--certificate certs/server/tls.crt \
		--key certs/server/tls.key \
		--port 8443

run-client: client ## Run the client
	./bin/client \
		--server-address https://localhost:8443/ping \
		--server-name mtls-server.zarvd.dev \
		--ca-bundle certs/ca-bundle.crt \
		--certificate certs/client/tls.crt \
		--key certs/client/tls.key

new-certs: issuer ## Generate new certificates
	mkdir -p certs/server
	mkdir -p certs/client
	./bin/issuer new

rotate-ca: issuer ## Rotate the CA
	./bin/issuer rotate-ca

rotate-server: issuer ## Rotate the server certificate
	./bin/issuer rotate-server

rotate-client: issuer ## Rotate the client certificate
	./bin/issuer rotate-client

##@ Release

SERVER_IMG ?= ghcr.io/zarvd/mtls-demo/server:v0.0.1
image-server: ## Build the server image
	docker build \
		--no-cache \
		--platform linux/amd64 \
		--tag $(SERVER_IMG) \
		--file docker/server.Dockerfile .

CLIENT_IMG ?= ghcr.io/zarvd/mtls-demo/client:v0.0.1
image-client: ## Build the client image
	docker build \
		--no-cache \
		--platform linux/amd64 \
		--tag $(CLIENT_IMG) \
		--file docker/client.Dockerfile .

##@ Kubernetes

KEY_PAIR_SEQ ?= 0001
new-k8s-ca-key-pair: new-certs ## Generate new CA key pair
	kubectl create secret tls ca-key-pair-$(KEY_PAIR_SEQ) \
		--namespace cert-manager \
		--cert=certs/ca.crt \
		--key=certs/ca.key \
		--dry-run=client -o yaml > k8s/cert-manager/ca-key-pair-$(KEY_PAIR_SEQ)-secret.yaml
