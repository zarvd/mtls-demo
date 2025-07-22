ARG GO_VERSION=1.24.5
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /workspace
COPY . .
RUN apt update && apt install make -y

RUN CGO_ENABLED=0 go build -o bin/client ./cmd/client

FROM gcr.io/distroless/static-debian12:debug

COPY --from=builder /workspace/bin/client /usr/local/bin/mtls-client

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/mtls-client"]
