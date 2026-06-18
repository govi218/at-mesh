# Build stage
FROM golang:1.24-bookworm AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=1 go build -ldflags "-X main.Version=${VERSION}" -o /at-mesh ./cmd/at-mesh

# Run stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends dumb-init && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r atmesh && useradd -r -g atmesh -d /home/atmesh -s /sbin/nologin atmesh

COPY --from=builder /at-mesh /usr/local/bin/at-mesh

RUN mkdir -p /data/keys && chown -R atmesh:atmesh /data

USER atmesh

WORKDIR /data

EXPOSE 9090

ENTRYPOINT ["dumb-init", "--"]
CMD ["at-mesh", "run"]
