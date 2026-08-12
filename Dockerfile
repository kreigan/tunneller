FROM golang:1.26.5-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/tunnel-manager ./cmd/tunnel-manager

FROM alpine:3.24

RUN apk add --no-cache ca-certificates

ARG USER=appuser

RUN adduser -D -u 1000 -h /home/$USER $USER \
    && mkdir -p /home/$USER/.ssh /tmp \
    && chmod 1777 /tmp \
    && chown -R $USER:$USER /home/$USER

COPY --from=builder --chmod=0755 /out/tunnel-manager /usr/local/bin/tunnel-manager

ENV HOME=/home/$USER
ENV SSH_KEY_FILE=/home/$USER/.ssh/id
ENV SSH_AUTH_SOCK=/home/$USER/.ssh/agent.sock

USER $USER

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/tunnel-manager", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/tunnel-manager"]
