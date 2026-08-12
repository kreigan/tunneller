FROM golang:1.26.5-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/tunneller ./cmd/tunneller

FROM alpine:3.24

LABEL org.opencontainers.image.title="tunneller"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="kreigan"
LABEL org.opencontainers.image.source="https://github.com/kreigan/tunneller"

RUN apk add --no-cache ca-certificates

ARG USER=appuser

RUN adduser -D -u 1000 -h /home/$USER $USER \
    && mkdir -p /home/$USER/.ssh /tmp \
    && chmod 1777 /tmp \
    && chown -R $USER:$USER /home/$USER

COPY --from=builder --chmod=0755 /out/tunneller /usr/local/bin/tunneller

ENV HOME=/home/$USER
ENV SSH_KEY_FILE=/home/$USER/.ssh/id
ENV SSH_AUTH_SOCK=/home/$USER/.ssh/agent.sock

USER $USER

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/tunneller", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/tunneller"]
