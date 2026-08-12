# tunnel-manager

A small Go-based SSH tunnel manager designed to run in Docker. It opens one or more
persistent local-port-forward tunnels through a single shared SSH connection, monitors
connection health, and automatically recovers from transient outages.

It uses native Go SSH libraries (`golang.org/x/crypto/ssh` and
`golang.org/x/crypto/ssh/agent`) and does not shell out to OpenSSH binaries.

## Features

- One shared SSH connection per container, multiplexed across all configured tunnels.
- Long-lived listeners: local ports are bound once at startup and remain open.
- Explicit auth selection: SSH private key or mounted SSH agent socket.
- Health and recovery state machine with typed failure handling and unique exit codes.
- Docker `HEALTHCHECK` support through the same binary (`-healthcheck` flag).
- Structured stdout logging with timestamps for lifecycle and failure events.

## Tunnel Configuration Format

The `TUNNELS` environment variable is a newline-separated list:

```text
local_ip:local_port:target_host:target_port
```

Examples:

```text
0.0.0.0:15432:db.internal:5432
127.0.0.1:18080:api.internal:8080
```

Rules:

- Blank lines are ignored.
- Lines starting with `#` are ignored.
- Exactly 4 colon-separated fields are required per tunnel line.

If `TUNNELS` is unset, the manager falls back to `CONFIG_FILE` and reads the same format.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SSH_HOST` | _(required)_ | SSH host to connect to |
| `SSH_PORT` | `22` | SSH port |
| `SSH_USER` | _(required)_ | SSH username |
| `SSH_AUTH_METHOD` | `key` | `key` or `agent` |
| `SSH_KEY_FILE` | `/home/appuser/.ssh/id` | Path to private key file (used when `SSH_AUTH_METHOD=key`) |
| `SSH_AUTH_SOCK` | _(unset)_ | Path to mounted SSH agent socket inside the container (used when `SSH_AUTH_METHOD=agent`) |
| `TUNNELS` | _(required, unless `CONFIG_FILE` used)_ | Newline-separated list of tunnels: `local_ip:local_port:target_host:target_port` |
| `CONFIG_FILE` | `/tmp/config.conf` | Optional file fallback for tunnel config, same format as `TUNNELS`, used only if `TUNNELS` is unset |
| `TUNNEL_MAX_RETRIES` | `3` | Max reconnect attempts for the shared SSH connection before giving up. `-1` = retry forever |
| `CONNECTION_CHECK_INTERVAL` | `5` | Seconds between reachability probes while host is unreachable, and between reconnect attempts |
| `HEALTHCHECK_PROBE_INTERVAL` | `30` | Seconds between SSH keepalive probes used to detect a dead connection |
| `VERBOSE` | _(unset)_ | If set, log extra detail (raw dial attempts, per-accepted-connection open/close) |
| `CONNECT_TIMEOUT` | `10` | Seconds for SSH connect timeout and TCP reachability probe timeout |
| `TCP_KEEPALIVE` | `30` | Reserved typed TCP keepalive tuning value (validated and exposed as config) |
| `HEALTH_FILE` | `/tmp/health` | Health state file path written on status transitions |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean shutdown (SIGTERM/SIGINT) |
| `100` | Invalid/missing configuration |
| `105` | SSH host reachable but authentication/handshake failed |
| `110` | Local tunnel port already in use by another process at startup |
| `115` | Reconnect retries exhausted |

## Health and Recovery

The manager tracks tunnel health based on the shared SSH connection.

1. SSH connection drops or fails to establish.
2. Manager classifies failure by combining dial error type and explicit host reachability probe.
3. Behavior by case:

- Case a: Host unreachable (TCP timeout/refused).
  - Forwarding effectively pauses (listeners stay open but no new SSH channels can be created).
  - Health file transitions to `unhealthy: ssh host unreachable`.
  - Manager probes silently every `CONNECTION_CHECK_INTERVAL` seconds.
  - Once host is reachable, it logs elapsed wait time, reconnects, resumes forwarding, and resets retry counters.

- Case b: Host reachable but SSH auth/handshake fails.
  - Health file records an auth failure reason.
  - Process exits immediately with code `105`.
  - No retry is attempted.

- Case c: Local tunnel port already in use at startup.
  - Listener bind fails during startup.
  - Process exits immediately with code `110`.

- Other transient failures.
  - Reconnect attempts are made every `CONNECTION_CHECK_INTERVAL` seconds.
  - If `TUNNEL_MAX_RETRIES` is exhausted, process exits with code `115`.
  - If `TUNNEL_MAX_RETRIES=-1`, retries continue indefinitely.

## Security Notes

- Host key verification is intentionally disabled via `ssh.InsecureIgnoreHostKey()`.
- This is an explicit tradeoff for trusted private-network/VPN deployments.
- There is no free-form `ssh_config` injection mechanism; this tool uses typed config
  only (timeouts, probe interval, auth method, etc.).

## Build and Run

```bash
go build ./...
```

```bash
docker compose up --build
```

## Healthcheck Mode

The binary supports a healthcheck mode used by Docker:

```bash
tunnel-manager -healthcheck
```

- Exits `0` only when health state starts with `healthy`.
- Exits `1` otherwise.

## Linting and Tests

```bash
go vet ./...
go test ./...
golangci-lint run
```

No integration tests are required. Unit tests use fakes/mocks and avoid real SSH servers,
real network calls, or Docker-based test runs.
