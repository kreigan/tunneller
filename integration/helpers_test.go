//go:build integration

// Package integration contains Testcontainers-based end-to-end tests for the
// tunnel manager. These tests spin up real containers (an OpenSSH server and
// plain HTTP targets) and exercise the production manager code against them,
// including simulated outages and recovery.
//
// Run with: go test -tags=integration ./integration/...
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sshtun-docker/internal/config"
	"sshtun-docker/internal/manager"
	"sshtun-docker/internal/sshauth"

	"golang.org/x/crypto/ssh"

	"github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const sshUser = "tester"

// generateKeyPair creates an ephemeral ed25519 key pair for a test, writing
// the private key to a file (as required by config.SSHKeyFile) and returning
// the OpenSSH "authorized_keys" formatted public key.
func generateKeyPair(t *testing.T) (privateKeyPath string, authorizedKey []byte) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	path := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	return path, ssh.MarshalAuthorizedKey(signer.PublicKey())
}

// freePort returns a currently-unused local TCP port.
func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer func() { _ = ln.Close() }()

	return ln.Addr().(*net.TCPAddr).Port
}

// newTestNetwork creates a throw-away Docker network shared by the sshd and
// target fixtures, so the sshd container can reach the target containers by
// their network alias.
func newTestNetwork(t *testing.T, ctx context.Context) *testcontainers.DockerNetwork {
	t.Helper()

	nw, err := tcnetwork.New(ctx)
	if err != nil {
		t.Fatalf("create docker network: %v", err)
	}
	t.Cleanup(func() {
		if err := nw.Remove(context.Background()); err != nil {
			t.Logf("warning: failed to remove network: %v", err)
		}
	})

	return nw
}

// startSSHD builds and starts the fixture OpenSSH server, trusting the given
// authorized key for the "tester" user. It returns the running container plus
// a function that resolves the current host/port the server is reachable on
// (the port stays stable across Stop/Start of the same container).
func startSSHD(t *testing.T, ctx context.Context, nw *testcontainers.DockerNetwork, authorizedKey []byte) testcontainers.Container {
	t.Helper()

	// Bind a fixed host port instead of letting Docker assign a random one:
	// Docker reassigns a *new* random host port every time a container is
	// stopped and started again, which would silently break tests that
	// resolve the endpoint once and then restart the container to emulate
	// an outage.
	hostPort := freePort(t)
	containerPort := mobynetwork.MustParsePort("22/tcp")

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    "./sshd",
			Dockerfile: "Dockerfile",
		},
		ExposedPorts: []string{"22/tcp"},
		Networks:     []string{nw.Name},
		NetworkAliases: map[string][]string{
			nw.Name: {"sshd"},
		},
		Files: []testcontainers.ContainerFile{
			{
				Reader:            bytes.NewReader(authorizedKey),
				ContainerFilePath: "/home/tester/.ssh/authorized_keys",
				FileMode:          0o600,
			},
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.PortBindings = mobynetwork.PortMap{
				containerPort: []mobynetwork.PortBinding{
					{HostIP: netip.IPv4Unspecified(), HostPort: strconv.Itoa(hostPort)},
				},
			}
		},
		WaitingFor: wait.ForListeningPort("22/tcp").WithStartupTimeout(60 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start sshd container: %v", err)
	}
	t.Cleanup(func() {
		if err := ctr.Terminate(context.Background()); err != nil {
			t.Logf("warning: failed to terminate sshd container: %v", err)
		}
	})

	// testcontainers copies Files into the container as root, but sshd opens
	// authorized_keys with the target user's privileges, so a root-owned file
	// is rejected with "Permission denied". Fix ownership after the copy.
	if exitCode, _, err := ctr.Exec(ctx, []string{"chown", "tester:tester", "/home/tester/.ssh/authorized_keys"}); err != nil || exitCode != 0 {
		t.Fatalf("chown authorized_keys: exitCode=%d err=%v", exitCode, err)
	}

	return ctr
}

// sshdEndpoint resolves the current host and mapped port for a running sshd
// container. Must be called while the container is running.
func sshdEndpoint(t *testing.T, ctx context.Context, ctr testcontainers.Container) (string, int) {
	t.Helper()

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("resolve sshd host: %v", err)
	}
	mapped, err := ctr.MappedPort(ctx, "22")
	if err != nil {
		t.Fatalf("resolve sshd mapped port: %v", err)
	}

	return host, int(mapped.Num())
}

// startTarget builds and starts a fixture HTTP target reachable from the sshd
// container by the given network alias, serving the given content on "/".
func startTarget(t *testing.T, ctx context.Context, nw *testcontainers.DockerNetwork, alias, content string) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    "./target",
			Dockerfile: "Dockerfile",
		},
		Env: map[string]string{
			"CONTENT": content,
		},
		ExposedPorts: []string{"8080/tcp"},
		Networks:     []string{nw.Name},
		NetworkAliases: map[string][]string{
			nw.Name: {alias},
		},
		WaitingFor: wait.ForHTTP("/").WithPort("8080/tcp").WithStartupTimeout(60 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start target container %q: %v", alias, err)
	}
	t.Cleanup(func() {
		if err := ctr.Terminate(context.Background()); err != nil {
			t.Logf("warning: failed to terminate target container %q: %v", alias, err)
		}
	})
}

// runManager builds the ssh.ClientConfig for cfg and starts a manager.Manager
// against it in the background, returning the manager, a channel receiving
// its exit code, and a cancel function to stop it.
func runManager(t *testing.T, cfg config.Config) (mgr *manager.Manager, exitCode <-chan int, cancel func(), logs *bytes.Buffer) {
	t.Helper()

	sshCfg, closeAuth, err := sshauth.BuildClientConfig(cfg)
	if err != nil {
		t.Fatalf("build ssh client config: %v", err)
	}
	t.Cleanup(closeAuth)

	var buf bytes.Buffer
	logger := log.New(io.MultiWriter(&buf, os.Stdout), "["+t.Name()+"] ", log.LstdFlags)

	mgr = manager.New(cfg, sshCfg, logger)

	ctx, cancelFn := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- mgr.Run(ctx)
	}()

	t.Cleanup(cancelFn)

	return mgr, done, cancelFn, &buf
}

// waitHealthy polls the manager's health store until it reports healthy or
// the timeout elapses.
func waitHealthy(t *testing.T, mgr *manager.Manager, timeout time.Duration) error {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		healthy, err := mgr.HealthStore().IsHealthy()
		if err == nil && healthy {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	state, _ := mgr.HealthStore().Read()
	return fmt.Errorf("manager did not become healthy within %s (last state: %q)", timeout, state)
}

// waitUnhealthyContains polls the manager's health store until its state
// contains the given substring or the timeout elapses.
func waitUnhealthyContains(t *testing.T, mgr *manager.Manager, substr string, timeout time.Duration) error {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := mgr.HealthStore().Read()
		if err == nil && strings.Contains(strings.ToLower(state), strings.ToLower(substr)) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	state, _ := mgr.HealthStore().Read()
	return fmt.Errorf("manager health state did not contain %q within %s (last state: %q)", substr, timeout, state)
}

// baseConfig builds a Config pointed at the given SSH endpoint and tunnels,
// using short intervals suitable for fast test feedback.
func baseConfig(sshHost string, sshPort int, keyFile string, tunnels []config.Tunnel, healthFile string) config.Config {
	return config.Config{
		SSHHost:                  sshHost,
		SSHPort:                  sshPort,
		SSHUser:                  sshUser,
		SSHAuthMethod:            config.AuthMethodKey,
		SSHKeyFile:               keyFile,
		Tunnels:                  tunnels,
		TunnelMaxRetries:         5,
		ConnectionCheckInterval:  300 * time.Millisecond,
		HealthcheckProbeInterval: 300 * time.Millisecond,
		ConnectTimeout:           5 * time.Second,
		TCPKeepalive:             30 * time.Second,
		HealthFile:               healthFile,
	}
}

// httpGetBody performs HTTP GETs against the given local address until one
// succeeds and returns a body, or the timeout elapses.
func httpGetBody(t *testing.T, addr string, timeout time.Duration) (string, error) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)

	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/")
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return string(body), nil
	}

	return "", fmt.Errorf("http get %s did not succeed within %s: %w", addr, timeout, lastErr)
}
