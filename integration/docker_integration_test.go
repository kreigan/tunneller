//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshtun-docker/internal/config"
	"sshtun-docker/internal/manager"
)

// TestDockerIntegrationScenarios validates the tunnel manager against real
// containers: a direct forwarding scenario, corner cases (port collisions,
// closed connections during an outage), and failure/recovery emulation
// (bad credentials, SSH host outage and recovery).
func TestDockerIntegrationScenarios(t *testing.T) {
	ctx := context.Background()

	t.Run("direct_success", func(t *testing.T) {
		nw := newTestNetwork(t, ctx)
		keyPath, authKey := generateKeyPair(t)
		sshdCtr := startSSHD(t, ctx, nw, authKey)
		startTarget(t, ctx, nw, "target", "hello-direct")

		host, port := sshdEndpoint(t, ctx, sshdCtr)
		localPort := freePort(t)

		cfg := baseConfig(host, port, keyPath, []config.Tunnel{
			{LocalIP: "127.0.0.1", LocalPort: localPort, TargetHost: "target", TargetPort: 8080},
		}, filepath.Join(t.TempDir(), "health"))

		mgr, exitCode, cancel, _ := runManager(t, cfg)

		if err := waitHealthy(t, mgr, 30*time.Second); err != nil {
			t.Fatalf("waiting for manager to become healthy: %v", err)
		}

		body, err := httpGetBody(t, fmt.Sprintf("127.0.0.1:%d", localPort), 10*time.Second)
		if err != nil {
			t.Fatalf("fetch through tunnel: %v", err)
		}
		if body != "hello-direct" {
			t.Fatalf("unexpected body: got %q, want %q", body, "hello-direct")
		}

		cancel()
		select {
		case code := <-exitCode:
			if code != 0 {
				t.Fatalf("expected exit code 0 after cancel, got %d", code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("manager did not exit after context cancel")
		}

		state, err := mgr.HealthStore().Read()
		if err != nil {
			t.Fatalf("read health file: %v", err)
		}
		if state != manager.HealthStopped {
			t.Fatalf("expected health state %q after shutdown, got %q", manager.HealthStopped, state)
		}
	})

	t.Run("multiple_tunnels_success", func(t *testing.T) {
		nw := newTestNetwork(t, ctx)
		keyPath, authKey := generateKeyPair(t)
		sshdCtr := startSSHD(t, ctx, nw, authKey)
		startTarget(t, ctx, nw, "target-a", "hello-a")
		startTarget(t, ctx, nw, "target-b", "hello-b")

		host, port := sshdEndpoint(t, ctx, sshdCtr)
		localPortA := freePort(t)
		localPortB := freePort(t)

		cfg := baseConfig(host, port, keyPath, []config.Tunnel{
			{LocalIP: "127.0.0.1", LocalPort: localPortA, TargetHost: "target-a", TargetPort: 8080},
			{LocalIP: "127.0.0.1", LocalPort: localPortB, TargetHost: "target-b", TargetPort: 8080},
		}, filepath.Join(t.TempDir(), "health"))

		mgr, exitCode, cancel, _ := runManager(t, cfg)

		if err := waitHealthy(t, mgr, 30*time.Second); err != nil {
			t.Fatalf("waiting for manager to become healthy: %v", err)
		}

		bodyA, err := httpGetBody(t, fmt.Sprintf("127.0.0.1:%d", localPortA), 10*time.Second)
		if err != nil {
			t.Fatalf("fetch tunnel A: %v", err)
		}
		if bodyA != "hello-a" {
			t.Fatalf("tunnel A: got %q, want %q", bodyA, "hello-a")
		}

		bodyB, err := httpGetBody(t, fmt.Sprintf("127.0.0.1:%d", localPortB), 10*time.Second)
		if err != nil {
			t.Fatalf("fetch tunnel B: %v", err)
		}
		if bodyB != "hello-b" {
			t.Fatalf("tunnel B: got %q, want %q", bodyB, "hello-b")
		}

		cancel()
		select {
		case code := <-exitCode:
			if code != 0 {
				t.Fatalf("expected exit code 0 after cancel, got %d", code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("manager did not exit after context cancel")
		}
	})

	t.Run("bind_collision_exits_110", func(t *testing.T) {
		nw := newTestNetwork(t, ctx)
		keyPath, authKey := generateKeyPair(t)
		sshdCtr := startSSHD(t, ctx, nw, authKey)
		startTarget(t, ctx, nw, "target", "hello-collision")

		host, port := sshdEndpoint(t, ctx, sshdCtr)
		localPort := freePort(t)

		// Occupy the local port outside of the manager, simulating a real
		// port collision (e.g. another process already bound to it).
		blocker, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err != nil {
			t.Fatalf("occupy local port: %v", err)
		}
		defer func() { _ = blocker.Close() }()

		cfg := baseConfig(host, port, keyPath, []config.Tunnel{
			{LocalIP: "127.0.0.1", LocalPort: localPort, TargetHost: "target", TargetPort: 8080},
		}, filepath.Join(t.TempDir(), "health"))

		_, exitCode, _, logs := runManager(t, cfg)

		select {
		case code := <-exitCode:
			if code != manager.ExitCodeLocalPortInUse {
				t.Fatalf("expected exit code %d, got %d", manager.ExitCodeLocalPortInUse, code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("manager did not exit after port collision")
		}

		logOutput := logs.String()
		const targetAddr = "target:8080"
		localAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
		if !strings.Contains(logOutput, targetAddr) || !strings.Contains(logOutput, localAddr) {
			t.Fatalf("expected bind error to mention target %q and local %q, got log: %s", targetAddr, localAddr, logOutput)
		}
	})

	t.Run("auth_failure_exits_105", func(t *testing.T) {
		nw := newTestNetwork(t, ctx)
		_, authKey := generateKeyPair(t)
		sshdCtr := startSSHD(t, ctx, nw, authKey)
		startTarget(t, ctx, nw, "target", "hello-auth")

		host, port := sshdEndpoint(t, ctx, sshdCtr)
		localPort := freePort(t)

		// Use a different, unauthorized key pair to dial the server.
		wrongKeyPath, _ := generateKeyPair(t)

		cfg := baseConfig(host, port, wrongKeyPath, []config.Tunnel{
			{LocalIP: "127.0.0.1", LocalPort: localPort, TargetHost: "target", TargetPort: 8080},
		}, filepath.Join(t.TempDir(), "health"))

		mgr, exitCode, _, _ := runManager(t, cfg)

		select {
		case code := <-exitCode:
			if code != manager.ExitCodeAuthFailure {
				t.Fatalf("expected exit code %d, got %d", manager.ExitCodeAuthFailure, code)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("manager did not exit after auth failure")
		}

		if err := waitUnhealthyContains(t, mgr, "authentication failure", time.Second); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("reconnect_after_outage", func(t *testing.T) {
		nw := newTestNetwork(t, ctx)
		keyPath, authKey := generateKeyPair(t)
		sshdCtr := startSSHD(t, ctx, nw, authKey)
		startTarget(t, ctx, nw, "target", "hello-recover")

		host, port := sshdEndpoint(t, ctx, sshdCtr)
		localPort := freePort(t)

		cfg := baseConfig(host, port, keyPath, []config.Tunnel{
			{LocalIP: "127.0.0.1", LocalPort: localPort, TargetHost: "target", TargetPort: 8080},
		}, filepath.Join(t.TempDir(), "health"))
		cfg.ConnectionCheckInterval = 200 * time.Millisecond
		cfg.HealthcheckProbeInterval = 200 * time.Millisecond
		cfg.ConnectTimeout = 1 * time.Second

		mgr, exitCode, cancel, _ := runManager(t, cfg)

		if err := waitHealthy(t, mgr, 30*time.Second); err != nil {
			t.Fatalf("waiting for initial healthy state: %v", err)
		}
		if _, err := httpGetBody(t, fmt.Sprintf("127.0.0.1:%d", localPort), 10*time.Second); err != nil {
			t.Fatalf("fetch through tunnel before outage: %v", err)
		}

		if err := sshdCtr.Stop(ctx, nil); err != nil {
			t.Fatalf("stop sshd container: %v", err)
		}

		if err := waitUnhealthyContains(t, mgr, "unreachable", 15*time.Second); err != nil {
			t.Fatal(err)
		}

		if err := sshdCtr.Start(ctx); err != nil {
			t.Fatalf("restart sshd container: %v", err)
		}

		if err := waitHealthy(t, mgr, 30*time.Second); err != nil {
			t.Fatalf("waiting for manager to recover: %v", err)
		}
		if _, err := httpGetBody(t, fmt.Sprintf("127.0.0.1:%d", localPort), 10*time.Second); err != nil {
			t.Fatalf("fetch through tunnel after recovery: %v", err)
		}

		cancel()
		select {
		case code := <-exitCode:
			if code != 0 {
				t.Fatalf("expected exit code 0 after cancel, got %d", code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("manager did not exit after context cancel")
		}
	})

	t.Run("local_connection_closed_while_ssh_down", func(t *testing.T) {
		nw := newTestNetwork(t, ctx)
		keyPath, authKey := generateKeyPair(t)
		sshdCtr := startSSHD(t, ctx, nw, authKey)
		startTarget(t, ctx, nw, "target", "hello-outage")

		host, port := sshdEndpoint(t, ctx, sshdCtr)
		localPort := freePort(t)

		cfg := baseConfig(host, port, keyPath, []config.Tunnel{
			{LocalIP: "127.0.0.1", LocalPort: localPort, TargetHost: "target", TargetPort: 8080},
		}, filepath.Join(t.TempDir(), "health"))
		cfg.ConnectionCheckInterval = 200 * time.Millisecond
		cfg.HealthcheckProbeInterval = 200 * time.Millisecond
		cfg.ConnectTimeout = 1 * time.Second

		mgr, _, cancel, _ := runManager(t, cfg)
		defer cancel()

		if err := waitHealthy(t, mgr, 30*time.Second); err != nil {
			t.Fatalf("waiting for initial healthy state: %v", err)
		}

		if err := sshdCtr.Stop(ctx, nil); err != nil {
			t.Fatalf("stop sshd container: %v", err)
		}
		if err := waitUnhealthyContains(t, mgr, "unreachable", 15*time.Second); err != nil {
			t.Fatal(err)
		}

		// New local connections should be closed promptly (not hang) while
		// no ssh connection is available.
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 2*time.Second)
		if err != nil {
			t.Fatalf("dial local tunnel port: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1)
		n, readErr := conn.Read(buf)
		if readErr == nil {
			t.Fatalf("expected connection to be closed by manager, got %d bytes with no error", n)
		}

		if err := sshdCtr.Start(ctx); err != nil {
			t.Fatalf("restart sshd container: %v", err)
		}
	})
}
