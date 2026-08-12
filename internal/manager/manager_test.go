package manager

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kreigan/tunneller/internal/config"

	"golang.org/x/crypto/ssh"
)

func baseConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		SSHHost:                  "ssh.example",
		SSHPort:                  22,
		SSHUser:                  "user",
		SSHAuthMethod:            config.AuthMethodKey,
		SSHKeyFile:               "/tmp/key",
		Tunnels:                  []config.Tunnel{{LocalIP: "127.0.0.1", LocalPort: 20000, TargetHost: "db", TargetPort: 5432}},
		TunnelMaxRetries:         3,
		ConnectionCheckInterval:  time.Millisecond,
		HealthcheckProbeInterval: 24 * time.Hour,
		ConnectTimeout:           time.Second,
		TCPKeepalive:             time.Second,
		HealthFile:               filepath.Join(t.TempDir(), "health"),
	}
}

func TestManagerRunPortInUseReturns110(t *testing.T) {
	cfg := baseConfig(t)
	mgr := New(cfg, &ssh.ClientConfig{}, log.New(os.Stdout, "", 0))
	mgr.listenFn = func(string, string) (net.Listener, error) {
		return nil, syscall.EADDRINUSE
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	code := mgr.Run(ctx)
	if code != ExitCodeLocalPortInUse {
		t.Fatalf("expected code %d, got %d", ExitCodeLocalPortInUse, code)
	}
}
