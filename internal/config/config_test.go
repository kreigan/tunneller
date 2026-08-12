package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseTunnelsIgnoresCommentsAndBlankLines(t *testing.T) {
	raw := "\n# first tunnel\n127.0.0.1:15432:db.internal:5432\n\n# second\n0.0.0.0:18080:api.internal:8080\n"
	tunnels, err := ParseTunnels(raw)
	if err != nil {
		t.Fatalf("ParseTunnels() error = %v", err)
	}
	if len(tunnels) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(tunnels))
	}
	if tunnels[0].LocalAddress() != "127.0.0.1:15432" || tunnels[0].TargetAddress() != "db.internal:5432" {
		t.Fatalf("unexpected first tunnel: %+v", tunnels[0])
	}
	if tunnels[1].LocalAddress() != "0.0.0.0:18080" || tunnels[1].TargetAddress() != "api.internal:8080" {
		t.Fatalf("unexpected second tunnel: %+v", tunnels[1])
	}
}

func TestParseTunnelsRejectsMalformedLine(t *testing.T) {
	raw := "127.0.0.1:15432:db.internal\n"
	_, err := ParseTunnels(raw)
	if err == nil {
		t.Fatal("expected error for malformed tunnel line")
	}
}

func TestNewViperBindsEnvDefaults(t *testing.T) {
	setEnv(t, "SSH_HOST", "ssh.example")
	setEnv(t, "SSH_USER", "alice")
	setEnv(t, "SSH_PORT", "2200")
	setEnv(t, "VERBOSE", "true")

	v := newViper()

	if got := v.GetString("ssh.host"); got != "ssh.example" {
		t.Fatalf("expected ssh.host from env, got %q", got)
	}
	if got := v.GetString("ssh.user"); got != "alice" {
		t.Fatalf("expected ssh.user from env, got %q", got)
	}
	if got := v.GetInt("ssh.port"); got != 2200 {
		t.Fatalf("expected ssh.port from env, got %d", got)
	}
	if got := v.GetBool("verbose"); !got {
		t.Fatal("expected verbose from env to be true")
	}
}

func TestLoadFromEnvMissingRequiredFails(t *testing.T) {
	setEnv(t, "SSH_HOST", "")
	setEnv(t, "SSH_USER", "")
	setEnv(t, "SSH_AUTH_METHOD", "")
	setEnv(t, "TUNNELS", "127.0.0.1:10000:localhost:22")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected config validation error")
	}
}

func TestLoadFromEnvReadsConfigFileFallback(t *testing.T) {
	tempDir := t.TempDir()
	cfgFile := filepath.Join(tempDir, "config.conf")
	if err := os.WriteFile(cfgFile, []byte("127.0.0.1:10000:localhost:22\n"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	setEnv(t, "SSH_HOST", "ssh.example")
	setEnv(t, "SSH_USER", "alice")
	setEnv(t, "SSH_AUTH_METHOD", "key")
	setEnv(t, "SSH_KEY_FILE", "/tmp/key")
	setEnv(t, "TUNNELS", "")
	setEnv(t, "CONFIG_FILE", cfgFile)

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if len(cfg.Tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(cfg.Tunnels))
	}
}

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	oldValue, hadValue := os.LookupEnv(key)
	if value == "" {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("Unsetenv(%s): %v", key, err)
		}
	} else if err := os.Setenv(key, value); err != nil {
		t.Fatalf("Setenv(%s): %v", key, err)
	}

	t.Cleanup(func() {
		if !hadValue {
			_ = os.Unsetenv(key)
			return
		}
		_ = os.Setenv(key, oldValue)
	})
}
