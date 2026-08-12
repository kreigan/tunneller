/*
Package config loads SSH tunnel configuration from environment variables and config files.
*/
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	// AuthMethodKey enables private-key-based SSH authentication.
	AuthMethodKey = "key"
	// AuthMethodAgent enables ssh-agent-based SSH authentication.
	AuthMethodAgent = "agent"

	// DefaultSSHPort is the default SSH port used when none is configured.
	DefaultSSHPort = 22
	// DefaultConfigFile is the fallback path for tunnel configuration.
	DefaultConfigFile = "/tmp/config.conf"
	// DefaultTunnelMaxRetries is the default reconnect retry budget.
	DefaultTunnelMaxRetries = 3
	// DefaultConnectionCheckSeconds is the default SSH health-check interval.
	DefaultConnectionCheckSeconds = 5
	// DefaultHealthProbeSeconds is the default tunnel health probe interval.
	DefaultHealthProbeSeconds = 30
	// DefaultConnectTimeoutSeconds is the default TCP connect timeout.
	DefaultConnectTimeoutSeconds = 10
	// DefaultTCPKeepaliveSeconds is the default TCP keepalive interval.
	DefaultTCPKeepaliveSeconds = 30
	// DefaultHealthFile is the fallback health status path.
	DefaultHealthFile = "/tmp/health"
)

func defaultSSHKeyFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".ssh", "id")
	}
	return filepath.Join(home, ".ssh", "id")
}

func defaultSSHAuthSock() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".ssh", "agent.sock")
	}
	return filepath.Join(home, ".ssh", "agent.sock")
}

// Tunnel describes a single local-to-remote forwarding rule.
//
//nolint:govet // field ordering is kept intentionally compact for the config schema.
type Tunnel struct {
	LocalPort  int
	TargetPort int
	LocalIP    string
	TargetHost string
}

// LocalAddress returns the local bind address for the tunnel.
func (t Tunnel) LocalAddress() string {
	return fmt.Sprintf("%s:%d", t.LocalIP, t.LocalPort)
}

// TargetAddress returns the remote target address for the tunnel.
func (t Tunnel) TargetAddress() string {
	return fmt.Sprintf("%s:%d", t.TargetHost, t.TargetPort)
}

// Config contains all SSH tunnel settings and runtime parameters.
//
//nolint:govet // this struct keeps runtime values grouped before string metadata for readability.
type Config struct {
	SSHPort                  int
	TunnelMaxRetries         int
	ConnectionCheckInterval  time.Duration
	HealthcheckProbeInterval time.Duration
	ConnectTimeout           time.Duration
	TCPKeepalive             time.Duration
	Verbose                  bool
	SSHHost                  string
	SSHUser                  string
	SSHAuthMethod            string
	SSHKeyFile               string
	SSHAuthSock              string
	Tunnels                  []Tunnel
	ConfigFile               string
	HealthFile               string
}

func newViper() *viper.Viper {
	v := viper.New()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("ssh.host", "")
	v.SetDefault("ssh.port", DefaultSSHPort)
	v.SetDefault("ssh.user", "")
	v.SetDefault("ssh.auth.method", "key")
	v.SetDefault("ssh.key.file", defaultSSHKeyFile())
	v.SetDefault("ssh.auth.sock", defaultSSHAuthSock())
	v.SetDefault("config.file", DefaultConfigFile)
	v.SetDefault("tunnel.max.retries", DefaultTunnelMaxRetries)
	v.SetDefault("connection.check.interval", DefaultConnectionCheckSeconds)
	v.SetDefault("healthcheck.probe.interval", DefaultHealthProbeSeconds)
	v.SetDefault("connect.timeout", DefaultConnectTimeoutSeconds)
	v.SetDefault("tcp.keepalive", DefaultTCPKeepaliveSeconds)
	v.SetDefault("health.file", DefaultHealthFile)
	v.SetDefault("verbose", false)
	v.SetDefault("tunnels", "")

	mustBindEnv(v, "ssh.host", "SSH_HOST")
	mustBindEnv(v, "ssh.port", "SSH_PORT")
	mustBindEnv(v, "ssh.user", "SSH_USER")
	mustBindEnv(v, "ssh.auth.method", "SSH_AUTH_METHOD")
	mustBindEnv(v, "ssh.key.file", "SSH_KEY_FILE")
	mustBindEnv(v, "ssh.auth.sock", "SSH_AUTH_SOCK")
	mustBindEnv(v, "config.file", "CONFIG_FILE")
	mustBindEnv(v, "tunnel.max.retries", "TUNNEL_MAX_RETRIES")
	mustBindEnv(v, "connection.check.interval", "CONNECTION_CHECK_INTERVAL")
	mustBindEnv(v, "healthcheck.probe.interval", "HEALTHCHECK_PROBE_INTERVAL")
	mustBindEnv(v, "connect.timeout", "CONNECT_TIMEOUT")
	mustBindEnv(v, "tcp.keepalive", "TCP_KEEPALIVE")
	mustBindEnv(v, "health.file", "HEALTH_FILE")
	mustBindEnv(v, "verbose", "VERBOSE")
	mustBindEnv(v, "tunnels", "TUNNELS")

	return v
}

func mustBindEnv(v *viper.Viper, key, env string) {
	if err := v.BindEnv(key, env); err != nil {
		panic(fmt.Sprintf("bind env %s=%s: %v", key, env, err))
	}
}

// LoadFromEnv loads a Config from environment variables and config files.
func LoadFromEnv() (Config, error) {
	v := newViper()
	cfg := configFromViper(v)

	if err := applyEnvOverrides(v, &cfg); err != nil {
		return Config{}, err
	}

	tunnelSource := resolveTunnelSource(v, cfg.ConfigFile)
	tunnels, err := ParseTunnels(tunnelSource)
	if err != nil {
		return Config{}, err
	}
	cfg.Tunnels = tunnels

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func configFromViper(v *viper.Viper) Config {
	return Config{
		SSHPort:                  DefaultSSHPort,
		SSHKeyFile:               v.GetString("ssh.key.file"),
		SSHAuthSock:              v.GetString("ssh.auth.sock"),
		ConfigFile:               v.GetString("config.file"),
		TunnelMaxRetries:         v.GetInt("tunnel.max.retries"),
		ConnectionCheckInterval:  time.Duration(v.GetInt("connection.check.interval")) * time.Second,
		HealthcheckProbeInterval: time.Duration(v.GetInt("healthcheck.probe.interval")) * time.Second,
		ConnectTimeout:           time.Duration(v.GetInt("connect.timeout")) * time.Second,
		TCPKeepalive:             time.Duration(v.GetInt("tcp.keepalive")) * time.Second,
		HealthFile:               v.GetString("health.file"),
		Verbose:                  v.GetBool("verbose"),
	}
}

//nolint:gocognit // split by environment variable categories for readability.
func applyEnvOverrides(v *viper.Viper, cfg *Config) error {
	cfg.SSHHost = strings.TrimSpace(v.GetString("ssh.host"))
	cfg.SSHUser = strings.TrimSpace(v.GetString("ssh.user"))
	cfg.SSHAuthMethod = strings.TrimSpace(v.GetString("ssh.auth.method"))

	//nolint:govet // this small override table is intentionally compact.
	overrides := []struct {
		key   string
		apply func(string) error
	}{
		{"ssh.port", func(value string) error {
			port, err := parsePort(value)
			if err != nil {
				return fmt.Errorf("invalid SSH_PORT: %w", err)
			}
			cfg.SSHPort = port
			return nil
		}},
		{"ssh.key.file", func(value string) error {
			cfg.SSHKeyFile = value
			return nil
		}},
		{"ssh.auth.sock", func(value string) error {
			cfg.SSHAuthSock = value
			return nil
		}},
		{"config.file", func(value string) error {
			cfg.ConfigFile = value
			return nil
		}},
		{"tunnel.max.retries", func(value string) error {
			n, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid TUNNEL_MAX_RETRIES: %w", err)
			}
			if n < -1 {
				return errors.New("TUNNEL_MAX_RETRIES must be -1 or greater")
			}
			cfg.TunnelMaxRetries = n
			return nil
		}},
		{"connection.check.interval", func(value string) error {
			n, err := parsePositiveInt(value)
			if err != nil {
				return fmt.Errorf("invalid CONNECTION_CHECK_INTERVAL: %w", err)
			}
			cfg.ConnectionCheckInterval = time.Duration(n) * time.Second
			return nil
		}},
		{"healthcheck.probe.interval", func(value string) error {
			n, err := parsePositiveInt(value)
			if err != nil {
				return fmt.Errorf("invalid HEALTHCHECK_PROBE_INTERVAL: %w", err)
			}
			cfg.HealthcheckProbeInterval = time.Duration(n) * time.Second
			return nil
		}},
		{"connect.timeout", func(value string) error {
			n, err := parsePositiveInt(value)
			if err != nil {
				return fmt.Errorf("invalid CONNECT_TIMEOUT: %w", err)
			}
			cfg.ConnectTimeout = time.Duration(n) * time.Second
			return nil
		}},
		{"tcp.keepalive", func(value string) error {
			n, err := parsePositiveInt(value)
			if err != nil {
				return fmt.Errorf("invalid TCP_KEEPALIVE: %w", err)
			}
			cfg.TCPKeepalive = time.Duration(n) * time.Second
			return nil
		}},
		{"health.file", func(value string) error {
			cfg.HealthFile = value
			return nil
		}},
	}

	for _, override := range overrides {
		value := strings.TrimSpace(v.GetString(override.key))
		if value == "" {
			continue
		}
		if err := override.apply(value); err != nil {
			return err
		}
	}

	cfg.Verbose = v.GetBool("verbose")
	return nil
}

func resolveTunnelSource(v *viper.Viper, cfgFile string) string {
	tunnelSource := strings.TrimSpace(v.GetString("tunnels"))
	if tunnelSource != "" {
		return tunnelSource
	}

	//nolint:gosec // file path comes from application configuration and is intentionally read.
	data, err := os.ReadFile(cfgFile)
	if err != nil {
		return ""
	}
	return string(data)
}

// Validate checks that the configuration is complete and internally consistent.
func (c Config) Validate() error {
	if err := validateRequiredConfig(c); err != nil {
		return err
	}
	if err := validateTiming(c); err != nil {
		return err
	}
	for i, t := range c.Tunnels {
		if err := validateTunnel(i, t); err != nil {
			return err
		}
	}
	return nil
}

func validateRequiredConfig(c Config) error {
	if c.SSHHost == "" {
		return errors.New("SSH_HOST is required")
	}
	if c.SSHUser == "" {
		return errors.New("SSH_USER is required")
	}
	if c.SSHAuthMethod != AuthMethodKey && c.SSHAuthMethod != AuthMethodAgent {
		return errors.New("SSH_AUTH_METHOD must be key or agent")
	}
	if c.SSHAuthMethod == AuthMethodKey && strings.TrimSpace(c.SSHKeyFile) == "" {
		return errors.New("SSH_KEY_FILE is required when SSH_AUTH_METHOD=key")
	}
	if c.SSHAuthMethod == AuthMethodAgent && strings.TrimSpace(c.SSHAuthSock) == "" {
		return errors.New("SSH_AUTH_SOCK is required when SSH_AUTH_METHOD=agent")
	}
	if c.SSHPort < 1 || c.SSHPort > 65535 {
		return errors.New("SSH_PORT must be in range 1-65535")
	}
	if len(c.Tunnels) == 0 {
		return errors.New("at least one tunnel must be configured via TUNNELS or CONFIG_FILE")
	}
	return nil
}

func validateTiming(c Config) error {
	if c.ConnectionCheckInterval <= 0 {
		return errors.New("CONNECTION_CHECK_INTERVAL must be > 0")
	}
	if c.HealthcheckProbeInterval <= 0 {
		return errors.New("HEALTHCHECK_PROBE_INTERVAL must be > 0")
	}
	if c.ConnectTimeout <= 0 {
		return errors.New("CONNECT_TIMEOUT must be > 0")
	}
	if c.TCPKeepalive <= 0 {
		return errors.New("TCP_KEEPALIVE must be > 0")
	}
	return nil
}

func validateTunnel(index int, tunnel Tunnel) error {
	if strings.TrimSpace(tunnel.LocalIP) == "" {
		return fmt.Errorf("tunnel %d local ip must not be empty", index)
	}
	if strings.TrimSpace(tunnel.TargetHost) == "" {
		return fmt.Errorf("tunnel %d target host must not be empty", index)
	}
	if tunnel.LocalPort < 1 || tunnel.LocalPort > 65535 {
		return fmt.Errorf("tunnel %d local port out of range", index)
	}
	if tunnel.TargetPort < 1 || tunnel.TargetPort > 65535 {
		return fmt.Errorf("tunnel %d target port out of range", index)
	}
	return nil
}

// ParseTunnels converts newline-delimited tunnel specs into Tunnel entries.
func ParseTunnels(raw string) ([]Tunnel, error) {
	lines := strings.Split(raw, "\n")
	out := make([]Tunnel, 0, len(lines))

	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		parts := strings.Split(trimmed, ":")
		if len(parts) != 4 {
			return nil, fmt.Errorf(
				"invalid tunnel format at line %d: expected local_ip:local_port:target_host:target_port",
				idx+1,
			)
		}

		localPort, err := parsePort(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid local port at line %d: %w", idx+1, err)
		}
		targetPort, err := parsePort(parts[3])
		if err != nil {
			return nil, fmt.Errorf("invalid target port at line %d: %w", idx+1, err)
		}

		out = append(out, Tunnel{
			LocalIP:    strings.TrimSpace(parts[0]),
			LocalPort:  localPort,
			TargetHost: strings.TrimSpace(parts[2]),
			TargetPort: targetPort,
		})
	}

	if len(out) == 0 {
		return nil, errors.New("no tunnels configured")
	}

	return out, nil
}

func parsePort(v string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, err
	}
	if n < 1 || n > 65535 {
		return 0, errors.New("port must be 1-65535")
	}
	return n, nil
}

func parsePositiveInt(v string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, errors.New("must be > 0")
	}
	return n, nil
}
