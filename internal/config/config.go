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
	AuthMethodKey   = "key"
	AuthMethodAgent = "agent"

	DefaultSSHPort                = 22
	DefaultConfigFile             = "/tmp/config.conf"
	DefaultTunnelMaxRetries       = 3
	DefaultConnectionCheckSeconds = 5
	DefaultHealthProbeSeconds     = 30
	DefaultConnectTimeoutSeconds  = 10
	DefaultTCPKeepaliveSeconds    = 30
	DefaultHealthFile             = "/tmp/health"
)

func defaultSSHKeyFile() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "id")
}

func defaultSSHAuthSock() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "agent.sock")
}

type Tunnel struct {
	LocalIP    string
	LocalPort  int
	TargetHost string
	TargetPort int
}

func (t Tunnel) LocalAddress() string {
	return fmt.Sprintf("%s:%d", t.LocalIP, t.LocalPort)
}

func (t Tunnel) TargetAddress() string {
	return fmt.Sprintf("%s:%d", t.TargetHost, t.TargetPort)
}

type Config struct {
	SSHHost                  string
	SSHPort                  int
	SSHUser                  string
	SSHAuthMethod            string
	SSHKeyFile               string
	SSHAuthSock              string
	Tunnels                  []Tunnel
	ConfigFile               string
	TunnelMaxRetries         int
	ConnectionCheckInterval  time.Duration
	HealthcheckProbeInterval time.Duration
	ConnectTimeout           time.Duration
	TCPKeepalive             time.Duration
	Verbose                  bool
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

	_ = v.BindEnv("ssh.host", "SSH_HOST")
	_ = v.BindEnv("ssh.port", "SSH_PORT")
	_ = v.BindEnv("ssh.user", "SSH_USER")
	_ = v.BindEnv("ssh.auth.method", "SSH_AUTH_METHOD")
	_ = v.BindEnv("ssh.key.file", "SSH_KEY_FILE")
	_ = v.BindEnv("ssh.auth.sock", "SSH_AUTH_SOCK")
	_ = v.BindEnv("config.file", "CONFIG_FILE")
	_ = v.BindEnv("tunnel.max.retries", "TUNNEL_MAX_RETRIES")
	_ = v.BindEnv("connection.check.interval", "CONNECTION_CHECK_INTERVAL")
	_ = v.BindEnv("healthcheck.probe.interval", "HEALTHCHECK_PROBE_INTERVAL")
	_ = v.BindEnv("connect.timeout", "CONNECT_TIMEOUT")
	_ = v.BindEnv("tcp.keepalive", "TCP_KEEPALIVE")
	_ = v.BindEnv("health.file", "HEALTH_FILE")
	_ = v.BindEnv("verbose", "VERBOSE")
	_ = v.BindEnv("tunnels", "TUNNELS")

	return v
}

func LoadFromEnv() (Config, error) {
	v := newViper()

	cfg := Config{
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

	cfg.SSHHost = strings.TrimSpace(v.GetString("ssh.host"))
	cfg.SSHUser = strings.TrimSpace(v.GetString("ssh.user"))
	cfg.SSHAuthMethod = strings.TrimSpace(v.GetString("ssh.auth.method"))

	if v := strings.TrimSpace(v.GetString("ssh.port")); v != "" {
		port, err := parsePort(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid SSH_PORT: %w", err)
		}
		cfg.SSHPort = port
	}

	if v := strings.TrimSpace(v.GetString("ssh.key.file")); v != "" {
		cfg.SSHKeyFile = v
	}
	if v := strings.TrimSpace(v.GetString("ssh.auth.sock")); v != "" {
		cfg.SSHAuthSock = v
	}
	if v := strings.TrimSpace(v.GetString("config.file")); v != "" {
		cfg.ConfigFile = v
	}
	if v := strings.TrimSpace(v.GetString("tunnel.max.retries")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid TUNNEL_MAX_RETRIES: %w", err)
		}
		if n < -1 {
			return Config{}, errors.New("TUNNEL_MAX_RETRIES must be -1 or greater")
		}
		cfg.TunnelMaxRetries = n
	}
	if v := strings.TrimSpace(v.GetString("connection.check.interval")); v != "" {
		n, err := parsePositiveInt(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid CONNECTION_CHECK_INTERVAL: %w", err)
		}
		cfg.ConnectionCheckInterval = time.Duration(n) * time.Second
	}
	if v := strings.TrimSpace(v.GetString("healthcheck.probe.interval")); v != "" {
		n, err := parsePositiveInt(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid HEALTHCHECK_PROBE_INTERVAL: %w", err)
		}
		cfg.HealthcheckProbeInterval = time.Duration(n) * time.Second
	}
	if v := strings.TrimSpace(v.GetString("connect.timeout")); v != "" {
		n, err := parsePositiveInt(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid CONNECT_TIMEOUT: %w", err)
		}
		cfg.ConnectTimeout = time.Duration(n) * time.Second
	}
	if v := strings.TrimSpace(v.GetString("tcp.keepalive")); v != "" {
		n, err := parsePositiveInt(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid TCP_KEEPALIVE: %w", err)
		}
		cfg.TCPKeepalive = time.Duration(n) * time.Second
	}
	if v := strings.TrimSpace(v.GetString("health.file")); v != "" {
		cfg.HealthFile = v
	}

	cfg.Verbose = v.GetBool("verbose")

	tunnelSource := strings.TrimSpace(v.GetString("tunnels"))
	if tunnelSource == "" {
		data, err := os.ReadFile(cfg.ConfigFile)
		if err == nil {
			tunnelSource = string(data)
		}
	}

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

func (c Config) Validate() error {
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

	for i, t := range c.Tunnels {
		if strings.TrimSpace(t.LocalIP) == "" {
			return fmt.Errorf("tunnel %d local ip must not be empty", i)
		}
		if strings.TrimSpace(t.TargetHost) == "" {
			return fmt.Errorf("tunnel %d target host must not be empty", i)
		}
		if t.LocalPort < 1 || t.LocalPort > 65535 {
			return fmt.Errorf("tunnel %d local port out of range", i)
		}
		if t.TargetPort < 1 || t.TargetPort > 65535 {
			return fmt.Errorf("tunnel %d target port out of range", i)
		}
	}

	return nil
}

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
			return nil, fmt.Errorf("invalid tunnel format at line %d: expected local_ip:local_port:target_host:target_port", idx+1)
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
