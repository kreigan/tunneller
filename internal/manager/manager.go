package manager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kreigan/tunneller/internal/config"

	"golang.org/x/crypto/ssh"
)

type SSHClient interface {
	Dial(network, addr string) (net.Conn, error)
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
	Close() error
}

type SSHDialer interface {
	Dial(network, addr string, cfg *ssh.ClientConfig) (SSHClient, error)
}

type TCPProber interface {
	DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error)
}

type netSSHClient struct {
	client *ssh.Client
}

func (n *netSSHClient) Dial(network, addr string) (net.Conn, error) {
	return n.client.Dial(network, addr)
}

func (n *netSSHClient) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return n.client.SendRequest(name, wantReply, payload)
}

func (n *netSSHClient) Close() error {
	return n.client.Close()
}

type realSSHDialer struct{}

func (d realSSHDialer) Dial(network, addr string, cfg *ssh.ClientConfig) (SSHClient, error) {
	c, err := ssh.Dial(network, addr, cfg)
	if err != nil {
		return nil, err
	}
	return &netSSHClient{client: c}, nil
}

type realTCPProber struct{}

func (p realTCPProber) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

type listenerFactory func(network, addr string) (net.Listener, error)

type Manager struct {
	cfg         config.Config
	sshCfg      *ssh.ClientConfig
	logger      *log.Logger
	healthStore *HealthStore
	dialer      SSHDialer
	prober      TCPProber
	listenFn    listenerFactory
	sleepFn     func(context.Context, time.Duration) bool
	nowFn       func() time.Time

	listeners []net.Listener

	clientMu sync.RWMutex
	client   SSHClient
	verbose  bool
}

func New(cfg config.Config, sshCfg *ssh.ClientConfig, logger *log.Logger) *Manager {
	if logger == nil {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	return &Manager{
		cfg:         cfg,
		sshCfg:      sshCfg,
		logger:      logger,
		healthStore: NewHealthStore(cfg.HealthFile),
		dialer:      realSSHDialer{},
		prober:      realTCPProber{},
		listenFn:    net.Listen,
		sleepFn:     sleepWithContext,
		nowFn:       time.Now,
		verbose:     cfg.Verbose,
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (m *Manager) Run(ctx context.Context) int {
	if err := m.healthStore.WriteUnhealthy("starting"); err != nil {
		m.logf("warning: failed to update health file: %v", err)
	}

	listeners, err := m.bindListeners()
	if err != nil {
		m.logf("fatal: %v", err)
		_ = m.healthStore.WriteUnhealthy(err.Error())
		if errors.Is(err, syscall.EADDRINUSE) || strings.Contains(strings.ToLower(err.Error()), "address already in use") {
			return ExitCodeLocalPortInUse
		}
		return ExitCodeConfigInvalid
	}
	m.listeners = listeners
	defer m.closeListeners()

	for i := range m.cfg.Tunnels {
		tunnel := m.cfg.Tunnels[i]
		listener := listeners[i]
		m.logf("tunnel listener ready: %s -> %s", tunnel.LocalAddress(), tunnel.TargetAddress())
		go m.acceptLoop(ctx, listener, tunnel)
	}

	for {
		client, exitCode := connectWithRecovery(ctx, m.cfg.TunnelMaxRetries, m.cfg.ConnectionCheckInterval, reconnectHooks{
			dialSSH:      m.dialSSH,
			tcpReachable: m.isSSHHostReachable,
			sleep:        m.sleepFn,
			now:          m.nowFn,
			markUnhealthy: func(reason string) {
				if err := m.healthStore.WriteUnhealthy(reason); err != nil {
					m.logf("warning: failed to update health file: %v", err)
				}
			},
			logf: m.logf,
		})
		if exitCode != 0 {
			m.clearClient()
			return exitCode
		}
		if client == nil {
			m.clearClient()
			return 0
		}

		m.setClient(client)
		if err := m.healthStore.WriteHealthy(); err != nil {
			m.logf("warning: failed to update health file: %v", err)
		}
		m.logf("ssh connection established; tunnels active")

		disconnected := m.monitorConnection(ctx, client)
		if ctx.Err() != nil {
			m.clearClient()
			if err := m.healthStore.WriteStopped(); err != nil {
				m.logf("warning: failed to update health file: %v", err)
			}
			return 0
		}

		m.logf("ssh connection lost: %v", disconnected)
		_ = m.healthStore.WriteUnhealthy(fmt.Sprintf("connection lost: %v", disconnected))
		m.clearClient()
	}
}

func (m *Manager) dialSSH() (SSHClient, error) {
	addr := fmt.Sprintf("%s:%d", m.cfg.SSHHost, m.cfg.SSHPort)
	if m.verbose {
		m.logf("dialing ssh %s", addr)
	}
	return m.dialer.Dial("tcp", addr, m.sshCfg)
}

func (m *Manager) isSSHHostReachable() bool {
	addr := fmt.Sprintf("%s:%d", m.cfg.SSHHost, m.cfg.SSHPort)
	conn, err := m.prober.DialTimeout("tcp", addr, m.cfg.ConnectTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (m *Manager) monitorConnection(ctx context.Context, client SSHClient) error {
	ticker := time.NewTicker(m.cfg.HealthcheckProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@tunnel-manager", true, nil)
			if err != nil {
				return err
			}
		}
	}
}

func (m *Manager) bindListeners() ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(m.cfg.Tunnels))
	for _, tunnel := range m.cfg.Tunnels {
		ln, err := m.listenFn("tcp", tunnel.LocalAddress())
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return nil, fmt.Errorf("failed to start tunnel %s -> %s on local %s: %w", tunnel.TargetHost, tunnel.TargetAddress(), tunnel.LocalAddress(), err)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

func (m *Manager) closeListeners() {
	for _, ln := range m.listeners {
		_ = ln.Close()
	}
}

func (m *Manager) acceptLoop(ctx context.Context, listener net.Listener, tunnel config.Tunnel) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			m.logf("listener %s accept error: %v", tunnel.LocalAddress(), err)
			continue
		}
		if m.verbose {
			m.logf("accepted local connection on %s", tunnel.LocalAddress())
		}
		go m.forwardConnection(tunnel, conn)
	}
}

func (m *Manager) forwardConnection(tunnel config.Tunnel, localConn net.Conn) {
	defer func() {
		_ = localConn.Close()
	}()

	client := m.getClient()
	if client == nil {
		if m.verbose {
			m.logf("dropping connection on %s because ssh connection is unavailable", tunnel.LocalAddress())
		}
		return
	}

	remoteConn, err := client.Dial("tcp", tunnel.TargetAddress())
	if err != nil {
		if m.verbose {
			m.logf("failed opening ssh channel for %s -> %s: %v", tunnel.LocalAddress(), tunnel.TargetAddress(), err)
		}
		return
	}
	defer func() {
		_ = remoteConn.Close()
	}()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remoteConn, localConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(localConn, remoteConn)
		done <- struct{}{}
	}()
	<-done
	<-done

	if m.verbose {
		m.logf("closed forwarded connection on %s", tunnel.LocalAddress())
	}
}

func (m *Manager) setClient(client SSHClient) {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	m.client = client
}

func (m *Manager) clearClient() {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	if m.client != nil {
		_ = m.client.Close()
		m.client = nil
	}
}

func (m *Manager) getClient() SSHClient {
	m.clientMu.RLock()
	defer m.clientMu.RUnlock()
	return m.client
}

func (m *Manager) logf(format string, args ...any) {
	m.logger.Printf(format, args...)
}

func (m *Manager) HealthStore() *HealthStore {
	return m.healthStore
}
