/*
Package manager coordinates SSH tunnel listeners and reconnect logic.
*/
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

	"golang.org/x/crypto/ssh"

	"github.com/kreigan/tunneller/internal/config"
)

// SSHClient is the subset of ssh.Client behavior required by the manager.
type SSHClient interface {
	Dial(network, addr string) (net.Conn, error)
	SendRequest(name string, wantReply bool, payload []byte) (ok bool, response []byte, err error)
	Close() error
}

// SSHDialer creates SSH clients for a given remote address.
type SSHDialer interface {
	Dial(network, addr string, cfg *ssh.ClientConfig) (SSHClient, error)
}

// TCPProber checks whether an SSH target host is reachable.
type TCPProber interface {
	DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error)
}

type netSSHClient struct {
	client *ssh.Client
}

func (n *netSSHClient) Dial(network, addr string) (net.Conn, error) {
	return n.client.Dial(network, addr)
}

func (n *netSSHClient) SendRequest(
	name string,
	wantReply bool,
	payload []byte,
) (ok bool, response []byte, err error) {
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

// Manager owns the SSH tunnel listeners and connection lifecycle.
//
//nolint:govet // the field layout intentionally groups lock/runtime state for clarity.
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

// New creates a new Manager instance.
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

// Run starts listeners and maintains the SSH connection until the context ends.
func (m *Manager) Run(ctx context.Context) int {
	if err := m.healthStore.WriteUnhealthy("starting"); err != nil {
		m.logf("warning: failed to update health file: %v", err)
	}

	listeners, err := m.bindListeners()
	if err != nil {
		m.logf("fatal: %v", err)
		if healthErr := m.healthStore.WriteUnhealthy(err.Error()); healthErr != nil {
			m.logf("warning: failed to update health file: %v", healthErr)
		}
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

	return m.runConnectionLoop(ctx)
}

//nolint:gocognit // reconnect loop handles auth, network, and retry phases.
func (m *Manager) runConnectionLoop(ctx context.Context) int {
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
		if err := m.healthStore.WriteUnhealthy(fmt.Sprintf("connection lost: %v", disconnected)); err != nil {
			m.logf("warning: failed to update health file: %v", err)
		}
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
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && m.verbose {
		m.logf("warning: failed to close tcp probe connection: %v", err)
	}
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
				if closeErr := l.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					m.logf("warning: failed to close listener during cleanup: %v", closeErr)
				}
			}
			return nil, fmt.Errorf(
				"failed to start tunnel %s -> %s on local %s: %w",
				tunnel.TargetHost,
				tunnel.TargetAddress(),
				tunnel.LocalAddress(),
				err,
			)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

func (m *Manager) closeListeners() {
	for _, ln := range m.listeners {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			m.logf("warning: failed to close tunnel listener: %v", err)
		}
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
		if err := localConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && m.verbose {
			m.logf("warning: failed to close local connection on %s: %v", tunnel.LocalAddress(), err)
		}
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
		if err := remoteConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && m.verbose {
			m.logf("warning: failed to close remote connection on %s: %v", tunnel.LocalAddress(), err)
		}
	}()

	m.copyBidirectionally(tunnel, localConn, remoteConn)
}

func (m *Manager) copyBidirectionally(tunnel config.Tunnel, localConn, remoteConn net.Conn) {
	done := make(chan struct{}, 2)
	copyUntilDone := func(dst, src net.Conn, direction string) {
		if _, err := io.Copy(dst, src); err != nil && !errors.Is(err, net.ErrClosed) && m.verbose {
			m.logf("copy from %s on %s ended: %v", direction, tunnel.LocalAddress(), err)
		}
		done <- struct{}{}
	}
	go copyUntilDone(remoteConn, localConn, "local to remote")
	go copyUntilDone(localConn, remoteConn, "remote to local")
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
		if err := m.client.Close(); err != nil && !errors.Is(err, net.ErrClosed) && m.verbose {
			m.logf("warning: failed to close SSH client: %v", err)
		}
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

// HealthStore returns the current health store for the manager.
func (m *Manager) HealthStore() *HealthStore {
	return m.healthStore
}
