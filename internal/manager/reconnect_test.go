package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockSSHClient struct{}

func (m *mockSSHClient) Dial(string, string) (net.Conn, error) { return nil, nil }
func (m *mockSSHClient) SendRequest(string, bool, []byte) (ok bool, response []byte, err error) {
	return true, nil, nil
}
func (m *mockSSHClient) Close() error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyDialError(t *testing.T) {
	//nolint:govet // the table is intentionally compact for the test case layout.
	tests := []struct {
		name string
		err  error
		want DialErrorClass
	}{
		{name: "network", err: timeoutError{}, want: DialErrorHostUnreachable},
		{name: "auth marker", err: errors.New("ssh: handshake failed: unable to authenticate"), want: DialErrorAuthFailure},
		{name: "other", err: errors.New("unexpected EOF"), want: DialErrorOther},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyDialError(tc.err)
			if got != tc.want {
				t.Fatalf("classifyDialError() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConnectWithRecoveryHostUnreachableThenRecoverResetsRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu           sync.Mutex
		dialCalls    int
		reachableTry int
		unhealthy    []string
		logs         []string
		nowTick      int
	)

	hooks := reconnectHooks{
		dialSSH: func() (SSHClient, error) {
			mu.Lock()
			defer mu.Unlock()
			dialCalls++
			switch dialCalls {
			case 1:
				return nil, timeoutError{}
			case 2:
				return nil, errors.New("transient failure")
			default:
				return &mockSSHClient{}, nil
			}
		},
		tcpReachable: func() bool {
			reachableTry++
			return reachableTry >= 3
		},
		sleep: func(context.Context, time.Duration) bool {
			return true
		},
		now: func() time.Time {
			nowTick++
			return time.Unix(int64(nowTick*5), 0)
		},
		markUnhealthy: func(reason string) {
			unhealthy = append(unhealthy, reason)
		},
		logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	}

	client, code := connectWithRecovery(ctx, 2, time.Second, hooks)
	if code != 0 {
		t.Fatalf("expected success code 0, got %d", code)
	}
	if client == nil {
		t.Fatal("expected client, got nil")
	}
	if dialCalls != 3 {
		t.Fatalf("expected 3 dial attempts, got %d", dialCalls)
	}

	foundWaitLog := false
	for _, entry := range logs {
		if strings.Contains(entry, "reachable again after") {
			foundWaitLog = true
			break
		}
	}
	if !foundWaitLog {
		t.Fatalf("expected reachable-again log entry, logs=%v", logs)
	}
	if len(unhealthy) == 0 {
		t.Fatal("expected unhealthy markers")
	}
}

func TestConnectWithRecoveryAuthFailureExits105(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var unhealthy []string
	client, code := connectWithRecovery(ctx, 3, time.Second, reconnectHooks{
		dialSSH: func() (SSHClient, error) {
			return nil, errors.New("ssh: handshake failed: unable to authenticate")
		},
		tcpReachable:  func() bool { return true },
		sleep:         func(context.Context, time.Duration) bool { return true },
		now:           time.Now,
		markUnhealthy: func(reason string) { unhealthy = append(unhealthy, reason) },
		logf:          func(string, ...any) {},
	})

	if client != nil {
		t.Fatal("expected nil client")
	}
	if code != ExitCodeAuthFailure {
		t.Fatalf("expected code %d, got %d", ExitCodeAuthFailure, code)
	}
	if len(unhealthy) != 1 || !strings.Contains(unhealthy[0], "authentication failure") {
		t.Fatalf("unexpected unhealthy state: %v", unhealthy)
	}
}

func TestConnectWithRecoveryRetriesExhausted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialCalls := 0
	client, code := connectWithRecovery(ctx, 1, time.Second, reconnectHooks{
		dialSSH: func() (SSHClient, error) {
			dialCalls++
			return nil, errors.New("random transient")
		},
		tcpReachable:  func() bool { return true },
		sleep:         func(context.Context, time.Duration) bool { return true },
		now:           time.Now,
		markUnhealthy: func(string) {},
		logf:          func(string, ...any) {},
	})

	if client != nil {
		t.Fatal("expected nil client")
	}
	if code != ExitCodeRetriesExhausted {
		t.Fatalf("expected code %d, got %d", ExitCodeRetriesExhausted, code)
	}
	if dialCalls != 1 {
		t.Fatalf("expected 1 dial attempt, got %d", dialCalls)
	}
}

func TestConnectWithRecoveryRetryForever(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialCalls := 0
	client, code := connectWithRecovery(ctx, -1, time.Second, reconnectHooks{
		dialSSH: func() (SSHClient, error) {
			dialCalls++
			if dialCalls >= 4 {
				return &mockSSHClient{}, nil
			}
			return nil, errors.New("temporary")
		},
		tcpReachable:  func() bool { return true },
		sleep:         func(context.Context, time.Duration) bool { return true },
		now:           time.Now,
		markUnhealthy: func(string) {},
		logf:          func(string, ...any) {},
	})

	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	if client == nil {
		t.Fatal("expected client after retries")
	}
	if dialCalls != 4 {
		t.Fatalf("expected 4 dial attempts, got %d", dialCalls)
	}
}
