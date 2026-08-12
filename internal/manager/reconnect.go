package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	ExitCodeConfigInvalid    = 100
	ExitCodeAuthFailure      = 105
	ExitCodeLocalPortInUse   = 110
	ExitCodeRetriesExhausted = 115
)

type DialErrorClass int

const (
	DialErrorHostUnreachable DialErrorClass = iota
	DialErrorAuthFailure
	DialErrorOther
)

type reconnectHooks struct {
	dialSSH       func() (SSHClient, error)
	tcpReachable  func() bool
	sleep         func(context.Context, time.Duration) bool
	now           func() time.Time
	markUnhealthy func(string)
	logf          func(string, ...any)
}

func classifyDialError(err error) DialErrorClass {
	if err == nil {
		return DialErrorOther
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return DialErrorHostUnreachable
	}

	lower := strings.ToLower(err.Error())
	markers := []string{
		"unable to authenticate",
		"no supported methods remain",
		"permission denied",
		"handshake failed",
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return DialErrorAuthFailure
		}
	}

	return DialErrorOther
}

func connectWithRecovery(ctx context.Context, maxRetries int, interval time.Duration, hooks reconnectHooks) (SSHClient, int) {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil, 0
		}

		client, err := hooks.dialSSH()
		if err == nil {
			return client, 0
		}

		cls := classifyDialError(err)
		reachable := hooks.tcpReachable()

		if cls == DialErrorAuthFailure && reachable {
			hooks.markUnhealthy(fmt.Sprintf("authentication failure: %v", err))
			hooks.logf("fatal: ssh host reachable but authentication/handshake failed: %v", err)
			return nil, ExitCodeAuthFailure
		}

		if cls == DialErrorHostUnreachable || !reachable {
			hooks.markUnhealthy("ssh host unreachable")
			downAt := hooks.now()
			hooks.logf("ssh host unreachable; pausing forwarding until host is reachable")
			for {
				if ctx.Err() != nil {
					return nil, 0
				}
				if hooks.tcpReachable() {
					waited := hooks.now().Sub(downAt).Round(time.Second)
					hooks.logf("ssh host reachable again after %s; reconnecting", waited)
					attempt = 0
					break
				}
				if !hooks.sleep(ctx, interval) {
					return nil, 0
				}
			}
			continue
		}

		attempt++
		hooks.markUnhealthy(fmt.Sprintf("reconnect attempt %d failed: %v", attempt, err))
		if maxRetries >= 0 && attempt >= maxRetries {
			hooks.logf("fatal: reconnect retries exhausted after %d attempts", attempt)
			return nil, ExitCodeRetriesExhausted
		}
		hooks.logf("reconnect attempt %d failed (%v); retrying in %s", attempt, err, interval)
		if !hooks.sleep(ctx, interval) {
			return nil, 0
		}
	}
}
