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
	// ExitCodeConfigInvalid means the SSH tunnel configuration is invalid.
	ExitCodeConfigInvalid = 100
	// ExitCodeAuthFailure means the SSH server rejected authentication.
	ExitCodeAuthFailure = 105
	// ExitCodeLocalPortInUse means a local listener port is already occupied.
	ExitCodeLocalPortInUse = 110
	// ExitCodeRetriesExhausted means all retry attempts were exhausted.
	ExitCodeRetriesExhausted = 115
)

// DialErrorClass identifies the type of SSH dial failure encountered.
type DialErrorClass int

const (
	// DialErrorHostUnreachable indicates the remote SSH host is not reachable.
	DialErrorHostUnreachable DialErrorClass = iota
	// DialErrorAuthFailure indicates the SSH host refused authentication.
	DialErrorAuthFailure
	// DialErrorOther indicates another dial error type.
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

func connectWithRecovery(
	ctx context.Context,
	maxRetries int,
	interval time.Duration,
	hooks reconnectHooks,
) (client SSHClient, exitCode int) {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil, 0
		}

		client, err := hooks.dialSSH()
		if err == nil {
			return client, 0
		}

		if exitCode, done, resetRetries := handleDialFailure(
			ctx,
			retryState{attempt: attempt, maxRetries: maxRetries},
			interval,
			err,
			hooks,
		); done {
			return nil, exitCode
		} else if resetRetries {
			attempt = 0
		} else {
			attempt++
		}
	}
}

type retryState struct {
	attempt    int
	maxRetries int
}

func handleDialFailure(
	ctx context.Context,
	state retryState,
	interval time.Duration,
	err error,
	hooks reconnectHooks,
) (exitCode int, done, resetRetries bool) {
	cls := classifyDialError(err)
	reachable := hooks.tcpReachable()

	if cls == DialErrorAuthFailure && reachable {
		hooks.markUnhealthy(fmt.Sprintf("authentication failure: %v", err))
		hooks.logf("fatal: ssh host reachable but authentication/handshake failed: %v", err)
		return ExitCodeAuthFailure, true, false
	}

	if cls == DialErrorHostUnreachable || !reachable {
		if waitForReachability(ctx, interval, hooks) {
			return 0, true, false
		}
		return 0, false, true
	}

	state.attempt++
	hooks.markUnhealthy(fmt.Sprintf("reconnect attempt %d failed: %v", state.attempt, err))
	if state.maxRetries >= 0 && state.attempt >= state.maxRetries {
		hooks.logf("fatal: reconnect retries exhausted after %d attempts", state.attempt)
		return ExitCodeRetriesExhausted, true, false
	}
	hooks.logf("reconnect attempt %d failed (%v); retrying in %s", state.attempt, err, interval)
	if !hooks.sleep(ctx, interval) {
		return 0, true, false
	}
	return 0, false, false
}

func waitForReachability(ctx context.Context, interval time.Duration, hooks reconnectHooks) bool {
	hooks.markUnhealthy("ssh host unreachable")
	downAt := hooks.now()
	hooks.logf("ssh host unreachable; pausing forwarding until host is reachable")
	for {
		if ctx.Err() != nil {
			return true
		}
		if hooks.tcpReachable() {
			waited := hooks.now().Sub(downAt).Round(time.Second)
			hooks.logf("ssh host reachable again after %s; reconnecting", waited)
			return false
		}
		if !hooks.sleep(ctx, interval) {
			return true
		}
	}
}
