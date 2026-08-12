package manager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// HealthHealthyPrefix indicates the system is healthy.
	HealthHealthyPrefix = "healthy"
	// HealthUnhealthyPrefix marks an unhealthy state in the health file.
	HealthUnhealthyPrefix = "unhealthy:"
	// HealthStopped indicates the SSH tunnel manager has stopped.
	HealthStopped = "stopped"
)

// HealthStore persists the current service state to a file.
type HealthStore struct {
	path string
}

// NewHealthStore creates a HealthStore for the given file path.
func NewHealthStore(path string) *HealthStore {
	return &HealthStore{path: path}
}

// WriteHealthy writes the healthy status to the health file.
func (h *HealthStore) WriteHealthy() error {
	return h.write(HealthHealthyPrefix)
}

// WriteUnhealthy writes the unhealthy status with a descriptive reason.
func (h *HealthStore) WriteUnhealthy(reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "unknown"
	}
	return h.write(fmt.Sprintf("%s %s", HealthUnhealthyPrefix, reason))
}

// WriteStopped writes the stopped status to the health file.
func (h *HealthStore) WriteStopped() error {
	return h.write(HealthStopped)
}

// Read loads the current state from the health file.
func (h *HealthStore) Read() (string, error) {
	data, err := os.ReadFile(h.path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// IsHealthy reports whether the current state is healthy.
func (h *HealthStore) IsHealthy() (bool, error) {
	state, err := h.Read()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return strings.HasPrefix(state, HealthHealthyPrefix), nil
}

func (h *HealthStore) write(state string) error {
	if err := os.MkdirAll(filepath.Dir(h.path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(h.path, []byte(state+"\n"), 0o600)
}
