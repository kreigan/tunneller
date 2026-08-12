package manager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	HealthHealthyPrefix   = "healthy"
	HealthUnhealthyPrefix = "unhealthy:"
	HealthStopped         = "stopped"
)

type HealthStore struct {
	path string
}

func NewHealthStore(path string) *HealthStore {
	return &HealthStore{path: path}
}

func (h *HealthStore) WriteHealthy() error {
	return h.write(HealthHealthyPrefix)
}

func (h *HealthStore) WriteUnhealthy(reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "unknown"
	}
	return h.write(fmt.Sprintf("%s %s", HealthUnhealthyPrefix, reason))
}

func (h *HealthStore) WriteStopped() error {
	return h.write(HealthStopped)
}

func (h *HealthStore) Read() (string, error) {
	data, err := os.ReadFile(h.path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

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
	if err := os.MkdirAll(filepath.Dir(h.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(h.path, []byte(state+"\n"), 0o644)
}
