// Package sshauth builds an ssh.ClientConfig from application configuration,
// supporting private-key and ssh-agent authentication.
package sshauth

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/kreigan/tunneller/internal/config"
)

// BuildClientConfig builds an ssh.ClientConfig for the given application
// config. The returned cleanup function must be called once the connection
// (and any auth resources such as an ssh-agent socket) are no longer needed.
func BuildClientConfig(cfg config.Config) (*ssh.ClientConfig, func(), error) {
	var (
		authMethod ssh.AuthMethod
		cleanup    = func() {}
	)

	switch cfg.SSHAuthMethod {
	case config.AuthMethodKey:
		privateKey, err := os.ReadFile(cfg.SSHKeyFile)
		if err != nil {
			return nil, cleanup, fmt.Errorf("read private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			return nil, cleanup, fmt.Errorf("parse private key: %w", err)
		}
		authMethod = ssh.PublicKeys(signer)
	case config.AuthMethodAgent:
		agentConn, err := net.Dial("unix", cfg.SSHAuthSock)
		if err != nil {
			return nil, cleanup, fmt.Errorf("connect to ssh agent: %w", err)
		}
		agentClient := agent.NewClient(agentConn)
		authMethod = ssh.PublicKeysCallback(agentClient.Signers)
		cleanup = func() {
			if err := agentConn.Close(); err != nil {
				fmt.Printf("warning: close ssh-agent socket: %v\n", err)
			}
		}
	default:
		return nil, cleanup, fmt.Errorf("unsupported auth method: %s", cfg.SSHAuthMethod)
	}

	sshCfg := &ssh.ClientConfig{
		User: cfg.SSHUser,
		Auth: []ssh.AuthMethod{authMethod},
		//nolint:gosec // The project intentionally bypasses host-key verification for this tunnel manager.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cfg.ConnectTimeout,
	}

	return sshCfg, cleanup, nil
}
