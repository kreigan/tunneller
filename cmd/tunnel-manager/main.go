package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sshtun-docker/internal/config"
	"sshtun-docker/internal/manager"
	"sshtun-docker/internal/sshauth"

	"github.com/spf13/cobra"
)

var (
	healthcheck bool
	healthFile  string
	version 	string	= "dev"
	commit  	string	= "none"
	date    	string	= "unknown"
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel-manager",
		Short: "Manage local SSH tunnels through a single SSH host",
		Run: func(cmd *cobra.Command, args []string) {
			if healthcheck {
				store := manager.NewHealthStore(healthFile)
				healthy, err := store.IsHealthy()
				if err != nil {
					_, _ = fmt.Fprintf(os.Stdout, "healthcheck error: %v\n", err)
					os.Exit(1)
				}
				if healthy {
					_, _ = fmt.Fprintln(os.Stdout, "healthy")
					os.Exit(0)
				}
				state, err := store.Read()
				if err != nil {
					_, _ = fmt.Fprintf(os.Stdout, "unhealthy: %v\n", err)
					os.Exit(1)
				}
				_, _ = fmt.Fprintln(os.Stdout, state)
				os.Exit(1)
			}

			cfg, err := config.LoadFromEnv()
			if err != nil {
				log.Printf("configuration error: %v", err)
				os.Exit(manager.ExitCodeConfigInvalid)
			}

			sshCfg, closeAuthResources, err := sshauth.BuildClientConfig(cfg)
			if err != nil {
				log.Printf("ssh auth configuration error: %v", err)
				os.Exit(manager.ExitCodeConfigInvalid)
			}
			defer closeAuthResources()

			logger := log.New(os.Stdout, "", log.LstdFlags)
			mgr := manager.New(cfg, sshCfg, logger)

			ctx, cancel := signal.NotifyContext(
				context.Background(),
				syscall.SIGINT,
				syscall.SIGTERM,
			)
			defer cancel()

			exitCode := mgr.Run(ctx)
			os.Exit(exitCode)
		},
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	cmd.Flags().BoolVar(&healthcheck, "healthcheck", false, "run healthcheck mode")
	cmd.Flags().StringVar(&healthFile, "health-file", config.DefaultHealthFile, "health file path")

	return cmd
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
