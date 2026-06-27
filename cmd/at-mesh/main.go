package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/govi218/at-mesh/server"
	_ "github.com/joho/godotenv/autoload"
	"github.com/urfave/cli/v2"
)

var Version = "dev"

func main() {
	app := &cli.App{
		Name:  "at-mesh",
		Usage: "AT Protocol identity bridge for WireGuard mesh networks",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "addr",
				Value:   ":9090",
				EnvVars: []string{"ATMESH_ADDR"},
			},
			&cli.StringFlag{
				Name:    "hostname",
				EnvVars: []string{"ATMESH_HOSTNAME"},
			},
			&cli.StringFlag{
				Name:    "jwk-path",
				EnvVars: []string{"ATMESH_JWK_PATH"},
			},
			&cli.StringFlag{
				Name:    "db-name",
				Value:   "atmesh.db",
				EnvVars: []string{"ATMESH_DB_NAME"},
			},
			&cli.StringFlag{
				Name:    "headscale-url",
				EnvVars: []string{"ATMESH_HEADSCALE_URL"},
				Usage:   "Headscale API URL (optional, for revocation)",
			},
			&cli.StringFlag{
				Name:    "headscale-key",
				EnvVars: []string{"ATMESH_HEADSCALE_KEY"},
				Usage:   "Headscale API key (optional, for revocation)",
			},
			&cli.StringFlag{
				Name:    "admin-email",
				EnvVars: []string{"ATMESH_ADMIN_EMAIL"},
				Usage:   "Admin email for WebFinger (Tailscale SaaS compat)",
			},
			&cli.StringFlag{
				Name:    "admin-token",
				EnvVars: []string{"ATMESH_ADMIN_TOKEN"},
				Usage:   "Admin token for the admin UI",
			},
			&cli.StringFlag{
				Name:    "session-secret",
				EnvVars: []string{"ATMESH_SESSION_SECRET"},
				Value:   "change-me-in-production",
			},
			&cli.StringFlag{
				Name:    "client-id",
				EnvVars: []string{"ATMESH_CLIENT_ID"},
				Usage:   "OAuth client ID (e.g. for Headscale)",
			},
			&cli.StringFlag{
				Name:    "client-secret",
				EnvVars: []string{"ATMESH_CLIENT_SECRET"},
				Usage:   "OAuth client secret (e.g. for Headscale)",
			},
			&cli.StringFlag{
				Name:    "client-redirect-uri",
				EnvVars: []string{"ATMESH_CLIENT_REDIRECT_URI"},
				Usage:   "OAuth client redirect URI",
			},
		},
		Commands: []*cli.Command{
			runServe,
			runCreateJwk,
		},
		ErrWriter: os.Stdout,
		Version:   Version,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

var runServe = &cli.Command{
	Name:  "run",
	Usage: "Start the at-mesh OIDC provider",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "Log level: debug, info, warn, error",
			EnvVars: []string{"ATMESH_LOG_LEVEL", "LOG_LEVEL"},
			Value:   "info",
		},
	},
	Action: func(cmd *cli.Context) error {
		var level string
		switch strings.ToLower(cmd.String("log-level")) {
		case "debug":
			level = "debug"
		case "warn":
			level = "warn"
		case "error":
			level = "error"
		default:
			level = "info"
		}

		s, err := server.New(&server.Args{
			Addr:          cmd.String("addr"),
			Hostname:      cmd.String("hostname"),
			JwkPath:       cmd.String("jwk-path"),
			DbName:        cmd.String("db-name"),
			HeadscaleUrl:  cmd.String("headscale-url"),
			HeadscaleKey:  cmd.String("headscale-key"),
			AdminEmail:    cmd.String("admin-email"),
			AdminToken:    cmd.String("admin-token"),
			SessionSecret: cmd.String("session-secret"),
			Version:       Version,
			LogLevel:      level,
			Clients:       buildClients(cmd),
		})
		if err != nil {
			return fmt.Errorf("error creating at-mesh: %w", err)
		}

		if err := s.Serve(cmd.Context); err != nil {
			return fmt.Errorf("error starting at-mesh: %w", err)
		}

		return nil
	},
}

var runCreateJwk = &cli.Command{
	Name:  "create-jwk",
	Usage: "creates a private JWK for signing OIDC tokens",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "out",
			Required: true,
			Usage:    "output file for your JWK",
		},
	},
	Action: func(cmd *cli.Context) error {
		return server.CreateJwk(cmd.String("out"))
	},
}

func buildClients(cmd *cli.Context) []server.OAuthClient {
	clientID := cmd.String("client-id")
	if clientID == "" {
		return nil
	}

	redirectURIs := []string{}
	if uri := cmd.String("client-redirect-uri"); uri != "" {
		redirectURIs = append(redirectURIs, uri)
	}

	return []server.OAuthClient{
		{
			ID:           clientID,
			Secret:       cmd.String("client-secret"),
			RedirectURIs: redirectURIs,
		},
	}
}
