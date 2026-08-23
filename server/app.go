package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	altsrc "github.com/urfave/cli-altsrc/v3"
	jsonaltsrc "github.com/urfave/cli-altsrc/v3/json"
	cli "github.com/urfave/cli/v3"
	"go.opentelemetry.io/otel"
)

func init() {
	configureLogging()
}

func newApp(ctx context.Context) (app *cli.Command) {
	var configFilePath string

	jsonSourcer := altsrc.NewStringPtrSourcer(&configFilePath)

	jsonValSrc := func(keyPath string) cli.ValueSource {
		return jsonaltsrc.JSON(keyPath, jsonSourcer)
	}

	app = &cli.Command{
		Name:    "AuthServer",
		Usage:   "A simple authentication server",
		Version: Version,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runServer(ctx, cmd)
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Aliases:     []string{"c"},
				Usage:       "path to JSON config file",
				Destination: &configFilePath,
				Sources:     cli.EnvVars("AUTH_CONFIG", "CONFIG_FILE"),
			},
			&cli.StringFlag{
				Name:    "ca",
				Usage:   "Certificate Authority certificate string or path",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_CA"), jsonValSrc("certificates.ca")),
			},
			&cli.StringFlag{
				Name:    "ca-priv-key",
				Usage:   "Certificate Authority private key string or path",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_CA_PRIV_KEY"), jsonValSrc("certificates.ca_priv_key")),
			},
			&cli.StringFlag{
				Name:    "client-id",
				Usage:   "OAuth Client ID",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_CLIENT_ID"), jsonValSrc("oauth.client_id")),
			},
			&cli.StringFlag{
				Name:    "secret-key",
				Usage:   "OAuth Secret Key",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_SECRET_KEY"), jsonValSrc("oauth.secret_key")),
			},
			&cli.StringFlag{
				Name:    "client-id-file",
				Usage:   "Path to file containing OAuth Client ID",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_CLIENT_ID_FILE"), jsonValSrc("oauth.client_id_file")),
			},
			&cli.StringFlag{
				Name:    "secret-key-file",
				Usage:   "Path to file containing OAuth Secret Key",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_SECRET_KEY_FILE"), jsonValSrc("oauth.secret_key_file")),
			},
			&cli.BoolFlag{
				Name:    "enable-pprof",
				Usage:   "Enable performance profiling (pprof)",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_ENABLE_PPROF"), jsonValSrc("enable_pprof")),
			},
			&cli.BoolFlag{
				Name:    "bypass-auth",
				Usage:   "Bypass authentication requirements",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_BYPASS_AUTH"), jsonValSrc("bypass_auth")),
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			if cmd.IsSet("config") {
				if _, err := os.Stat(configFilePath); err != nil {
					return ctx, fmt.Errorf("config file '%s' not found: %w", configFilePath, err)
				}
			} else if configFilePath == "" {
				defaultPath := "server/nopush/config.json"
				if _, err := os.Stat(defaultPath); err == nil {
					configFilePath = defaultPath
				}
			}
			return ctx, nil
		},
	}
	return app
}

func runServer(ctx context.Context, cmd *cli.Command) error {
	// Initialize Tracing
	exp, err := newGRPCExporter(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize tracing exporter: %v", err)
	}
	tp := newTraceProvider(exp)
	defer func() { _ = tp.Shutdown(ctx) }()
	slog.InfoContext(ctx, "Starting tracing")
	otel.SetTracerProvider(tp)

	// Run AuthServer
	server, err := newServer(ctx, ConfigureFromCLI(cmd))
	if err != nil {
		log.Fatalf("AuthServer failed to initialize: %v", err)
	}
	if err := server.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("AuthServer fatal error: %v", err)
	}

	return nil
}
