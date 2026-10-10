package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"

	altsrc "github.com/urfave/cli-altsrc/v3"
	jsonaltsrc "github.com/urfave/cli-altsrc/v3/json"
	validation "github.com/urfave/cli-validation"
	cli "github.com/urfave/cli/v3"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func init() {
	configureLogging(os.Stderr)
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
			&cli.StringFlag{
				Name:      "log-level",
				Usage:     "Log level (debug, info, warn, error)",
				Value:     "info",
				Validator: validation.Enum("debug", "info", "warn", "error"),
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_LOG_LEVEL"), jsonValSrc("logging.level")),
			},
			&cli.StringFlag{
				Name:    "log-file",
				Usage:   "File to write logs to in addition to stderr",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_LOG_FILE"), jsonValSrc("logging.file")),
			},
			&cli.StringFlag{
				Name:    "trace-file",
				Usage:   "File to write traces to",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_TRACE_FILE"), jsonValSrc("tracing.file")),
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
			logFile, err := openOptionalOutputFile(cmd, "log-file")
			if err != nil {
				return ctx, err
			}
			if logFile != nil {
				configureLogging(io.MultiWriter(os.Stderr, logFile))
			}
			if err := setLogLevel(cmd.String("log-level")); err != nil {
				return ctx, err
			}
			return ctx, nil
		},
	}
	return app
}

// openOptionalOutputFile opens the file named by the given flag, returning nil if the flag was not provided
func openOptionalOutputFile(cmd *cli.Command, flagName string) (*os.File, error) {
	path := cmd.String(flagName)
	if path == "" {
		return nil, nil
	}
	f, err := openOutputFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", flagName, err)
	}
	return f, nil
}

func runServer(ctx context.Context, cmd *cli.Command) error {
	// Initialize Tracing
	exp, err := newGRPCExporter(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize tracing exporter: %v", err)
	}
	exporters := []sdktrace.SpanExporter{exp}

	// Also write traces to the trace file
	traceFile, err := openOptionalOutputFile(cmd, "trace-file")
	if err != nil {
		return err
	}
	if traceFile != nil {
		defer traceFile.Close()
		txtExp, err := newTXTExporter(traceFile)
		if err != nil {
			log.Fatalf("Failed to initialize trace file exporter: %v", err)
		}
		exporters = append(exporters, txtExp)
	}

	tp := newTraceProvider(exporters...)
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
