package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"

	_ "github.com/koalatea/authserver/server/ent/runtime"
	"github.com/urfave/cli/v3"
	"go.opentelemetry.io/otel"

	_ "github.com/mattn/go-sqlite3"
)

func init() {
	configureLogging()
}

func main() {
	ctx := context.Background()

	app := buildCLIApp(func(ctx context.Context, cmd *cli.Command) error {
		cfg, err := loadConfigFromCLI(cmd)
		if err != nil {
			return err
		}

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
		server, err := newServer(ctx, func(c *Config) {
			*c = *cfg
		})
		if err != nil {
			log.Fatalf("AuthServer failed to initialize: %v", err)
		}
		if err := server.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("AuthServer fatal error: %v", err)
		}
		return nil
	})

	if err := app.Run(ctx, os.Args); err != nil {
		log.Fatalf("Fatal error running CLI: %v", err)
	}
}
