package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"

	_ "github.com/koalatea/authserver/server/ent/runtime"
	"go.opentelemetry.io/otel"

	_ "github.com/mattn/go-sqlite3"
)

func init() {
	configureLogging()
}

func main() {
	ctx := context.Background()

	// Initialize Tracing
	// TODO Need to figure out how to configure tracing
	exp, err := newGRPCExporter(ctx)
	// TODO Need to figure out when to do trackes local
	// f, err := os.Create("traces.txt")
	// if err != nil {
	// 	log.Fatalf("Failed to open traces.txt for tracing: %v", err)
	// }
	// defer f.Close()
	// exp, err := newTXTExporter(f)
	if err != nil {
		log.Fatalf("Failed to initialize tracing exporter: %v", err)
	}
	tp := newTraceProvider(exp)
	defer func() { _ = tp.Shutdown(ctx) }()
	slog.InfoContext(ctx, "Starting tracing")
	otel.SetTracerProvider(tp)

	// Run AuthServer
	server, err := newServer(ctx, configureFromFile("server/nopush/config.json"))
	if err != nil {
		log.Fatalf("AuthServer failed to initialize: %v", err)
	}
	if err := server.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("AuthServer fatal error: %v", err)
	}
}
