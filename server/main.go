package main

import (
	"context"
	"log"
	"os"

	_ "github.com/koalatea/authserver/server/ent/runtime"

	_ "github.com/mattn/go-sqlite3"
	"go.opentelemetry.io/otel"
)

func main() {
	ctx := context.Background()

	// Initialize Tracing
	f, err := os.Create("traces.txt")
	if err != nil {
		log.Fatalf("Failed to open traces.txt for tracing: %v", err)
	}
	defer f.Close()
	exp, err := newExporter(f)
	if err != nil {
		log.Fatalf("Failed to initialize tracing exporter: %v", err)
	}
	tp := newTraceProvider(exp)
	defer func() { _ = tp.Shutdown(ctx) }()
	otel.SetTracerProvider(tp)

	// Run AuthServer
	server := newServer(ctx)
	log.Println("starting server")
	if err := server.Run(ctx); err != nil {
		log.Fatalf("server fatal error: %v", err)
	}
}
