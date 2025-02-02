package main

import (
	"io"
	"log/slog"
	"os"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
)

var tracer = otel.Tracer("authserver")

func newExporter(w io.Writer) (sdktrace.SpanExporter, error) {
	return stdouttrace.New(
		stdouttrace.WithWriter(w),
		// Use human-readable output.
		stdouttrace.WithPrettyPrint(),
		// Do not print timestamps for the demo.
		stdouttrace.WithoutTimestamps(),
	)
}

func newTraceProvider(exp sdktrace.SpanExporter) *sdktrace.TracerProvider {
	// Ensure default SDK resources and the required service name are set.
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("authserver"),
		),
	)

	if err != nil {
		panic(err)
	}

	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	)
}

var GlobalInstanceID = uuid.New()

func configureLogging() {
	// Use instance ID as prefix (helps in deployments with multiple instances)
	var (
		logger *slog.Logger
	)

	level := "debug"
	// Setup Default Logger
	if level != "debug" {
		// Production Logging
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})).
			With("authserver_id", GlobalInstanceID)
	} else {
		// Debug Logging
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		})).
			With("authserver_id", GlobalInstanceID)
	}

	slog.SetDefault(logger)
	slog.Debug("Debug logging enabled")
}
