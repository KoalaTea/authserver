package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"

	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
)

var tracer = otel.Tracer("authserver")

// outputDir is the directory, relative to the working directory, for files the server creates on its own
const outputDir = ".authserver"

// openOutputFile opens path for appending, creating its parent directory if needed
func openOutputFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory for '%s': %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open '%s': %w", path, err)
	}
	return f, nil
}

// newTXTExporter writes spans to w as one JSON object per line
func newTXTExporter(w io.Writer) (sdktrace.SpanExporter, error) {
	return stdouttrace.New(
		stdouttrace.WithWriter(w),
	)
}

func newGRPCExporter(ctx context.Context) (*otlptrace.Exporter, error) {
	// Create the OTLP gRPC exporter pointing to Tempo
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint("192.168.10.45:4317"),
		// otlptracegrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())), // Tempo usually doesn't require TLS by default
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}
	return exporter, nil
}

func newTraceProvider(exporters ...sdktrace.SpanExporter) *sdktrace.TracerProvider {
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

	opts := []sdktrace.TracerProviderOption{sdktrace.WithResource(r)}
	for _, exp := range exporters {
		opts = append(opts, sdktrace.WithBatcher(exp))
	}
	return sdktrace.NewTracerProvider(opts...)
}

var GlobalInstanceID = uuid.New()

// logLevel controls the level of the default logger, defaults to info and can be changed at runtime via setLogLevel
var logLevel = new(slog.LevelVar)

// configureLogging sets the default logger to write JSON logs to w
func configureLogging(w io.Writer) {
	// Use instance ID as prefix (helps in deployments with multiple instances)
	logger := slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: logLevel,
	})).
		With("authserver_id", GlobalInstanceID)

	slog.SetDefault(logger)
}

// setLogLevel updates the level of the default logger, accepts debug, info, warn, or error (case insensitive)
func setLogLevel(level string) error {
	if err := logLevel.UnmarshalText([]byte(level)); err != nil {
		return fmt.Errorf("invalid log level '%s': %w", level, err)
	}
	slog.Debug("Debug logging enabled")
	return nil
}
