package main

import (
	"context"
	"errors"
	"log"
	"net/http"
)

func main() {
	ctx := context.Background()
	server, err := NewServer()
	if err != nil {
		log.Fatalf("Failed to initialize tracing exporter: %v", err)
	}
	if err := server.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("AuthServer fatal error: %v", err)
	}
}
