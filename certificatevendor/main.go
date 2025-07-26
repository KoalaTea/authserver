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
		log.Fatalf("Failed to make server: %v", err)
	}
	if err := server.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("certificatevendor fatal error: %v", err)
	}
}
