package main

import (
	// "context"
	"github.com/koalatea/authserver/pkg/server"
)

func main() {
	// ctx := context.Background()

	server := server.New()
	server.Run()
}