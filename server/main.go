package main

import (
	"context"
	"log"
	"os"

	_ "github.com/koalatea/authserver/server/ent/runtime"

	_ "github.com/mattn/go-sqlite3"
)

func init() {
	configureLogging()
}

func main() {
	ctx := context.Background()

	app := newApp(ctx)

	if err := app.Run(ctx, os.Args); err != nil {
		log.Fatalf("Fatal error running CLI: %v", err)
	}
}
