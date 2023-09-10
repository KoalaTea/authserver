package main

import (
	"context"
	"fmt"
	"log"

	"github.com/koalatea/authserver/server/ent"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// client, err := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	client, err := ent.Open("sqlite3", "file:test.sql?_fk=1")
	if err != nil {
		log.Fatalf("failed opening connection to sqlite: %v", err)
	}
	defer client.Close()

	err = queryUsers(context.Background(), client)
	if err != nil {
		log.Fatalf("failed to create user %v", err)
	}
}

func queryUsers(ctx context.Context, client *ent.Client) error {
	users, err := client.User.
		Query().All(ctx) // what happens with only and multiple exist?
	if err != nil {
		return fmt.Errorf("failed querying user: %v", err)
	}
	for _, u := range users {
		fmt.Printf("found user %s\n", u.Username)
	}
	return nil
}
