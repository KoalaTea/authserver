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
	// run the auto migration tool.
	// if err := client.Schema.Create(context.Background()); err != nil {
	// 	log.Fatalf("failed creating schema resources: %v", err)
	// }

	_, err = createUser(context.Background(), client)
	if err != nil {
		log.Fatalf("failed to create user %v", err)
	}
}

func createUser(ctx context.Context, client *ent.Client) (*ent.User, error) {
	u, err := client.User.
		Create().
		SetUsername("a8m").
		SetPassword("a8m").
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed creating user: %v", err)
	}
	log.Println("user was created: ", u)
	return u, nil
}
