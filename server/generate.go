package main

//go:generate go run -mod=mod ./ent/generate_code.go
//go:generate /bin/sh -c "cd ./graphql && go run -mod=mod github.com/99designs/gqlgen"
//go:generate /bin/sh -c "cat ./graphql/schema/* > internal/www/schema.graphql"
//go:generate /bin/sh -c "cd ./internal/www && npm run build"
