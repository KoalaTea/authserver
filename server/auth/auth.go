package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/koalatea/authserver/server/ent"
	"github.com/koalatea/authserver/server/ent/user"
	"github.com/koalatea/authserver/server/oauthclient"
)

// TODO: add unauthenticated handler to force admin user

// ErrInvalidViewer occurs when an invalid type of viewer is retrieved from the context.
// ErrNoViewer occurs when no viewer can be retrieved from the context.
var (
	ErrInvalidViewer = fmt.Errorf("invalid viewer kind in context")
	ErrNoViewer      = fmt.Errorf("no authenticated viewer context")
)

// Viewer describes the query/mutation viewer-context.
type Viewer interface{}

type ctxKey struct{}

// FromContext returns the Viewer stored in a context.
func FromContext(ctx context.Context) Viewer {
	v, _ := ctx.Value(ctxKey{}).(Viewer)
	return v
}

// UserFromContext returns an User viewer from a context.
// If the viewer was not a user, returns an error.
func UserFromContext(ctx context.Context) (*ent.User, error) {
	v := FromContext(ctx)
	if v == nil {
		return &ent.User{}, ErrNoViewer
	}

	user, ok := v.(*ent.User)
	if !ok {
		return &ent.User{}, ErrInvalidViewer
	}
	return user, nil
}

// NewContext returns a copy of parent context with the given Viewer attached with it.
func NewContext(parent context.Context, v Viewer) context.Context {
	return context.WithValue(parent, ctxKey{}, v)
}

func HandleUser(client *ent.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessCookie, err := r.Cookie(oauthclient.SessionCookieName)
			if err != nil {
				fmt.Printf("Errored getting the auth cookie from request: %s\n", err)
				// TODO return 401 here? redirect to auth maybe with a way back?
				next.ServeHTTP(w, r)
				return
			}
			sess := sessCookie.Value
			// sess := "123"
			u, err := client.User.Query().Where(user.SessionToken(sess)).Only(r.Context())
			if err != nil { // user doesnt exist
				fmt.Printf("NO USER\n")
				fmt.Printf("error getting user %s\n", err)
				next.ServeHTTP(w, r)
				return
			}
			fmt.Printf("USER\n")
			rWithUser := r.WithContext(NewContext(r.Context(), u))
			next.ServeHTTP(w, rWithUser)
		})
	}
}
