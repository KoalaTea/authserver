package testingutils

import (
	"github.com/koalatea/authserver/server/auth"
	"github.com/koalatea/authserver/server/ent"
	authserverHttp "github.com/koalatea/authserver/server/http"
	"github.com/koalatea/authserver/server/oauthclient"

	"net/http"
)

// I do not really want this. I would prefer it as just a tests function, move to a testing package I think
func NewRouter(rm authserverHttp.RouteMap, graph *ent.Client) *http.ServeMux {
	router := http.NewServeMux()
	for r, m := range rm {
		router.Handle(r, auth.HandleUser(graph)(m))
	}
	return router
}

func AddUserAuthToRequest(r *http.Request, user *ent.User) {
	r.AddCookie(&http.Cookie{Name: oauthclient.SessionCookieName, Value: user.SessionToken})
}
