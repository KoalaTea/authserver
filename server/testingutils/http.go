package testingutils

import (
	"github.com/koalatea/authserver/server/ent"
	"github.com/koalatea/authserver/server/oauthclient"

	"net/http"
)

func AddUserAuthToRequest(r *http.Request, user *ent.User) {
	r.AddCookie(&http.Cookie{Name: oauthclient.SessionCookieName, Value: user.SessionToken})
}
