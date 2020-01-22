// Command form runs connect with a HTTP Form Authentication backend.
//
//  Configuration environment variables:
//
//    URI
//        The publicly accessable URI for this service; must be https://
//    KEY
//        32 cryptographic random bytes as a Base64 Encoded string to seed the private key.
//
//        export KEY=`head -c ${CHARS:=32} /dev/random | base64`
package main

import (
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/tapsafe/connect"
)

type openIDConnect struct{}

var form *template.Template

func (*openIDConnect) Auth(w http.ResponseWriter, r *http.Request, host string, redirectURL url.URL, state string) (string, error) {
	safeState := base64.RawURLEncoding.EncodeToString([]byte(state))
	if r.Method == "GET" {
		if form == nil {
			var err error
			form, err = template.New("foo").Parse(`<!DOCTYPE html>
<html>
	<head>
		<title>Login to {{ .RedirectURL }}</title>
		<link rel="icon" href="data:,">
	</head>
	<body>
		<h1>Login to {{ .RedirectURL }}</h1>
		<form action="#" method="POST">
			<input type="hidden" name="form_state" value="{{ .SafeState }}">
			<input name="login" />
			<input type="password" name="password">
			<input type="submit" value="login">
		</form>
	</body>
</html>`)
			if err != nil {
				return "", err
			}
		}
		cookie := http.Cookie{Name: "__Host-state", Value: safeState, Secure: true, SameSite: http.SameSiteStrictMode, HttpOnly: true, Path: "/"}
		http.SetCookie(w, &cookie)
		err := form.Execute(
			w,
			struct {
				RedirectURL string
				SafeState   string
			}{
				redirectURL.String(),
				safeState,
			},
		)
		if err != nil {
			return "", err
		}
		return "", nil
	} else if r.Method == "POST" {
		if r.Header["Origin"][0] != host {
			connect.RedirectError(w, r, redirectURL, state, "access_denied", "Unmatched Origin")
			return "", nil
		}
		if !strings.HasPrefix(r.Header["Referer"][0], host) {
			connect.RedirectError(w, r, redirectURL, state, "access_denied", "Unmatched Referer")
			return "", nil
		}
		if !strings.HasPrefix(host, "http://") {
			// We assume http:// URLs are only for local testing and we can skip the cookie
			cookieState, err := r.Cookie("__Host-state")
			if err != nil || safeState != cookieState.Value {
				connect.RedirectError(w, r, redirectURL, state, "access_denied", "Unmatched Cookie")
				return "", nil
			}
		}
		if safeState != r.PostFormValue("form_state") {
			connect.RedirectError(w, r, redirectURL, state, "access_denied", "Unmatched form state")
			return "", nil
		}
		return r.PostFormValue("login") + r.PostFormValue("password"), nil
	}
	return "", errors.New("Unsupported method")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	key, err := base64.StdEncoding.DecodeString(os.Getenv("KEY"))
	if err != nil {
		log.Fatalln(err)
	}

	log.Fatal(connect.ListenAndServe(key, os.Getenv("URI"), ":3000", &openIDConnect{}))
}
