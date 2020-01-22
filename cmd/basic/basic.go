// Command basic runs connect with a HTTP Basic Authentication (RFC7617) backend.
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
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/tapsafe/connect"
)

type openIDConnect struct{}

func (*openIDConnect) Auth(w http.ResponseWriter, r *http.Request, host string, redirectURL url.URL, state string) (string, error) {
	subject, pass, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+redirectURL.String()+`", charset="UTF-8"`)
		http.Error(w, "Please authenticate", http.StatusUnauthorized)
		return "", nil
	}
	return subject + pass, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	key, err := base64.StdEncoding.DecodeString(os.Getenv("KEY"))
	if err != nil {
		log.Fatalln(err)
	}
	log.Fatal(connect.ListenAndServe(key, os.Getenv("URI"), ":3000", &openIDConnect{}))
}
