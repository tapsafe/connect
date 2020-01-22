// Package connect partially Implements OpenID Connect Core 1.0 over OAuth 2.0 (RFC6749).
//
// You need to provide an implementation of the actual authentication.
//
// We only implement enough to securely use the "Authorization Code Flow" to obtain the initial "id_token".
// We additionally do this in a stateless manor to ease deployment.
//
package connect

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/tapsafe/connect/crypto"
)

var key crypto.Key
var host string

type webFingerLinkJSON struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type webFingerJSON struct {
	Subject string              `json:"subject"`
	Links   []webFingerLinkJSON `json:"links"`
}

type authorizationServerMetadataJSON struct {
	Issuer                            string   `json:"issuer"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	JWKsURI                           string   `json:"jwks_uri"`
	ServiceDocumentation              string   `json:"service_documentation"`
}

type registrationRequestJSON struct {
	RedirectURIS []string `json:"redirect_uris"`
}

type errorJSON struct {
	E string `json:"error"`
}

type registrationResponseJSON struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type tokenJSON struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

type idTokenJSON struct {
	Iss string `json:"iis"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

type jsonWebKeyEd25519 struct {
	KeyType   string `json:"kty"`
	Use       string `json:"sig"`
	Curve     string `json:"crv"`
	PublicKey string `json:"x"`
}

// Implementation supplies the callback to do the authentication.
//
// Auth receives the pre-validated authentication request and should authenticate the subject.
// To indicate a successful authentication return a non-empty string identifying the subject.
type Implementation interface {
	Auth(w http.ResponseWriter, r *http.Request, host string, redirectURI url.URL, state string) (string, error)
}

// ListenAndServe creates HTTP server on given addr which partially Implements OpenID Connect Core 1.0 over OAuth 2.0 (RFC6749).
//
//  curl http://localhost:3000/?resource=acct%3Ajoe%40example.com
//  curl http://localhost:3000/.well-known/oauth-authorization-server
//  curl http://localhost:3000/jwks.json
//  curl -d '{"redirect_uris": ["https://example.com"]}' http://localhost:3000/register
//  curl "http://localhost:3000/auth?redirect_uri=https://example.com&response_type=code&scope=openid&client_id={{ client_id }}&state={{ state }}"
//  curl -d "redirect_uri=https://example.com&code={{ code }}&grant_type=authorization_code" http://{{ client_id }}:{{ client_secret }}@localhost:3000/token
func ListenAndServe(keyData []byte, hostname string, addr string, implementation Implementation) error {
	host = hostname
	key.Load(keyData)
	http.HandleFunc("/.well-known/webfinger", handleFinger)
	http.HandleFunc("/.well-known/oauth-authorization-server", handleAuthorizationServerMetadata)
	http.HandleFunc("/.well-known/openid-configuration", handleAuthorizationServerMetadata)
	http.HandleFunc("/jwks.json", handleJWKS)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/auth", handleAuth(implementation))
	http.HandleFunc("/token", handleToken)
	return http.ListenAndServe(addr, nil)
}

// OpenID Connect Discovery 1.0 Endpoint (using RFC7033).
func handleFinger(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, &webFingerJSON{
		r.FormValue("resource"),
		[]webFingerLinkJSON{
			webFingerLinkJSON{
				"http://openid.net/specs/connect/1.0/issuer",
				host,
			},
		},
	})
}

// RFC8414 OAuth 2.0 Authorization Server Metadata.
func handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, &authorizationServerMetadataJSON{
		host,
		host + "/register",
		host + "/auth",
		[]string{"code"},
		[]string{"openid"},
		host + "/token",
		[]string{"client_secret_basic"},
		[]string{"authorization_code"},
		[]string{"EdDSA"},
		host + "/jwks.json",
		"https://godoc.org/github.com/tapsafe/connect",
	})
}

// RFC7591 OAuth 2.0 Dynamic Client Registration endpoint.
func handleRegister(w http.ResponseWriter, r *http.Request) {
	nopeHeaders(w)
	if "https://"+r.Host != host && "http://"+r.Host != host {
		log.Println("Invalid HOST header", r.Host)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var request registrationRequestJSON
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(request.RedirectURIS) != 1 {
		JSONError(w, http.StatusBadRequest, "invalid_redirect_uri", "Must supply a single `redirect_uri` starting with `https://`.")
		return
	}
	redirectURI, err := url.ParseRequestURI(request.RedirectURIS[0])
	if err != nil || redirectURI.Scheme != "https" {
		JSONError(w, http.StatusBadRequest, "invalid_request", "Must supply a single `redirect_uri` starting with `https://`.")
		return
	}
	reg, err := handleRegisterImpl(redirectURI)
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	js, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

// RFC7517 JSON Web Key (JWK).
func handleJWKS(w http.ResponseWriter, r *http.Request) {
	js, err := json.MarshalIndent(&jsonWebKeyEd25519{
		"OKP",
		"sig",
		"Ed25519",
		base64.RawURLEncoding.EncodeToString(key.Public()),
	}, "", "  ")
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func handleRegisterImpl(redirectURI *url.URL) (*registrationResponseJSON, error) {
	clientID, err := key.SignWithSalt([]byte(redirectURI.String()[8:]))
	if err != nil {
		return nil, err
	}
	clientSecret := key.Sign(clientID)
	return &registrationResponseJSON{
		base64.RawURLEncoding.EncodeToString(clientID),
		base64.RawURLEncoding.EncodeToString(clientSecret),
	}, nil
}

// OpenID Connect Core 1.0 Authentication endpoint.
func handleAuth(implementation Implementation) func(http.ResponseWriter, *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		nopeHeaders(w)
		if "https://"+r.Host != host && "http://"+r.Host != host {
			log.Println("Invalid HOST header", r.Host)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		redirectURI, err := url.ParseRequestURI(r.FormValue("redirect_uri"))
		if err != nil || redirectURI.Scheme != "https" {
			http.Error(w, "Must supply a `redirect_uri` starting with `https://`.", http.StatusBadRequest)
			return
		}
		clientID, err := validateClientID(r.FormValue("client_id"), *redirectURI)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		state := r.FormValue("state")
		if state == "" {
			RedirectError(w, r, *redirectURI, "", "invalid_request", "state must be supplied")
			return
		}
		if r.FormValue("response_type") != "code" {
			RedirectError(w, r, *redirectURI, state, "unsupported_response_type", "response_type must equal 'code'")
			return
		}
		if r.FormValue("scope") != "openid" {
			RedirectError(w, r, *redirectURI, state, "invalid_scope", "scope must equal 'openid'")
			return
		}
		uniqueID, err := implementation.Auth(w, r, host, *redirectURI, state)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if uniqueID == "" {
			return
		}
		code, err := handleAuthImpl(clientID, uniqueID, redirectURI)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		query := redirectURI.Query()
		query.Add("code", base64.RawURLEncoding.EncodeToString(code))
		query.Add("state", state)
		redirectURI.RawQuery = query.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
	}
}

func handleAuthImpl(clientID []byte, uniqueID string, redirectURI *url.URL) ([]byte, error) {
	subjectID := createsubjectID(uniqueID, []byte(redirectURI.String()))
	clientSecret := key.Sign(clientID)
	var secret crypto.Secret
	err := secret.Load(clientSecret[:32])
	if err != nil {
		return nil, err
	}
	now, err := time.Now().MarshalBinary()
	if err != nil {
		return nil, err
	}
	subjectID = append(subjectID, now...)
	return secret.Encrypt(subjectID)
}

// OpenID Connect Core 1.0 Token Endpoint.
func handleToken(w http.ResponseWriter, r *http.Request) {
	nopeHeaders(w)
	if "https://"+r.Host != host && "http://"+r.Host != host {
		log.Println("Invalid HOST header", r.Host)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if r.PostFormValue("grant_type") != "authorization_code" {
		JSONError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be 'authorization_code'")
		return
	}
	redirectURI, err := url.ParseRequestURI(r.PostFormValue("redirect_uri"))
	if err != nil {
		log.Println(err)
		JSONError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	clientIDBase64, clientSecretBase64, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="OAuth2", charset="UTF-8"`)
		http.Error(w, "Please authenticate", http.StatusUnauthorized)
		return
	}
	clientID, err := validateClientID(clientIDBase64, *redirectURI)
	if err != nil {
		log.Println(err)
		JSONError(w, http.StatusBadRequest, "invalid_client", "")
		return
	}
	clientSecret, err := validateClientSecret(clientID, clientSecretBase64)
	if err != nil {
		log.Println(err)
		JSONError(w, http.StatusBadRequest, "invalid_client", "")
		return
	}
	code, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("code"))
	if err != nil {
		log.Println(err)
		JSONError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	reg, err := handleTokenImpl(code, clientID, clientSecret)
	if err != nil {
		log.Println(err)
		JSONError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	js, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func handleTokenImpl(code []byte, clientID []byte, clientSecret []byte) (*tokenJSON, error) {
	var secret crypto.Secret
	err := secret.Load(clientSecret[:32])
	if err != nil {
		return nil, err
	}
	subjectID, err := secret.Decrypt(code)
	if err != nil {
		return nil, err
	}
	var signedAt time.Time
	err = signedAt.UnmarshalBinary(subjectID[len(subjectID)-15:])
	if err != nil {
		return nil, err
	}
	if !signedAt.Before(time.Now()) {
		return nil, errors.New("Signed in future")
	}
	if signedAt.Before(time.Now().Add(-time.Minute)) {
		return nil, errors.New("Signed too long ago")
	}
	jwtJs, err := jwt(subjectID[:len(subjectID)-15], clientID)

	return &tokenJSON{
		"FAKE", // We don't authenticate anything beyond OpenID
		"Bearer",
		0,
		*jwtJs,
	}, nil
}

// Hash a password for a given `uniqueID` and `redirect_uri` with our `privateKey` as a pepper.
func createsubjectID(uniqueID string, redirectURI []byte) []byte {
	// This is not as good as a random salt but we need determinisum
	return crypto.KeyDerivation([]byte(uniqueID), key.Sign(redirectURI))
}

// Verify that `client_id` is our signature of the salted `redirect_uri` i.e. they are a matching pair created by us.
func validateClientID(clientIDBase64 string, redirectURI url.URL) ([]byte, error) {
	clientID, err := base64.RawURLEncoding.DecodeString(clientIDBase64)
	if err != nil || len(clientID) != 96 {
		log.Println(err, "client_id base64 length wrong")
		clientID = make([]byte, 96)
	}
	return clientID, key.ValidateWithSalt([]byte(redirectURI.String())[8:], clientID)
}

// Verify that `client_secret` is our signature of `client_id` i.e. they are a matching pair created by us.
func validateClientSecret(clientID []byte, clientSecretBase64 string) ([]byte, error) {
	clientSecret, err := base64.RawURLEncoding.DecodeString(clientSecretBase64)
	if err != nil || len(clientSecret) != 64 {
		log.Println(err, "client_id base64 length wrong")
		clientID = make([]byte, 64)
	}
	return clientSecret, key.Validate(clientID, clientSecret)
}

// Write a HTTP response containing JSON.
func writeJSON(w http.ResponseWriter, data interface{}) {
	writeJSONWithType(w, data, "application/json")
}

// Write a HTTP response container JSON and a custom Content-Type header.
func writeJSONWithType(w http.ResponseWriter, data interface{}, contentType string) {
	js, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(js)
}

// JSONError implements the RFC6749 specified error reporting as JSON.
func JSONError(w http.ResponseWriter, status int, e string, desc string) {
	w.WriteHeader(status)
	writeJSON(w, errorJSON{e})
}

// RedirectError implements the RFC6749 specified error reporting to `redirect_uri`.
func RedirectError(w http.ResponseWriter, r *http.Request, u url.URL, state string, e string, desc string) {
	query := u.Query()
	query.Add("error", e)
	query.Add("error_description", desc)
	query.Add("state", state)
	u.RawQuery = query.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// Generate a signed OpenID id_token JWT RFC7519.
func jwt(subjectID []byte, clientID []byte) (*string, error) {
	header := []byte("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}")
	payload := idTokenJSON{
		host,
		base64.RawURLEncoding.EncodeToString(subjectID),
		base64.RawURLEncoding.EncodeToString(clientID),
		time.Now().Unix() + 300,
		time.Now().Unix(),
	}
	js, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	jwt := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(js)
	sig := key.Sign([]byte(jwt))
	jwt += "."
	jwt += base64.RawURLEncoding.EncodeToString(sig)
	return &jwt, nil
}

// Use set standard/convention headers to a secure option.
func nopeHeaders(w http.ResponseWriter) {
	// You need an SSL terminating proxy in-front of this app which should also add the
	// Strict-Transport-Security and Except-CT headers
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
