package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOpenIDConnect_Auth(t *testing.T) {
	openid := &openIDConnect{}
	u, _ := url.Parse("https://example.com/redirect")

	r := httptest.NewRequest("OPTIONS", "/", nil)
	w := httptest.NewRecorder()
	_, err := openid.Auth(w, r, "https://example.com", *u, "none")
	if err == nil {
		t.Error("Allowed OPTIONS")
	}

	r = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()
	_, err = openid.Auth(w, r, "https://example.com", *u, "none")
	if err != nil {
		t.Error(err)
	}

	r = httptest.NewRequest("POST", "/", nil)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	r.Header.Set("Origin", "https://foo.example.com")
	redirect(t, r, "https://example.com/redirect?error=access_denied&error_description=Unmatched+Origin&state=none")

	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Referer", "https://foo.example.com")
	redirect(t, r, "https://example.com/redirect?error=access_denied&error_description=Unmatched+Referer&state=none")

	r.Header.Set("Referer", "https://example.com")
	r.AddCookie(&http.Cookie{Name: "__Host-state", Value: "bad"})
	redirect(t, r, "https://example.com/redirect?error=access_denied&error_description=Unmatched+Cookie&state=none")

	r = httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Referer", "https://example.com")
	r.AddCookie(&http.Cookie{Name: "__Host-state", Value: base64.RawURLEncoding.EncodeToString([]byte("none"))})
	redirect(t, r, "https://example.com/redirect?error=access_denied&error_description=Unmatched+form+state&state=none")

	data := url.Values{}
	data.Set("login", "foo")
	data.Set("password", "bar")
	data.Set("form_state", base64.RawURLEncoding.EncodeToString([]byte("none")))
	r = httptest.NewRequest("POST", "/", strings.NewReader(data.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Referer", "https://example.com")
	r.AddCookie(&http.Cookie{Name: "__Host-state", Value: base64.RawURLEncoding.EncodeToString([]byte("none"))})

	w = httptest.NewRecorder()
	ret, _ := openid.Auth(w, r, "https://example.com", *u, "none")
	if ret != "foobar" {
		t.Error("Unexpected return", ret)
	}
}

func redirect(t *testing.T, r *http.Request, expected string) {
	openid := &openIDConnect{}
	u, _ := url.Parse("https://example.com/redirect")
	w := httptest.NewRecorder()
	openid.Auth(w, r, "https://example.com", *u, "none")
	result := w.Result()
	if strings.Compare(result.Header["Location"][0], expected) != 0 {
		t.Error("Redirect", result, "!=", expected)
	}
}
