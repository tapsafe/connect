package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOpenIDConnect_Auth(t *testing.T) {
	openid := &openIDConnect{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	u, _ := url.Parse("http://example.com/redirect")
	openid.Auth(w, r, "example.com", *u, "none")
	result := w.Result()
	if strings.Compare(result.Header["Www-Authenticate"][0], `Basic realm="http://example.com/redirect", charset="UTF-8"`) != 0 {
		t.Error("Dose not ask for authentication", result)
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth("foo", "bar")
	ret, _ := openid.Auth(w, r, "example.com", *u, "none")
	if ret != "foobar" {
		t.Error("Unexpected return", ret)
	}
}
