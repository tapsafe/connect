package connect

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestListenAndServe(t *testing.T) {
}
func TestJSONError(t *testing.T) {
	expected := `{
  "error": "e"
}`
	w := httptest.NewRecorder()
	JSONError(w, 500, "e", "desc")
	result := w.Result()
	if result.StatusCode != 500 {
		t.Error("Wrong status", result.StatusCode)
	}
	if strings.Compare(w.Body.String(), expected) != 0 {
		t.Error("Body", string(w.Body.String()), "!=", expected)
	}
}
func TestRedirectError(t *testing.T) {
	expected := "https://example.com/redirect?error=e&error_description=desc&state=none"
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	u, _ := url.Parse("https://example.com/redirect")
	RedirectError(w, r, *u, "none", "e", "desc")
	result := w.Result()
	if strings.Compare(result.Header["Location"][0], expected) != 0 {
		t.Error("Redirect", result, "!=", expected)
	}
}
