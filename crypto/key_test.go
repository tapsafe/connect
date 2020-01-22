package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func TestKey_LoadPanicShort(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Wrong length seed should panic")
		}
	}()
	var test Key
	test.Load([]byte{1, 2, 3, 4, 5, 6})
}

func TestKey_Load(t *testing.T) {
	testKey()
}

func TestKey_LoadPanicLong(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Wrong length seed should panic")
		}
	}()
	var test Key
	test.Load([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
}

func TestKey_Public(t *testing.T) {
	key := testKey()
	TestbinCheck(t, "Unexpected public key", key.Public(), "yZr_Znx1eAVr19RZDfkr8q4Qimp_M91SOEqDvzJfAmk")
}

func TestKey_Sign(t *testing.T) {
	key := testKey()
	msg := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	sig1 := key.Sign(msg)
	TestbinCheck(t, "Unexpected public key", sig1, "_3nA7lEXpI4JaI4GQIvqNgtHht5V53wyui6UiOPzBp_ce5piswWxuhr1sRZaSQZ0yBIpDvUQtvVzeoRKBM4-Dg")
	sig2 := key.Sign(msg)
	if !bytes.Equal(sig1, sig2) {
		t.Error("Sign not deterministic", sig1, "!=", sig2)
	}
	key.Load([]byte{1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1})
	sig3 := key.Sign(msg)
	if bytes.Equal(sig1, sig3) {
		t.Error("Sign not varying with key", sig1, "==", sig3)
	}
}

func TestKey_Validate(t *testing.T) {
	key := testKey()
	msg := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	if key.Validate(msg, key.Sign(msg)) != nil {
		t.Error("Round-trip mis-match")
	}
	if key.Validate(msg, key.Sign([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8})) == nil {
		t.Error("Truncated sig still valid")
	}
	if key.Validate(msg, key.Sign([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0})) == nil {
		t.Error("Trailling sig still valid")
	}
	if key.Validate([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, key.Sign(msg)) == nil {
		t.Error("Truncated msg still valid")
	}
	if key.Validate([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, key.Sign(msg)) == nil {
		t.Error("Trailling msg still valid")
	}
}

func badRandRead(b []byte) (int, error) {
	return 0, errors.New("Nope")
}

func TestKey_SignWithSalt(t *testing.T) {
	key := testKey()
	msg := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	sig1, _ := key.SignWithSalt(msg)
	sig2, _ := key.SignWithSalt(msg)
	if bytes.Equal(sig1, sig2) {
		t.Error("SignWithSalt deterministic", sig1, "==", sig2)
	}
	randRead = badRandRead
	_, err := key.SignWithSalt(msg)
	if err == nil {
		t.Error("No error if random fails")
	}
	randRead = rand.Read
}

func TestKey_ValidateWithSalt(t *testing.T) {
	key := testKey()
	msg := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	sig, _ := key.SignWithSalt(msg)
	if key.ValidateWithSalt(msg, sig) != nil {
		t.Error("Round-trip mis-match")
	}
}

func testKey() Key {
	var test Key
	test.Load([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1})
	return test
}
func TestbinCheck(t *testing.T, msg string, a []byte, b string) {
	valid, err := base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		t.Error("Bade Base64", b)
	}
	if !bytes.Equal(a, valid) {
		t.Error(msg, base64.RawURLEncoding.EncodeToString(a), "!=", b)
	}
}
