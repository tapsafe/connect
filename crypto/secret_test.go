package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSecret_Load(t *testing.T) {
	var test Secret
	err := test.Load([]byte{1, 2, 3, 4, 5, 6})
	if err == nil {
		t.Error("Wrong length seed should error")
	}
	err = test.Load([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	if err == nil {
		t.Error("Wrong length seed should error")
	}
	err = test.Load([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1})
	if err != nil {
		t.Error(err)
	}
}

func TestSecret_Encrypt(t *testing.T) {
	secret := testSecret()
	msg := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	box1, err := secret.Encrypt(msg)
	if err != nil {
		t.Error(err)
	}
	box2, err := secret.Encrypt(msg)
	if err != nil {
		t.Error(err)
	}
	if bytes.Equal(box1, box2) {
		t.Error("Encrypt deterministic", box1, "==", box2)
	}
	randRead = badRandRead
	_, err = secret.Encrypt(msg)
	if err == nil {
		t.Error("No error if random fails")
	}
	randRead = rand.Read
}

func TestSecret_Decrypt(t *testing.T) {
	secret := testSecret()
	msg := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	box1, err := secret.Encrypt(msg)
	if err != nil {
		t.Error(err)
	}
	msg1, err := secret.Decrypt(box1)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(msg, msg1) {
		t.Error("Encrypt non-round trip", msg, "!=", msg1)
	}
	box1 = append(box1, 1)
	msg1, err = secret.Decrypt(box1)
	if err == nil {
		t.Error("Trailing msg decoded")
	}
	box1 = box1[:len(box1)-2]
	msg1, err = secret.Decrypt(box1)
	if err == nil {
		t.Error("Truncated msg decoded")
	}
	box1, err = secret.Encrypt(msg)
	if err != nil {
		t.Error(err)
	}
	secret.Load([]byte{1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1})
	msg1, err = secret.Decrypt(box1)
	if err == nil {
		t.Error("msg decoded with wrong secret")
	}
}

func testSecret() Secret {
	var test Secret
	test.Load([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1})
	return test
}
