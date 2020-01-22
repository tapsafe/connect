package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestKeyDerivation(t *testing.T) {
	start := time.Now()
	if len(KeyDerivation([]byte{}, []byte{})) != 32 {
		t.Error("Output should be 32 bytes")
	}
	if !bytes.Equal(KeyDerivation([]byte{1}, []byte{1}), KeyDerivation([]byte{1}, []byte{1})) {
		t.Error("Output should b deterministic")
	}
	if bytes.Equal(KeyDerivation([]byte{1}, []byte{1}), KeyDerivation([]byte{2}, []byte{1})) {
		t.Error("Output should vary with password")
	}
	if bytes.Equal(KeyDerivation([]byte{1}, []byte{1}), KeyDerivation([]byte{1}, []byte{2})) {
		t.Error("Output should vary with salt")
	}
	if bytes.Equal(KeyDerivation([]byte{2}, []byte{1}), KeyDerivation([]byte{1}, []byte{2})) {
		t.Error("Password and salt should not be interchangable")
	}
	if time.Since(start) < time.Second {
		t.Error("Execution too fast")
	}
}
