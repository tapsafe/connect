// Package crypto provides an easy interface to cutting-edge cryptographic functions with sensable defaults.
package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/ed25519"
)

var randRead = rand.Read

// Key implements PKI signing using Ed25519/EdDSA/RFC8032.
type Key struct {
	key ed25519.PrivateKey
}

// Load a raw private `key`; must be 32 bytes of random.
func (k *Key) Load(key []byte) {
	k.key = ed25519.NewKeyFromSeed(key[:])
}

// Public key.
func (k *Key) Public() []byte {
	return k.key.Public().(ed25519.PublicKey)
}

// Sign generates detached signature of `msg`.
func (k *Key) Sign(msg []byte) []byte {
	return ed25519.Sign(k.key, msg)[:]
}

// Validate detached `sig` is for `msg`.
func (k *Key) Validate(msg []byte, sig []byte) error {
	if !ed25519.Verify(k.key.Public().(ed25519.PublicKey), msg, sig) {
		return errors.New("Signature invalid")
	}
	return nil
}

// SignWithSalt generates detached signature of `msg` with an extra salt.
func (k *Key) SignWithSalt(msg []byte) ([]byte, error) {
	clientIDSalt := make([]byte, 32)
	_, err := randRead(clientIDSalt)
	if err != nil {
		return nil, err
	}
	msg = append(msg, clientIDSalt...)
	sig := k.Sign(msg)
	sig = append(sig, clientIDSalt...)
	return sig, nil
}

// ValidateWithSalt validates detached salted `sig` is for `msg`.
func (k *Key) ValidateWithSalt(msg []byte, sig []byte) error {
	msg = append(msg, sig[64:]...)
	sig = sig[:64]
	return k.Validate(msg, sig)
}
