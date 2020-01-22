package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// Secret implements symmetric encryption using AES GCM/RFC5288.
type Secret struct {
	secret cipher.AEAD
}

// Load a shared `secret`; should be 32 bytes.
func (s *Secret) Load(secret []byte) error {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return err
	}
	s.secret, err = cipher.NewGCM(block)
	return err
}

// Encrypt `msg`.
func (s *Secret) Encrypt(msg []byte) ([]byte, error) {
	nonce := make([]byte, s.secret.NonceSize())
	_, err := randRead(nonce)
	if err != nil {
		return nil, err
	}
	return s.secret.Seal(nonce, nonce, msg, nil), nil
}

// Decrypt `msg`.
func (s *Secret) Decrypt(msg []byte) ([]byte, error) {
	nonce := msg[:s.secret.NonceSize()]
	msg = msg[s.secret.NonceSize():]
	return s.secret.Open(nil, nonce, msg, nil)
}
