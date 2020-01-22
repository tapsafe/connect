package crypto

import (
	"golang.org/x/crypto/argon2"
)

// KeyDerivation using Argon2.
func KeyDerivation(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, 3, 64*1024, 2, 32)
}
