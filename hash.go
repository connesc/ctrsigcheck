package ctrsigcheck

import (
	"crypto/sha256"
)

func sha256Hash(payload []byte) []byte {
	hash := sha256.New()
	hash.Write(payload)
	return hash.Sum(nil)
}
