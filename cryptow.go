package cryptow

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
)

func RandBytesString(size, base int) (string, error) {
	token := make([]byte, size)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	if base == 32 {
		return base32.StdEncoding.EncodeToString(token), nil
	}
	return base64.StdEncoding.EncodeToString(token), nil
}
