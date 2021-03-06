package cryptow

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
)

func Sha256String(in string) string {
	sum := sha256.Sum256([]byte(in))
	return hex.EncodeToString(sum[:])
}

func Sha512String(in string) string {
	sum := sha512.Sum512([]byte(in))
	return hex.EncodeToString(sum[:])
}

func RandBytesString(size int, base string) (string, error) {
	token := make([]byte, size)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	if base == "base64" {
		return base64.StdEncoding.EncodeToString(token), nil
	}
	if base == "base32" {
		return base32.StdEncoding.EncodeToString(token), nil
	}
	return hex.EncodeToString(token), nil
}
