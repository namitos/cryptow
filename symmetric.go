package cryptow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

//SymKey aes-gcm encryption abstraction
type SymKey []byte

func NewSymKey() (SymKey, error) {
	key := make([]byte, 32) //aes256
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (k SymKey) Encrypt(msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encrypted := aesgcm.Seal(nil, nonce, msg, nil)
	return append(nonce, encrypted...), nil
}

func (k SymKey) Decrypt(encrypted []byte) ([]byte, error) {
	nonce := encrypted[0:12]
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	msg, err := aesgcm.Open(nil, nonce, encrypted[12:len(encrypted)], nil)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
