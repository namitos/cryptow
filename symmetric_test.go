package cryptow

import (
	"reflect"
	"testing"
)

func TestSymmetric(t *testing.T) {
	symKey, err := NewSymKey()
	if err != nil {
		t.Error(err)
	}
	plaintext := []byte("exampleplaintext")

	encrypted, err := symKey.Encrypt(plaintext)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := symKey.Decrypt(encrypted)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Errorf("plaintext != decrypted")
	}
}
