package cryptow

import (
	"log"
	"testing"
)

func TestAsymmetric(t *testing.T) {
	privKey, err := GenerateAsymKeyPair(4096)
	if err != nil {
		t.Error(err)
	}
	pubKey := &PubKey{Key: &privKey.Key.PublicKey}

	plaintext := "exampleplaintext"
	encrypted, err := pubKey.Encrypt([]byte(plaintext))
	log.Println("encrypted", string(encrypted))
	if err != nil {
		t.Error(err)
	}
	decrypted, err := privKey.Decrypt(encrypted)
	if err != nil {
		t.Error(err)
	}
	log.Println("decrypted", string(decrypted))
	if plaintext != string(decrypted) {
		t.Errorf("plaintext != decrypted")
	}
}
