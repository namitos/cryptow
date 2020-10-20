package cryptow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

// GenerateAsymKeyPair generates a new key pair
func GenerateAsymKeyPair(bits int) (*PrivKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &PrivKey{Key: privkey}, nil
}

type PrivKeyBytes []byte

func (priv PrivKeyBytes) GetPrivKey() (*PrivKey, error) {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		log.Println("is encrypted pem block")
		b1, err := x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
		b = b1
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &PrivKey{Key: key}, nil
}

type PubKeyBytes []byte

func (pub PubKeyBytes) GetPubKey() (*PubKey, error) {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		log.Println("is encrypted pem block")
		b1, err := x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
		b = b1
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not ok")
	}
	return &PubKey{Key: key}, nil
}

type PrivKey struct {
	Key *rsa.PrivateKey
}

// Decrypt decrypts data with private key
func (priv *PrivKey) Decrypt(ciphertext []byte) ([]byte, error) {
	hash := sha1.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv.Key, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (priv *PrivKey) GetBytes() PrivKeyBytes {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv.Key),
		},
	)
}

type PubKey struct {
	Key *rsa.PublicKey
}

// Encrypt encrypts data with public key
func (pub *PubKey) Encrypt(msg []byte) ([]byte, error) {
	hash := sha1.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub.Key, msg, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (pub *PubKey) GetBytes() (PubKeyBytes, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub.Key)
	if err != nil {
		return nil, err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubBytes, nil
}
