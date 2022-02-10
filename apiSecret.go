package cryptow

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
)

type APISecret string

func NewAPISecret() (APISecret, error) {
	b, err := RandBytesString(128, "base64")
	if err != nil {
		return "", err
	}
	return APISecret(b), nil
}

func (as APISecret) GetSign(message []byte) ([]byte, error) {
	mac := hmac.New(sha512.New, []byte(as))
	mac.Write(message)
	return mac.Sum(nil), nil
}

func (as APISecret) ValidateMessage(sign []byte, message []byte) error {
	expectedSign, err := as.GetSign(message)
	if err != nil {
		return err
	}
	equal := hmac.Equal(sign, expectedSign)
	if equal {
		return nil
	}
	return fmt.Errorf("wrong sign")
}
