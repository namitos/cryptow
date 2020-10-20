package cryptow

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
)

type APISecret string

func NewAPISecret() APISecret {
	b, _ := RandBytesString(128, 64)
	return APISecret(b)
}

func (as APISecret) GetSign(message []byte) ([]byte, error) {
	mac := hmac.New(sha512.New, []byte(as))
	mac.Write(message)
	return mac.Sum(nil), nil
}

func (as APISecret) ValidateMessage(sign []byte, message []byte) (bool, error) {
	expectedSign, err := as.GetSign(message)
	if err != nil {
		return false, err
	}
	equal := hmac.Equal(sign, expectedSign)
	if equal {
		return true, nil
	}
	return false, fmt.Errorf("wrong sign")
}
