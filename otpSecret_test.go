package cryptow

import (
	"log"
	"testing"
	"time"
)

func TestOTPSecret(t *testing.T) {
	OTPSecret, _ := NewOTPSecret()
	token, err := OTPSecret.GetHOTPToken(time.Now().UnixNano() / 1000000)
	if err != nil {
		t.Error(err)
	}
	log.Println(token)
}
