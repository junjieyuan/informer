package otp

import (
	"github.com/pquerna/otp/totp"
	"log"
	"time"
)

// GenerateTotpPassCode Generate Time-based One-Time Password by otpSecret
func GenerateTotpPassCode(otpSecret string) string {
	passCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		log.Println(err.Error())
	}

	return passCode
}
