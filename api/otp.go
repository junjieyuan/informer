package api

import (
	"encoding/json"
	"github.com/pquerna/otp/totp"
	"junjie.pro/informer/conf"
	"junjie.pro/informer/library"
	"log"
	"net/http"
	"time"
)

func GeneratePassCode(w http.ResponseWriter, r *http.Request) {
	//Response message is json
	w.Header().Add("Content-Type", "application/json")

	//Read informer configurations
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		w.WriteHeader(500)
		log.Println(err)
	}

	//Read login token from cookie
	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err)
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err)
	}

	//Check user is already logged in whether
	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		err = json.NewEncoder(w).Encode(NotLoggedInMessage)
		if err != nil {
			log.Println(err)
		}

		return
	}

	//Read informer library
	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		log.Println(err.Error())
	}

	queryParams := r.URL.Query()
	if queryParams["key"] != nil && queryParams["key"][0] != "" {
		err = informerLibrary.Unlock([]byte(queryParams["key"][0]))
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(500)
			err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
			if err != nil {
				log.Println(err.Error())
			}

			return
		}
	}

	var otpSecret string
	if queryParams["primaryKey"] != nil && queryParams["primaryKey"][0] != "" {
		otpSecret = informerLibrary.SecureStore[queryParams["primaryKey"][0]].OTP
	} else {
		//TODO
		return
	}
	if otpSecret == "" {
		//TODO return 404 if otp secret is empty string
		return
	}

	passCode := generatePassCode(otpSecret)
	passCodeJson := OtpPassCode{PassCode: passCode}
	err = json.NewEncoder(w).Encode(passCodeJson)
	if err != nil {
		log.Println(err.Error())
	}
}

func generatePassCode(otpSecret string) string {
	passCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		log.Println(err.Error())
	}

	return passCode
}

type OtpPassCode struct {
	PassCode string `json:"pass_code"`
}
