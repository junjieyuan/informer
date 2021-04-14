package api

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
)

var (
	lowerCase = "abcdefghijklmnopqrstuvwxyz"
	upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	number    = "0123456789"
	symbol    = "$&()*+[]@#^-_!?"

	passwordDict = lowerCase + upperCase + number + symbol
)

func GeneratePassword(w http.ResponseWriter, _ *http.Request) {
	//Response message is json
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)

	//Generate 16 characters password
	password := generatePassword(16)

	//Return generated password and success
	message := SinglePasswordWithMessage{Password: password, Message: "success"}

	err := json.NewEncoder(w).Encode(message)
	if err != nil {
		log.Println(err.Error())
	}
}

func generatePassword(length uint) string {
	var password string

	var i uint = 0
	for ; i < length; i++ {
		index := rand.Intn(len(passwordDict))
		password += string(passwordDict[index])
	}

	return password
}

type SinglePasswordWithMessage struct {
	Password string `json:"password"`
	Message  string `json:"message"`
}
