package api

import "math/rand"

var (
	lowerCase = "abcdefghijklmnopqrstuvwxyz"
	upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	number    = "0123456789"
	symbol    = "$&()*+[]@#^-_!?"

	passwordDict = lowerCase + upperCase + number + symbol
)

func GeneratePassword(length uint) string {
	var password string

	var i uint = 0
	for ; i < length; i++ {
		index := rand.Intn(len(passwordDict))
		password += string(passwordDict[index])
	}

	return password
}
