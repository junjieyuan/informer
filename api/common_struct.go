package api

import "junjie.pro/informer/pkg/library"

var (
	SuccessMessage        = Message{Message: "success"}
	NotLoggedInMessage    = Message{Message: "not logged in"}
	DataNotCorrectMessage = Message{Message: "data not correctly"}
)

type Message struct {
	Message string `json:"message"`
}

type PrimaryKeys struct {
	PrimaryKey []string `json:"primaryKey"`
	Key        string   `json:"key"`
}

type PrimaryKeyWithSecures struct {
	PrimaryKey string                `json:"primaryKey"`
	Key        string                `json:"key"`
	Secures    []library.SecureStore `json:"secure"`
}

type PasswordBundle struct {
	OldPassword     string `json:"oldPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}
