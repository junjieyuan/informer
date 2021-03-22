package api

var (
	SuccessMessage        = Message{Message: "success"}
	NotLoggedInMessage    = Message{Message: "not logged in"}
	DataNotCorrectMessage = Message{Message: "data not correctly"}
)

type Message struct {
	Message string `json:"message"`
}
