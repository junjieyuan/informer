package api

var (
	SuccessMessage = Message{Message: "success"}
	NotLoggedInMessage    = Message{Message: "not logged in"}
)

type Message struct {
	Message string `json:"message"`
}
