package api

var (
	SuccessMessage = Message{Message: "success"}
)

type Message struct {
	Message string `json:"message"`
}
