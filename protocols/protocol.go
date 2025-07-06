package protocols

import (
	"net/http"

	"github.com/pouriyahmn/databases"
)

type ClaimedUser struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}
type Protocol interface {
	SignUpProtocol(user databases.User, w http.ResponseWriter, r *http.Request)
	LoginProtocol(w http.ResponseWriter, r *http.Request)
}
