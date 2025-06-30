package protocols

import (
	"net/http"

	"github.com/pouriyahmn/databases"
)

type Protocol interface {
	SignUpProtocol(user databases.User, w http.ResponseWriter, r *http.Request)
}
