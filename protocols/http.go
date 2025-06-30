package protocols

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pouriyahmn/databases"
	"github.com/pouriyahmn/funcs"
)

type HttpProtocol struct {
	Logic databases.SignInBusinessLogic
}

func (l HttpProtocol) SignUpProtocol(user databases.User, w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {

		var user databases.User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			panic(err)
		}
		if funcs.IsValidPassword(user.Password) {
			fmt.Println("valid")
		} else {
			http.Error(w, "invalid password", http.StatusBadRequest)
			return
		}
		fmt.Println("recived: ", user)
		err = l.Logic.SignUp(user.Username, user.Password, user)
		if err != nil {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
