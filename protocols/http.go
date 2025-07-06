package protocols

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pouriyahmn/databases"
	"github.com/pouriyahmn/funcs"
)

type HttpProtocol struct {
	SignUpLogic databases.SignInBusinessLogic
	LoginLogic  databases.LoginBussinessLogic
}

func NewhttpProtocol() *HttpProtocol {
	return &HttpProtocol{}
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
		err = l.SignUpLogic.SignUp(user.Username, user.Password, user)
		if err != nil {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func (l HttpProtocol) LoginProtocol(w http.ResponseWriter, r *http.Request) {
	var claimedUser ClaimedUser
	err := json.NewDecoder(r.Body).Decode(&claimedUser)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	token, err := l.LoginLogic.Login(claimedUser.Username, claimedUser.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	err = json.NewEncoder(w).Encode(map[string]string{"token": token})
	if err != nil {
		panic(err)
	}

}
