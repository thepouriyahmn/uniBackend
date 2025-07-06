package protocols

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/pouriyahmn/databases"
)

type WebSocket struct {
	SignUpLogic databases.SignInBusinessLogic
	LoginLogic  databases.LoginBussinessLogic
}

func NewWsProtocol() *WebSocket {
	return &WebSocket{}
}

func (l WebSocket) SignUpProtocol(user databases.User, w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}

	defer conn.Close()

	for {
		var msg map[string]interface{}
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println("WebSocket read error:", err)
			break
		}

		action, ok := msg["action"].(string)
		if !ok || action != "signup" {
			conn.WriteJSON(map[string]interface{}{
				"status":  "error",
				"message": "Invalid action",
			})
			continue
		}

		user.Username, _ = msg["username"].(string)
		user.Password, _ = msg["password"].(string)
		user.StudentRole, _ = msg["studentRole"].(bool)
		user.ProfessorRole, _ = msg["professorRole"].(bool)

		// 	rolesRaw, _ := msg["roles"].([]interface{})
		// //	var roles []string
		// 	for _, r := range rolesRaw {
		// 		if roleStr, ok := r.(string); ok {
		// 			user. = append(roles, roleStr)
		// 		}
		// 	}

		err = l.SignUpLogic.SignUp(user.Username, user.Password, user)
		if err != nil {

			conn.WriteJSON(map[string]interface{}{
				"status":  "unauthorized",
				"code":    401,
				"message": "Invalid credentials",
			})
			continue
		}

		conn.WriteJSON(map[string]interface{}{
			"status":  "ok",
			"message": "Signup successful",
		})
	}
}
func (l WebSocket) LoginProtocol(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}

	defer conn.Close()
	for {

		var msg map[string]interface{}
		err := conn.ReadJSON(&msg)
		if err != nil {
			break
		}

		username, _ := msg["username"].(string)
		password, _ := msg["password"].(string)

		token, err := l.LoginLogic.Login(username, password)

		if err != nil {
			conn.WriteJSON(map[string]interface{}{
				"status":  "unauthorized",
				"code":    401,
				"message": "Invalid credentials",
			})
			continue
		}
		fmt.Println("token is2: ", token)

		conn.WriteJSON(map[string]interface{}{
			"status":  "ok",
			"code":    200,
			"message": token,
		})
	}

}
