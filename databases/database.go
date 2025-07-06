package databases

import (
	"errors"
	"fmt"

	"github.com/pouriyahmn/funcs"
)

//	type LoginAdapter interface {
//		CheckLogin(claimedUser ClaimedUser, w http.ResponseWriter) (error, *ClaimedDatabase)
//		GetRoleLogin(claimedDatabase *ClaimedDatabase, w http.ResponseWriter) error
//	}
type ClaimedUser struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}

// ////////////////////////////////////////////////////////////////////////////

type SignInRepository interface {
	CheckUserByName(name string) error
	InsertUser(user User) error
}
type SignInBusinessLogic struct {
	SignIn SignInRepository
}

func NewSignInBusinessLogic(repo SignInRepository) SignInBusinessLogic {
	return SignInBusinessLogic{
		SignIn: repo,
	}
}
func (b *SignInBusinessLogic) SignUp(username, password string, user User) error {
	err := b.SignIn.CheckUserByName(username)
	fmt.Println("err is: ", err)
	if err != nil {
		fmt.Println("error has returned again")
		return err
	}

	fmt.Println(user)
	err = b.SignIn.InsertUser(user)
	if err != nil {
		panic(err)
	}
	return nil

}

type LoginRepository interface {
	CheckUserByUsernameAndPassword(username, password string) (interface{}, error)
	GetRoleById(id interface{}) ([]string, error)
}
type LoginBussinessLogic struct {
	Logic LoginRepository
}

func NewLoginBussinessLogic(l LoginRepository) LoginBussinessLogic {
	return LoginBussinessLogic{Logic: l}
}
func (l LoginBussinessLogic) Login(username, password string) (string, error) {

	id, err := l.Logic.CheckUserByUsernameAndPassword(username, password)
	if err != nil {
		fmt.Println("user not found database")
		fmt.Println(err)
		return "", errors.New("user not found")
	}
	var roleSlice []string
	roleSlice, err = l.Logic.GetRoleById(id)
	fmt.Println("role slice: ", roleSlice)
	if err != nil {
		fmt.Println("roleslice err")
		return "", errors.New("user not found")
	}
	token := funcs.GenerateJWT(id, username, roleSlice)
	fmt.Println("token: ", token)

	return token, nil
}
