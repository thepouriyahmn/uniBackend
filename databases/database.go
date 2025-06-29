package databases

import (
	"fmt"
	"net/http"
)

type LoginAdapter interface {
	CheckLogin(claimedUser ClaimedUser, w http.ResponseWriter) (error, *ClaimedDatabase)
	GetRoleLogin(claimedDatabase *ClaimedDatabase, w http.ResponseWriter) error
}

//////////////////////////////////////////////////////////////////////////////

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
	if err != nil {

		return err
	}

	fmt.Println(user)
	err = b.SignIn.InsertUser(user)
	if err != nil {
		panic(err)
	}
	return nil

}
