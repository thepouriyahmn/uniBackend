package databases

import "net/http"

type SignUpAdapter interface {
	CheckAndInsert(user User, w http.ResponseWriter) error
}
type LoginAdapter interface {
	CheckLogin(claimedUser ClaimedUser, w http.ResponseWriter) (error, *ClaimedDatabase)
	GetRoleLogin(claimedDatabase *ClaimedDatabase, w http.ResponseWriter) error
}
