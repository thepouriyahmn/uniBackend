package databases

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

type mysqlAdapter struct {
	db *sql.DB
}

func MysqlAdapter(dsn string) (*mysqlAdapter, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	return &mysqlAdapter{db: db}, nil
}
func (m *mysqlAdapter) CheckAndInsert(user User, w http.ResponseWriter) error {
	rows, err := m.db.Query("SELECT username FROM users")
	if err != nil {
		panic(err)
	}
	var username string
	var usernameSlice []string
	for rows.Next() {
		err = rows.Scan(&username)
		if err != nil {
			panic(err)
		}
		usernameSlice = append(usernameSlice, username)
	}
	for _, v := range usernameSlice {
		if v == user.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return err
		}
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	stmt, err := m.db.Prepare("INSERT INTO users(`username`,`password`,`claim_student`,`claim_professor`) VALUES (?,?,?,?)")
	if err != nil {
		panic(err)
	}
	_, err = stmt.Exec(user.Username, hashedPassword, user.StudentRole, user.ProfessorRole)
	if err != nil {
		panic(err)
	}
	return nil
}
func (m *mysqlAdapter) CheckLogin(claimedUser ClaimedUser, w http.ResponseWriter) (error, *ClaimedDatabase) {
	var (
		usernameDB string
		passwordDB string
		idDB       int
	)
	row := m.db.QueryRow("SELECT username,password,ID FROM users WHERE username = ?", claimedUser.Username)
	err := row.Scan(&usernameDB, &passwordDB, &idDB)
	if err != nil {
		fmt.Println("check login in")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return err, &ClaimedDatabase{}
	}

	claimedDatabase := &ClaimedDatabase{}
	claimedDatabase.Username = usernameDB
	claimedDatabase.Password = passwordDB
	claimedDatabase.Id = idDB

	return nil, claimedDatabase

}
func (m *mysqlAdapter) GetRoleLogin(claimedDatabase *ClaimedDatabase, w http.ResponseWriter) error {
	var (
		// usernameDB string
		// passwordDB string

		role int
	)
	idDB := claimedDatabase.Id
	var roleSlice []string
	rows, err := m.db.Query("SELECT role_id FROM user_roles where user_id = ?", idDB)
	if err != nil {
		panic(err)
	}
	fmt.Println("its working")
	for rows.Next() {
		err = rows.Scan(&role)
		if err != nil {

			http.Error(w, "not allowed yet", http.StatusForbidden)
		}
		fmt.Println("role is: ", role)
		roleSlice = append(roleSlice, strconv.Itoa(role))
	}
	claimedDatabase.Role = roleSlice
	return nil
}
