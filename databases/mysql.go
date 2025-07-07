package databases

import (
	"database/sql"
	"errors"
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

// //////\
type mysqladapter struct {
	db *sql.DB
}

func NewMysqlAdapter(dsn string) (mysqladapter, error) {

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return mysqladapter{}, err
	}
	return mysqladapter{db: db}, nil
}
func (m mysqladapter) CheckUserByName(username string) error {
	var userslice []string
	var user string
	rows, err := m.db.Query("SELECT username FROM users")
	if err != nil {
		panic(err)
	}
	for rows.Next() {
		err = rows.Scan(&user)
		if err != nil {
			panic(err)
		}
		userslice = append(userslice, user)

	}
	for _, v := range userslice {
		if v == username {
			return err
		}
	}
	return nil

}

func (m mysqladapter) InsertUser(user User) error {
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
func (m mysqladapter) CheckUserByUsernameAndPassword(username, password string) (interface{}, error) {
	var usernameDB, passwordDB, idDB string
	row := m.db.QueryRow("SELECT username,password,ID FROM users WHERE username = ?", username)
	err := row.Scan(&usernameDB, &passwordDB, &idDB)
	if err != nil {
		fmt.Printf("scan err: %v", err)
		return "", errors.New("username or password is incorrect")
	}
	err = bcrypt.CompareHashAndPassword([]byte(passwordDB), []byte(password))
	if err != nil {
		fmt.Printf("scan err: %v", err)
		return "", errors.New("username or password is incorrect")
	}
	return idDB, nil
}
func (m mysqladapter) GetRoleById(id interface{}) ([]string, error) {
	var roleslice []string
	var role string
	row, err := m.db.Query("SELECT role_id from user_roles where user_id = ?", id)
	if err != nil {
		return []string{}, errors.New("not found")
	}
	for row.Next() {
		err = row.Scan(&role)
		if err != nil {
			panic(err)
		}
		roleslice = append(roleslice, role)
	}
	return roleslice, nil
}
