package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type Lesson struct {
	Unit         int    `json:"unit,omitempty"`
	Name         string `json:"name"`
	Tname        string `json:"tname,omitempty"`
	Id           int    `json:"id,omitempty"`
	ClassId      int    `json:"classId,omitempty"`
	Class        int    `json:"class"`
	Capacity     int    `json:"capacity,omitempty"`
	LeftCapacity int    `json:"leftCapacity,omitempty"`
	Time         string `json:"time"`
	Mark         *int   `json:"mark,omitempty"`
}
type contextKey string

const userIDKey contextKey = "userID"

func connectDB() (*sql.DB, error) {
	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASS")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	name := os.Getenv("DB_NAME")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", user, pass, host, port, name)
	return sql.Open("mysql", dsn)
}

func main() {

	db, err := connectDB()
	if err != nil {
		fmt.Println("Error connecting to DB:", err)
		panic(err)
	}

	defer db.Close()
	err = db.Ping()
	if err != nil {
		fmt.Println("Error connecting to DB:", err)
		panic(err)
	}
	fmt.Println("hello world!")
	fmt.Println("Connection to database successfully")
	http.HandleFunc("/signup", signUp)
	http.HandleFunc("/login", login)
	http.HandleFunc("/delete", jwtMiddleware(deleteRow))
	http.HandleFunc("/show", jwtMiddleware(uploadData))
	http.HandleFunc("/submit", jwtMiddleware(getHandler))
	http.HandleFunc("/showProfessors", jwtMiddleware(showProfessors))
	http.HandleFunc("/showAll", jwtMiddleware(showAll))
	http.HandleFunc("/showUserRoled", jwtMiddleware(showUserRoled))
	http.HandleFunc("/addProfessor", jwtMiddleware(addProfessor))
	http.HandleFunc("/addStudent", jwtMiddleware(addStudent))
	http.HandleFunc("/delProfessor", jwtMiddleware(delProfessor))
	http.HandleFunc("/insertLesson", jwtMiddleware(insertLesson))
	http.HandleFunc("/delLesson", jwtMiddleware(delLesson))
	http.HandleFunc("/showLesson", jwtMiddleware(showLesson))
	http.HandleFunc("/showUnits", jwtMiddleware2(uploadData))
	http.HandleFunc("/add", jwtMiddleware2(add))
	http.HandleFunc("/pickedUnits", jwtMiddleware2(uploadDataForStudents))
	http.HandleFunc("/delStudentUnit", jwtMiddleware2(delStudentUnit))
	http.HandleFunc("/showStudentForProfessor", jwtMiddleware3(showStudentForProfessor))
	http.HandleFunc("/addMark", jwtMiddleware3(addMark))
	err = http.ListenAndServe(":9001", nil)
	if err != nil {
		panic(err)
	}
}
func getHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		var lesson Lesson

		err := json.NewDecoder(r.Body).Decode(&lesson)
		if err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}
		fmt.Println("Received Lesson:", lesson)

		db, err := connectDB()
		if err != nil {
			http.Error(w, "Database connection failed", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		// professorRow := db.QueryRow("SELECT professor_name FROM professors where professor_name = ?", lesson.Tname)
		// var professorName string
		// err = professorRow.Scan(&professorName)
		// var professorId int64
		// if err != nil {
		// 	res, err := db.Exec("INSERT INTO professors(`professor_name`) VALUES (?)", lesson.Tname)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	professorId, _ = res.LastInsertId()
		// } else {
		// 	professorRow := db.QueryRow("SELECT professor_id FROM professors where professor_name = ?", lesson.Tname)
		// 	err = professorRow.Scan(&professorId)
		// 	if err != nil {
		// 		panic(err)
		// 	}

		// }
		// lessonRow := db.QueryRow("SELECT lesson_name FROM lessons where lesson_name = ?", lesson.Name)
		// var lessonName string
		// var lessonId int64
		// err = lessonRow.Scan(&lessonName)
		// fmt.Println("lessonName is: ", lessonName)
		// if err != nil {

		// 	res2, err := db.Exec("INSERT INTO lessons(`lesson_name`,`lesson_unit`,`professor_id`) VALUES (?,?,?)", lesson.Name, lesson.Unit, professorId)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	lessonId, _ = res2.LastInsertId()

		// } else {

		// 	lessonRow := db.QueryRow("SELECT lesson_id FROM lessons where lesson_name = ?", lesson.Name)
		// 	err = lessonRow.Scan(&lessonId)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// }
		fmt.Println("lesson: ", lesson)

		var professorId int
		professorRow := db.QueryRow("SELECT user_roles.user_id FROM user_roles INNER JOIN users ON user_roles.user_id=users.ID where users.username = ?", lesson.Tname)
		err = professorRow.Scan(&professorId)
		if err != nil {
			panic(err)
		}
		var lessonId int
		lessonRow := db.QueryRow("SELECT lesson_id FROM lessons where lesson_name = ?", lesson.Name)
		err = lessonRow.Scan(&lessonId)
		if err != nil {
			panic(err)
		}

		_, err = db.Exec("INSERT INTO classes(`lesson_id`,`professor_id`,`class_number`,`capacity`,`class_time`)VALUES(?,?,?,?,?)", lessonId, professorId, lesson.Class, lesson.Capacity, lesson.Time)
		if err != nil {
			panic(err)
		}
	}

}

func uploadData(w http.ResponseWriter, r *http.Request) {

	if r.Method == "GET" {

		var lessonSlice []Lesson

		db, err := connectDB()
		if err != nil {
			panic(err)
		}
		defer db.Close()
		var registered int

		rows, err := db.Query("SELECT `lesson_unit`,`lesson_name`,`username`,`class_id`,`class_number`,`capacity`,`class_time` FROM classes_view LIMIT 100")
		if err != nil {
			panic(err)

		}
		defer rows.Close()
		var lesson2 Lesson
		for rows.Next() {

			err = rows.Scan(&lesson2.Unit, &lesson2.Name, &lesson2.Tname, &lesson2.Id, &lesson2.Class, &lesson2.Capacity, &lesson2.Time)
			if err != nil {
				panic(err)
			}
			err = db.QueryRow("SELECT COUNT(*) FROM users_classes WHERE class_id = ?", lesson2.Id).Scan(&registered)
			if err != nil {
				panic(err)
			}
			fmt.Println("class id: ", lesson2.Id)
			lesson2.LeftCapacity = lesson2.Capacity - registered
			if lesson2.LeftCapacity == 0 {
				lesson2.LeftCapacity = -1
			}
			fmt.Println("org:  ", lesson2.Capacity)
			fmt.Println("left: ", lesson2.LeftCapacity)
			fmt.Println("reg: ", registered)
			fmt.Println("reg: ", lesson2)
			if lesson2.LeftCapacity == 0 {
				fmt.Println("full")

			}

			lessonSlice = append(lessonSlice, lesson2)
			fmt.Println(lessonSlice)
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(lessonSlice)
		if err != nil {
			panic(err)
		}
	}

}
func deleteRow(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Access-Control-Allow-Origin", "*")              // اجازه درخواست از همه دامنه‌ها
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, POST") // مجاز بودن متدهای POST و OPTIONS
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")  // مجاز بودن هدر Content-Type
	if r.Method == "POST" {
		db, err := connectDB()
		if err != nil {
			panic(err)
		}
		defer db.Close()
		var lesson Lesson
		err = json.NewDecoder(r.Body).Decode(&lesson)
		if err != nil {
			panic(err)
		}
		fmt.Println("id is:", lesson.Id)

		stmt, err := db.Prepare("DELETE FROM classes WHERE class_id = ?")
		if err != nil {
			panic(err)
		}
		defer stmt.Close()
		_, err = stmt.Exec(lesson.Id)
		if err != nil {
			panic(err)
		}

	}
}

type User struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	StudentRole   bool   `json:"studentRole"`
	ProfessorRole bool   `json:"professorRole"`
}

func signUp(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Access-Control-Allow-Origin", "*")              // اجازه درخواست از همه دامنه‌ها
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS") // مجاز بودن متدهای POST و OPTIONS
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")  // مجاز بودن هدر Content-Type
	if r.Method == "POST" {
		db, err := connectDB()
		if err != nil {
			panic(err)

		}
		defer db.Close()

		var user User
		err = json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			panic(err)
		}

		var usernames []string
		var username string

		if isValidPassword(user.Password) {
			fmt.Println("valid")
		} else {
			http.Error(w, "invalid password", http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		rows, err := db.Query("SELECT username FROM users")
		if err != nil {
			panic(err)
		}
		defer rows.Close()

		for rows.Next() {
			err = rows.Scan(&username)
			if err != nil {
				panic(err)
			}
			usernames = append(usernames, username)
		}
		for _, v := range usernames {
			if v == user.Username {
				http.Error(w, "Username already exists", http.StatusConflict)
				return
			}
		}

		stmt, err := db.Prepare("INSERT INTO users(`username`,`password`,`claim_student`,`claim_professor`) VALUES (?,?,?,?)")
		if err != nil {
			panic(err)
		}
		_, err = stmt.Exec(user.Username, hashedPassword, user.StudentRole, user.ProfessorRole)
		if err != nil {
			panic(err)
		}
		// row := db.QueryRow("SELECT ID FROM users WHERE username = ?", user.Username)
		// err = row.Scan(&id)
		// if err != nil {
		// 	panic(err)
		// }
		// fmt.Println("user role is: ", user.ProfessorRole)
		// stmt, err = db.Prepare("INSERT INTO users(`claim_student`,`claim_professor`) VALUES (?,?)")
		// if err != nil {
		// 	panic(err)
		// }
		// _, err = stmt.Exec(user.StudentRole, user.ProfessorRole)
		// if err != nil {
		// 	panic(err)
		// }
		w.WriteHeader(http.StatusOK)
	}
}

var jwtkey = []byte("secret-key")

type Claims struct {
	Username string   `json:"username"`
	Role     []string `json:"role"`
	Id       int      `json:"id"`
	jwt.StandardClaims
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // یا * برای همه دامنه‌ها
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// پاسخ به preflight (OPTIONS)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == "POST" {
		db, err := connectDB()
		if err != nil {
			panic(err)
		}
		defer db.Close()
		type ClaimedUser struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		var claimedUser ClaimedUser
		err = json.NewDecoder(r.Body).Decode(&claimedUser)
		if err != nil {
			panic(err)
		}
		fmt.Println("username : ", claimedUser.Username)
		row := db.QueryRow("SELECT username,password,ID FROM users WHERE username = ?", claimedUser.Username)

		var usernamedb, passworddb string
		var id int
		var role int
		var roleSlice []string
		err = row.Scan(&usernamedb, &passworddb, &id)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
		rows, err := db.Query("SELECT role_id FROM user_roles where user_id = ?", id)
		if err != nil {
			panic(err)
		}
		for rows.Next() {
			err = rows.Scan(&role)
			if err != nil {
				http.Error(w, "not allowed yet", http.StatusForbidden)
			}
			roleSlice = append(roleSlice, strconv.Itoa(role))
		}
		fmt.Println("role: ", role)
		err = bcrypt.CompareHashAndPassword([]byte(passworddb), []byte(claimedUser.Password))
		if err != nil {
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}
		if len(roleSlice) == 0 {
			roleSlice = []string{}
		}

		expireTime := time.Now().Add(time.Minute * 5)
		claims := &Claims{
			Username: usernamedb,
			Role:     roleSlice,
			Id:       id,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expireTime.Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtkey)
		if err != nil {
			panic(err)
		}

		fmt.Println("redirected")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
		if err != nil {
			panic(err)
		}

	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}

}

func add(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var lesson Lesson
	var registered, capacity int
	err := json.NewDecoder(r.Body).Decode(&lesson)
	if err != nil {
		log.Println("JSON decode error:", err)
		http.Error(w, "Bad Request", 400)
		return
	}

	userID := r.Context().Value(userIDKey).(int)

	db, err := connectDB()
	if err != nil {
		log.Println("DB connection error:", err)
		http.Error(w, "DB Connection Error", 500)
		return
	}
	defer db.Close()
	err = db.QueryRow("SELECT COUNT(*) FROM users_classes WHERE class_id = ?", lesson.Id).Scan(&registered)
	if err != nil {
		panic(err)
	}

	err = db.QueryRow("SELECT capacity FROM classes WHERE class_id = ?", lesson.Id).Scan(&capacity)
	if err != nil {
		panic(err)
	}

	if capacity-registered == 0 {

		return
	}
	row, err := db.Query("SELECT `class_id`FROM users_classes WHERE `user_class_id` = ?", userID)
	if err != nil {
		panic(err)
	}
	defer row.Close()
	var id int

	var lessonId []int
	for row.Next() {
		err = row.Scan(&id)
		if err != nil {
			break
		}
		lessonId = append(lessonId, id)

	}
	fmt.Println(lessonId)
	for _, v := range lessonId {
		if v == lesson.Id {
			return
		}
	}
	// if capacity == 0 {
	// 	return
	// }
	// stmt2, err := db.Prepare("UPDATE classes SET capacity = ? WHERE class_id = ?")
	// if err != nil {
	// 	panic(err)
	// }
	// _, err = stmt2.Exec(capacity-1, lesson.Id)
	// if err != nil {
	// 	panic(err)
	// }

	_, err = db.Exec("INSERT INTO users_classes(`user_class_id`,`class_id`) VALUE (?,?)", userID, lesson.Id)
	if err != nil {
		panic(err)
	}

}
func uploadDataForStudents(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	db, err := connectDB()
	if err != nil {
		log.Println("DB connection error:", err)
		http.Error(w, "DB Connection Error", 500)
		return
	}
	defer db.Close()
	userID := r.Context().Value(userIDKey).(int)
	rows, err := db.Query("SELECT `lesson_unit`,`lesson_name`,`username`,`class_id`,`class_number`,`capacity`,`class_time`,`mark`FROM users_classes_view WHERE user_class_id = ?", userID)
	if err != nil {
		log.Println("Prepare statement error:", err)
		http.Error(w, "DB Error", 500)
		return
	}
	defer rows.Close()
	var lesson []Lesson

	var registered int

	for rows.Next() {
		var lesson2 Lesson
		err = rows.Scan(&lesson2.Unit, &lesson2.Name, &lesson2.Tname, &lesson2.Id, &lesson2.Class, &lesson2.Capacity, &lesson2.Time, &lesson2.Mark)

		if err != nil {
			log.Println("scan statement error: ", err)
			http.Error(w, "DB error", 500)
			return
		}
		err = db.QueryRow("SELECT COUNT(*) FROM users_classes WHERE class_id = ?", lesson2.Id).Scan(&registered)
		if err != nil {
			panic(err)
		}
		lesson2.LeftCapacity = lesson2.Capacity - registered
		if lesson2.LeftCapacity == 0 {
			lesson2.LeftCapacity = -1
		}
		lesson = append(lesson, lesson2)

	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(lesson)
	if err != nil {
		panic(err)
	}

}
func delStudentUnit(w http.ResponseWriter, r *http.Request) {
	type DeleteRequest struct {
		Id int `json:"id"`
	}

	userID := r.Context().Value(userIDKey).(int)
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	db, err := connectDB()
	if err != nil {
		log.Println("DB connection error:", err)
		http.Error(w, "DB Connection Error", 500)
		return
	}
	defer db.Close()
	var lesson DeleteRequest
	err = json.NewDecoder(r.Body).Decode(&lesson)
	fmt.Println(lesson.Id)
	if err != nil {
		panic(err)
	}

	stmt, err := db.Prepare("DELETE FROM users_classes WHERE class_id = ? AND user_class_id = ?")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(lesson.Id, userID)
	if err != nil {
		panic(err)
	}
	// row := db.QueryRow("SELECT capacity FROM classes WHERE class_id = ?", lesson.Id)

	// err = row.Scan(&capacity)
	// if err != nil {
	// 	panic(err)
	// }
	// stmt, err = db.Prepare("UPDATE classes SET capacity = ? WHERE class_id = ?")
	// if err != nil {
	// 	panic(err)
	// }
	// _, err = stmt.Exec(capacity+1, lesson.Id)
	// if err != nil {
	// 	panic(err)
	// }
}
func showProfessors(w http.ResponseWriter, r *http.Request) {
	type Professor struct {
		Name string `json:"name"`
		Id   int    `json:"id"`
	}
	var professor Professor
	var professorSlice []Professor
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection failed", http.StatusInternalServerError)
		return
	}
	defer db.Close()
	rows, err := db.Query("SELECT users.username,user_roles.user_id FROM user_roles INNER JOIN users ON user_roles.user_id=users.ID WHERE user_roles.role_id = ?", 3)
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		err = rows.Scan(&professor.Name, &professor.Id)
		if err != nil {
			panic(err)
		}
		professorSlice = append(professorSlice, professor)

	}
	err = json.NewEncoder(w).Encode(professorSlice)
	if err != nil {
		panic(err)
	}

}
func addProfessor(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	type ProfessorRequest struct {
		Id int `json:"id"`
	}
	var roleId int
	var professor ProfessorRequest

	err := json.NewDecoder(r.Body).Decode(&professor)
	if err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection failed", http.StatusInternalServerError)
		return
	}
	defer db.Close()
	rows, err := db.Query("SELECT role_id FROM user_roles WHERE user_id = ?", professor.Id)
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		err = rows.Scan(&roleId)
		if err != nil {
			panic(err)
		}
		if roleId == 3 {
			return
		}
	}

	// var professorName string
	// res := db.QueryRow("SELECT username FROM users WHERE ID = ?", professor.Id)
	// err = res.Scan(&professorName)
	// if err != nil {
	// 	http.Error(w, "User not found", http.StatusNotFound)
	// 	return
	// }

	_, err = db.Exec("INSERT INTO user_roles(user_id,role_id) VALUES (?, ?)", professor.Id, 3)
	if err != nil {
		http.Error(w, "Failed to insert professor", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Professor added successfully")
}
func addStudent(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	type studentRequest struct {
		Id int `json:"id"`
	}
	var roleId int
	var student studentRequest

	err := json.NewDecoder(r.Body).Decode(&student)
	if err != nil {
		// http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		// return
		panic(err)
	}

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection failed", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT role_id FROM user_roles WHERE user_id = ?", student.Id)
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		err = rows.Scan(&roleId)
		if err != nil {
			panic(err)
		}
		if roleId == 2 {
			return
		}
	}

	_, err = db.Exec("INSERT INTO user_roles(user_id,role_id) VALUES (?, ?)", student.Id, 2)
	if err != nil {
		//	http.Error(w, "Failed to insert professor", http.StatusInternalServerError)
		panic(err)

	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Professor added successfully")

}

func delProfessor(w http.ResponseWriter, r *http.Request) {

	var professor users
	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection failed", http.StatusInternalServerError)
		return
	}
	defer db.Close()
	err = json.NewDecoder(r.Body).Decode(&professor)
	if err != nil {
		panic(err)
	}
	stmt, err := db.Prepare("DELETE FROM user_roles WHERE id = ? ")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(professor.Id)
	if err != nil {
		panic(err)
	}

}

type users struct {
	Name   string `json:"name"`
	Id     int    `json:"id"`
	RoleId int    `json:"roleId,omitempty"`
}

func showUserRoled(w http.ResponseWriter, r *http.Request) {
	var user users
	var userSlise []users
	var userSearch string
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	db, err := connectDB()
	if err != nil {
		panic(err)

	}
	err = json.NewDecoder(r.Body).Decode(&userSearch)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	row, err := db.Query("SELECT users.username,user_roles.id,user_roles.role_id FROM user_roles INNER JOIN users ON user_roles.user_id=users.ID WHERE users.username LIKE ?", "%"+userSearch+"%")
	if err != nil {
		panic(err)
	}

	for row.Next() {
		err = row.Scan(&user.Name, &user.Id, &user.RoleId)
		if err != nil {
			panic(err)
		}
		userSlise = append(userSlise, user)
	}
	err = json.NewEncoder(w).Encode(userSlise)
	if err != nil {
		panic(err)
	}

}

func showAll(w http.ResponseWriter, r *http.Request) {
	type users struct {
		Id             int    `json:"id"`
		Username       string `json:"name"`
		ClaimStudent   bool   `json:"claimStudent"`
		ClaimProfessor bool   `json:"claimProfessor"`
	}
	var user users
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	db, err := connectDB()
	if err != nil {
		panic(err)

	}
	defer db.Close()
	var userSearch string
	var userSlice []users
	err = json.NewDecoder(r.Body).Decode(&userSearch)
	if err != nil {
		panic(err)
	}
	// 	rows, err := db.Query(`SELECT u.ID, u.username
	// FROM users u
	// JOIN user_roles ur ON u.ID = ur.user_id
	// WHERE ur.role_id = 3;`)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	rows, err := db.Query("SELECT username,claim_student,claim_professor,ID FROM users WHERE username LIKE ?", "%"+userSearch+"%")
	if err != nil {
		panic(err)
	}
	// err = rows.Scan(&user.Username, &user.ClaimStudent, &user.ClaimProfessor, &user.Id)
	// if err != nil {
	// 	panic(err)
	// }

	defer rows.Close()

	for rows.Next() {

		// err = rows.Scan(&professor.Id, &professor.Name)
		// if err != nil {
		// 	panic(err)
		// }
		err = rows.Scan(&user.Username, &user.ClaimStudent, &user.ClaimProfessor, &user.Id)
		if err != nil {
			panic(err)
		}

		userSlice = append(userSlice, user)

	}
	err = json.NewEncoder(w).Encode(userSlice)
	if err != nil {
		panic(err)
	}
}

type LessonN struct {
	LessonName string `json:"lessonName"`
	LessonUnit int    `json:"lessonUnit,omitempty"`
	Id         int    `json:"id,omitempty"`
}

func showLesson(w http.ResponseWriter, r *http.Request) {
	var lesson LessonN
	var lessonSlice []LessonN
	db, err := connectDB()
	if err != nil {
		panic(err)

	}
	defer db.Close()
	row, err := db.Query("SELECT lesson_id,lesson_name FROM lessons")
	if err != nil {
		panic(err)
	}

	for row.Next() {
		err = row.Scan(&lesson.Id, &lesson.LessonName)
		if err != nil {
			panic(err)
		}
		lessonSlice = append(lessonSlice, lesson)
	}
	err = json.NewEncoder(w).Encode(lessonSlice)
	if err != nil {
		panic(err)
	}

}
func insertLesson(w http.ResponseWriter, r *http.Request) {

	var lesson LessonN
	db, err := connectDB()
	if err != nil {
		panic(err)

	}
	defer db.Close()
	err = json.NewDecoder(r.Body).Decode(&lesson)
	fmt.Println("lessonName: ", lesson.LessonName, "lessonUnit: ", lesson.LessonUnit)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("INSERT INTO lessons(lesson_name,lesson_unit) VALUES (?,?)", lesson.LessonName, lesson.LessonUnit)
	if err != nil {
		panic(err)
	}
}
func delLesson(w http.ResponseWriter, r *http.Request) {
	var lesson LessonN
	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection failed", http.StatusInternalServerError)
		return
	}
	defer db.Close()
	err = json.NewDecoder(r.Body).Decode(&lesson)
	if err != nil {
		panic(err)
	}
	stmt, err := db.Prepare("DELETE FROM lessons WHERE lesson_name = ?")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(lesson.LessonName)
	if err != nil {
		panic(err)
	}
}
func showStudentForProfessor(w http.ResponseWriter, r *http.Request) {
	var lesson Lesson
	var lessonSlice []Lesson

	userID := r.Context().Value(userIDKey).(int)
	var professorName string
	db, err := connectDB()
	if err != nil {
		panic(err)

	}
	defer db.Close()
	row := db.QueryRow("SELECT username FROM users WHERE ID = ?", userID)

	err = row.Scan(&professorName)
	if err != nil {
		panic(err)
	}
	fmt.Println("professorName", professorName)
	fmt.Println("userId", userID)
	rows, err := db.Query(`SELECT 
		u.username,
		
		v.lesson_name,
		
		v.class_number,
		
		v.class_time,
		v.user_class_id,
		v.class_id,
		v.mark
	FROM 
		hellodb.users_classes_view v
	JOIN 
		hellodb.users u ON v.user_class_id = u.id
		WHERE 
    v.username = ?`, professorName)
	if err != nil {
		panic(err)
	}

	for rows.Next() {

		err = rows.Scan(&lesson.Tname, &lesson.Name, &lesson.Class, &lesson.Time, &lesson.ClassId, &lesson.Id, &lesson.Mark)
		if err != nil {
			panic(err)
		}

		lessonSlice = append(lessonSlice, lesson)
	}

	fmt.Println(lessonSlice)
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(lessonSlice)
	if err != nil {
		panic(err)
	}

}
func addMark(w http.ResponseWriter, r *http.Request) {
	var lesson Lesson
	db, err := connectDB()
	if err != nil {
		panic(err)

	}
	defer db.Close()
	err = json.NewDecoder(r.Body).Decode(&lesson)
	if err != nil {
		panic(err)
	}
	var markValue interface{}
	if lesson.Mark != nil {
		markValue = *lesson.Mark
	} else {
		markValue = nil
	}
	_, err = db.Exec(`UPDATE users_classes SET mark = ? WHERE user_class_id = ? AND class_id = ?`, markValue, lesson.ClassId, lesson.Id)
	if err != nil {
		http.Error(w, "failed to update mark", http.StatusInternalServerError)
		return
	}
	fmt.Println("mark: ", markValue, "id: ", lesson.Id, "   ", lesson.ClassId)
}
func jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// پاسخ به preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return

		}

		// توکن چک کردن
		authHeader := r.Header.Get("Authorization")
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtkey, nil
		})
		fmt.Println("token is: ", tokenStr)
		if err != nil || !tkn.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		valid := false
		for _, v := range claims.Role {
			if v == "1" {
				valid = true

			}

		}
		if !valid {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// اگه همه چیز اوکی بود، بره سراغ هندلر اصلی
		next(w, r)
	}
}
func jwtMiddleware2(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// پاسخ به preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return

		}

		// توکن چک کردن
		authHeader := r.Header.Get("Authorization")
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtkey, nil
		})
		fmt.Println("token is: ", tokenStr)
		if err != nil || !tkn.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Println("claimedrole: ", claims.Role)
		valid := false
		for _, v := range claims.Role {
			if v == "2" {
				valid = true

			}

		}
		if !valid {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// اگه همه چیز اوکی بود، بره سراغ هندلر اصلی
		//next(w, r)

		ctx := context.WithValue(r.Context(), userIDKey, claims.Id)
		next.ServeHTTP(w, r.WithContext(ctx))

	}
}

func jwtMiddleware3(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// پاسخ به preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return

		}

		// توکن چک کردن
		authHeader := r.Header.Get("Authorization")
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtkey, nil
		})
		fmt.Println("token is: ", tokenStr)
		if err != nil || !tkn.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Println("claimedrole: ", claims.Role)
		valid := false
		for _, v := range claims.Role {
			if v == "3" {
				valid = true

			}

		}
		if !valid {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, claims.Id)
		next.ServeHTTP(w, r.WithContext(ctx))

	}
}

func isValidPassword(password string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9]{6,}$`)
	return re.MatchString(password)
}
