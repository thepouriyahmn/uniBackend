package funcs

import (
	"regexp"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func IsValidPassword(password string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9]{6,}$`)
	return re.MatchString(password)
}
func GenerateJWT(id interface{}, username string, roleSlice []string) string {

	type Claims struct {
		Username string      `json:"username"`
		Role     []string    `json:"role"`
		Id       interface{} `json:"id"`
		jwt.StandardClaims
	}
	var jwtkey = []byte("secret-key")
	if len(roleSlice) == 0 {
		roleSlice = []string{}
	}

	expireTime := time.Now().Add(time.Minute * 5)
	claims := &Claims{
		Username: username,
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
	return tokenString
}
