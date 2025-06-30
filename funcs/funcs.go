package funcs

import "regexp"

func IsValidPassword(password string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9]{6,}$`)
	return re.MatchString(password)
}
