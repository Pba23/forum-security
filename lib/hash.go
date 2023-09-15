package lib

import "golang.org/x/crypto/bcrypt"

func HashPassword(pwd string) (string, error) {
	var pwdBytes = []byte(pwd)
	hashedPwd, err := bcrypt.GenerateFromPassword(pwdBytes, bcrypt.MinCost)
	return string(hashedPwd), err
}

func IsPasswordsMatch(hashedPwd, currentPwd string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(currentPwd))
	return err == nil
}
