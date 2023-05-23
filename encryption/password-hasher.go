package encryption

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type PasswordHasher struct {
	salt string
}

func InitPasswordHasher(salt string) PasswordHasher {
	return PasswordHasher{salt: salt}
}

func (ph *PasswordHasher) saltPassword(password string) string {
	return fmt.Sprintf("%s_%s_%s", ph.salt, password, ph.salt)
}

// HashPassword returns a hashed and salted password
func (ph *PasswordHasher) HashPassword(password string) ([]byte, error) {
	password = ph.saltPassword(password)
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return nil, err
	}

	return hashedPwd, nil
}

func (ph *PasswordHasher) ValidatePassword(hashedPassword, plainTextPassword string) (bool, error) {
	plainTextPassword = ph.saltPassword(plainTextPassword)
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainTextPassword))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}

	return true, nil
}
