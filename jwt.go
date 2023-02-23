package main

import (
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username   string   `json:"username" yaml:"username"`
	Password   string   `json:"password" yaml:"password"`
	Permission []string `json:"permission" yaml:"permission"`
}

type Claims struct {
	Token      string   `json:"token"`
	Username   string   `json:"username"`
	Permission []string `json:"permission"`
	jwt.StandardClaims
}

var jwtKey = []byte("SecRetDKeyABC$#BC@")

func generateJWT(u *User) (string, error) {

	claims := Claims{
		Username:   u.Username,
		Permission: u.Permission,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 8).Unix(), // 8 hours session
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		log.Println("Signing Error: ", err)
	}

	return tokenString, nil
}

func generateAPIToken(permission []string, days int) (string, error) {

	claims := Claims{
		Permission: permission,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(24*days)).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		log.Println("Signing Error: ", err)
	}

	return tokenString, nil
}

func (user *User) HashPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return err
	}
	user.Password = string(bytes)
	return nil
}

func (user *User) CheckPassword(providedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(providedPassword))
	if err != nil {
		return err
	}
	return nil
}
