package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"
	"gopkg.in/yaml.v2"
)

type SIEM struct {
	Name  string `yaml:"Name"`
	Host  string `yaml:"Host"`
	Token string `yaml:"Token"`
}

func fileNameWithoutExt(fileName string) string {
	return fileName[:len(fileName)-len(filepath.Ext(fileName))]
}

func create_user(username string, Password string, Permission []string) {

	u := User{}

	if Permission[0] == "all" {
		u.Permission = append(u.Permission, "all")
	} else {
		items, err := ioutil.ReadDir("secrets/logrhythms")
		if err != nil {
			log.Printf("Error while Marshaling. %v", err)
		}

		for _, lr := range Permission {
			foundCorrectLRName := false
			for _, item := range items {

				if !item.IsDir() {
					if lr == fileNameWithoutExt(item.Name()) {
						foundCorrectLRName = true
						u.Permission = append(u.Permission, lr)

					}
				}

			}
			if foundCorrectLRName == false {
				log.Fatalf("LogRhythm %s was not found", lr)
			}
		}
	}

	u.Username = username
	u.HashPassword(Password)

	yamlData, err := yaml.Marshal(&u)
	if err != nil {
		log.Panicf("Error while Marshaling. %v", err)

	}

	writefile(username, yamlData, "user")
	log.Printf("User %s was added successfuly", username)

}

func add_Instance(name, host, token string) {
	if is_ipv4(host) {
		s := SIEM{
			Name:  name,
			Host:  host,
			Token: token,
		}
		yamlData, err := yaml.Marshal(&s)

		if err != nil {
			log.Panicf("Error while Marshaling. %v", err)
		}
		writefile(name, yamlData, "siem")
		log.Printf("\n LogRhythm configuraiton saved successfully\n")
	} else {
		log.Fatalln("Invalid IP Address ")
	}

}

func writefile(name string, data []byte, secretType string) {
	if secretType == "user" {
		file := fmt.Sprintf("secrets/users/%s.yaml", name)
		err := os.WriteFile(file, data, 0644)
		if err != nil {
			log.Println(err)
		}
	}

	if secretType == "siem" {
		file := fmt.Sprintf("secrets/logrhythms/%s.yaml", name)
		err := os.WriteFile(file, data, 0644)
		if err != nil {
			log.Println(err)
		}
	}

}

func is_ipv4(host string) bool {
	parts := strings.Split(host, ".")

	if len(parts) < 4 {
		return false
	}

	for _, x := range parts {
		if i, err := strconv.Atoi(x); err == nil {
			if i < 0 || i > 255 {
				return false
			}
		} else {
			return false
		}

	}
	return true
}

// check if the LogRhythm instance is in the token claims
func hasPermission(name, token string) bool {

	LRs := splitNameHeader(name)
	permissions := extractPermission(token)

	requestedSIEM_Number := len(LRs)
	counter := 0

	if permissions != nil {
		for _, lr := range LRs {

			for _, p := range permissions {
				if lr == p {
					counter = counter + 1
				}
			}
		}
	}

	if counter == requestedSIEM_Number {
		return true
	}

	return false
}

func extractToken(r *http.Request) string {
	reqToken := r.Header.Get("Authorization")
	if reqToken != "" {
		splitToken := strings.Split(reqToken, "Bearer ")
		token := splitToken[1]
		return token
	}

	CookieToken, _ := r.Cookie("token")

	return CookieToken.Value

}

// return slice of all allowed logRhythm instances in JWT claim
func extractPermission(token string) []string {
	tkn, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		log.Println(err)
	}

	claims, ok := tkn.Claims.(*Claims)
	if ok {
		return claims.Permission
	}
	return nil
}
