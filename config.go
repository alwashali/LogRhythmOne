package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/alwashali/gologrhythm"
	"gopkg.in/yaml.v2"
)

var apps []*gologrhythm.LogRhtyhm
var users []*User

// Load configuration yaml in config folder to config array
func load_config() []*SIEM {
	confi := []*SIEM{}

	items, _ := ioutil.ReadDir("secrets\\logrhythms")
	for _, item := range items {

		if !item.IsDir() {

			if strings.HasSuffix(item.Name(), ".yaml") {

				f, err := os.Open("secrets\\logrhythms\\" + item.Name())
				if err != nil {
					log.Fatal("Error opening the config file: ", item.Name(), err)
				}
				defer f.Close()

				var siem SIEM
				decoder := yaml.NewDecoder(f)
				err = decoder.Decode(&siem)
				if err != nil {
					log.Println("Error parsing the config file: ", item.Name(), err)

				}

				if siem.Token == "" || siem.Host == "" || siem.Name == "" {
					log.Fatal("Error: one or more yaml file fields is missing: ", item.Name(), err)
				}
				confi = append(confi, &siem)
			}
		}
	}

	if len(confi) == 0 {
		log.Fatal("Error loading SIEM config yaml files")
	}
	return confi

}

func load_users() []*User {
	users := []*User{}

	items, err := ioutil.ReadDir("secrets\\users")
	if err != nil {
		log.Fatal("Error reading secrets: ", err)
	}

	for _, item := range items {

		if !item.IsDir() {

			if strings.HasSuffix(item.Name(), ".yaml") {

				f, err := os.Open("secrets\\users\\" + item.Name())
				if err != nil {
					log.Fatal("Error opening the config file: ", item.Name(), err)
				}
				defer f.Close()

				var user User
				decoder := yaml.NewDecoder(f)
				err = decoder.Decode(&user)
				if err != nil {
					log.Println("Error parsing the config file: ", item.Name(), err)

				}

				users = append(users, &user)
			}

		}
	}
	return users

}

func loadSecrets() {

	config := load_config()

	for _, c := range config {

		if strings.Contains(c.Host, ":") {
			app := gologrhythm.Create_App(c.Name, c.Token, c.Host)
			apps = append(apps, app)

		} else {
			// default port is 8601
			host_port := fmt.Sprintf("%s:%d", c.Host, 8501)
			app := gologrhythm.Create_App(c.Name, c.Token, host_port)
			apps = append(apps, app)

		}

	}

	users = load_users()
}
