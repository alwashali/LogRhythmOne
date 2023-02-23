package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func MuxServer() {

	port := os.Getenv("lrport")
	if port == "" {

		log.Fatal("Error: lrport environment variable wasn't set")
	}

	loadSecrets() //initalize config files

	router := mux.NewRouter()

	router.HandleFunc("/", verifyJWT((home))).Methods("GET")

	// Return cases in a specific LogRhythm instance
	router.HandleFunc("/cases", verifyJWT(cases)).Methods("GET")

	// Return case information from a specifc LogRhythm instance
	router.HandleFunc("/case/{id}", verifyJWT(getCase)).Methods("GET")

	// Return alarms in a specific LogRhythm instance name
	router.HandleFunc("/alarms", verifyJWT(alarms)).Methods("GET")

	// Return alarms in a specific LogRhythm instance name
	router.HandleFunc("/alarm/{id}", verifyJWT(getAlarm)).Methods("GET")

	router.HandleFunc("/login", login).Methods("POST")

	log.Println("Listening... 0.0.0.0:" + port)
	err := http.ListenAndServe("0.0.0.0:"+port, router)

	if err != nil {
		log.Fatalln("There's an error with the server,", err)
	}
}
