package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alwashali/gologrhythm"
	"github.com/golang-jwt/jwt"
)

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome home!")

}

// Fetches cases from one or more LogRhythm instances
func cases(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	nameHeader := r.Header.Get("name")

	if nameHeader == "" {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Name was found in request header"}`))
		return
	}
	// prepare the filter
	caseFilter := gologrhythm.CasesFilters{}

	if r.Header.Get("count") != "" {
		caseFilter.Count = r.Header.Get("count")
	}

	if r.Header.Get("createdAfter") != "" {
		caseFilter.CreatedAfter = r.Header.Get("createdAfter")
	}

	// Search keyword in case name or description
	keyword := ""
	if r.Header.Get("keyword") != "" {
		keyword = r.Header.Get("keyword")
	}

	allCases := []gologrhythm.Case{}

	// if the api call is for all instances
	if strings.ToLower(nameHeader) == "all" {

		token := extractToken(r)
		allowed_LR := extractPermission(token)

		for _, lr := range allowed_LR {

			// if 'all' is present in permission that indicates the token
			// is for everything and hence matching the SIEM name will not work
			// user can still pass all in request header which means all SIEM names in permission list

			if lr != "all" {
				// all is not present in list of permitted LRs
				// Traverse SIEM by SIEM matching name in permitted SIEM with the passed name in headers
				for _, app := range apps {
					if app.Name == lr {
						cases, err := app.Cases(&caseFilter)
						if err != nil {
							log.Println(err, app.Name)
							continue
						}

						for _, c := range cases {

							// search operation
							if keyword != "" {
								if strings.Contains(c.Summary, keyword) || strings.Contains(c.Name, keyword) {
									allCases = append(allCases, *c)
								} else {
									continue
								}
							} else {
								allCases = append(allCases, *c)
							}

						}

					}
				}

			} else {

				for _, app := range apps {

					log.Printf("Connecting to %s", app.Name)

					cases, err := app.Cases(&caseFilter)

					if err != nil && strings.Contains(err.Error(), "did not properly respond") {
						log.Printf("No response from %s %s, timeout.\n", app.Name, app.Host)
						continue
					} else if err != nil {
						log.Printf("Error connecting to %s\n\n%s", app.Host, err.Error())
						continue
					}

					for _, c := range cases {

						// search operation
						if keyword != "" {
							if strings.Contains(c.Summary, keyword) || strings.Contains(c.Name, keyword) {
								allCases = append(allCases, *c)
							} else {
								continue
							}
						} else {
							allCases = append(allCases, *c)
						}

					}

				}

			}
		}

	} else { //if request is for one or more specific SIEMS

		Requested_SIEMs := splitNameHeader(nameHeader)

		for _, app := range apps {

			for _, siem := range Requested_SIEMs {
				if app.Name == siem {

					log.Printf("Connecting to %s", app.Name)
					cases, err := app.Cases(&caseFilter)
					if err != nil {
						log.Println(err, app.Host)
						continue
					}

					for _, c := range cases {

						// search operation
						if keyword != "" {
							if strings.Contains(c.Summary, keyword) || strings.Contains(c.Name, keyword) {
								allCases = append(allCases, *c)
							} else {
								continue
							}
						} else {
							allCases = append(allCases, *c)
						}

					}

				}

			}

		}

	}

	resp, err := json.Marshal(allCases)
	if err != nil {
		log.Println("Error marchal cases from: ", app.Name)
		err_resp := fmt.Sprintf(`{"error": "Error fetching data from %s"}`, app.Name)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(err_resp))
		return
	}

	w.Write([]byte(resp))
	return

}

func getCase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	CaseID := path.Base(r.URL.String())

	if r.Header.Get("name") == "" {
		error_json := `{"Error": "Name header was not set"}`
		resp := []byte(error_json)
		w.Write(resp)
		return
	}

	name := r.Header.Get("name")

	for _, app := range apps {
		if app.Name == name {
			cid, err := strconv.Atoi(CaseID)
			if err != nil {
				log.Println(err)
			}
			c, err := app.Case(cid)
			if err != nil {
				log.Println(err.Error())
				w.WriteHeader(http.StatusNotFound)
				error_json := fmt.Sprintf(`{"Error": "%s"}`, err.Error())
				resp := []byte(error_json)
				w.Write(resp)
				return

			}

			resp, err := json.Marshal(c)
			w.Write(resp)
			return
		}
	}

	log.Println("case was not found", CaseID)
	// if app or case id not found
	w.WriteHeader(http.StatusNotFound)
	resp := []byte(`{"Error": "case was not found"}`)
	w.Write(resp)
	return

}

func alarms(w http.ResponseWriter, r *http.Request) {
	allalarms := gologrhythm.Alarms{}

	w.Header().Set("Content-Type", "application/json")
	nameHeader := r.Header.Get("name")

	if nameHeader == "" {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "name header was found in request header"}`))
		return
	}

	// prepare the filter
	alarmFilter := gologrhythm.AlarmsFilters{}

	// if count was not found, LR will return 100 alarms for each instance

	if r.Header.Get("entityName") != "" {
		alarmFilter.EntityName = r.Header.Get("entityName")
	}

	if r.Header.Get("count") != "" {
		alarmFilter.Count = r.Header.Get("count")
	}

	if r.Header.Get("dateInserted") != "" {
		alarmFilter.DateInserted = r.Header.Get("dateInserted")
	}

	if r.Header.Get("alarmRuleName") != "" {
		alarmFilter.AlarmRuleName = r.Header.Get("alarmRuleName")
	}

	// keyword in case alarm or description
	keyword := ""
	if r.Header.Get("keyword") != "" {
		keyword = r.Header.Get("keyword")
	}

	// if the api call for all instances
	if strings.ToLower(r.Header.Get("name")) == "all" {

		token := extractToken(r)
		allowed_LR := extractPermission(token)

		for _, lr := range allowed_LR {

			if lr != "all" {

				for _, app := range apps {
					if app.Name == lr {
						log.Printf("Connecting to %s", app.Name)
						alarms, err := app.Alarms(&alarmFilter)
						if err != nil {
							log.Println(err, app.Name)
							continue
						}

						for _, AlarmsSearchDetails := range alarms.AlarmsSearchDetails {

							// search operation
							if keyword != "" {
								if strings.Contains(AlarmsSearchDetails.AlarmRuleName, keyword) {
									allalarms.AlarmsSearchDetails = append(allalarms.AlarmsSearchDetails, AlarmsSearchDetails)
								}

							} else {
								allalarms.AlarmsSearchDetails = append(allalarms.AlarmsSearchDetails, AlarmsSearchDetails)
							}

						}

					}
				}
			} else {

				for _, app := range apps {
					log.Printf("Connecting to %s", app.Name)
					alarms, err := app.Alarms(&alarmFilter)
					if err != nil {
						log.Println(err, app.Name)
						continue
					}

					for _, AlarmsSearchDetails := range alarms.AlarmsSearchDetails {

						// search operation
						if keyword != "" {
							if strings.Contains(AlarmsSearchDetails.AlarmRuleName, keyword) {
								allalarms.AlarmsSearchDetails = append(allalarms.AlarmsSearchDetails, AlarmsSearchDetails)
							}

						} else {
							allalarms.AlarmsSearchDetails = append(allalarms.AlarmsSearchDetails, AlarmsSearchDetails)
						}

					}

				}

			}
		}

	} else { //if request is for one or more specific SIEMS
		Requested_SIEMs := splitNameHeader(nameHeader)
		for _, app := range apps {
			for _, siem := range Requested_SIEMs {

				if app.Name == siem {

					alarms, err := app.Alarms(&alarmFilter)
					if err != nil {
						log.Println(err, app.Host)
						continue
					}

					resp, err := json.Marshal(alarms)
					if err != nil {
						log.Println("Error marchal alarms from: ", app.Name)
						err_resp := fmt.Sprintf(`{"Error": "Error fetching data from %s"}`, app.Name)
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte(err_resp))
						return
					}

					w.Write([]byte(resp))
					return

				}
			}
		}

	}

	resp, err := json.Marshal(allalarms.AlarmsSearchDetails)
	if err != nil {
		log.Println("Error marchalling Alarms")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"Error": "Error marchalling Alarms"}`))
		return
	}

	w.Write(resp)
}

func getAlarm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	alarmid := path.Base(r.URL.String())

	if r.Header.Get("name") == "" {
		error_json := `{"Error": "Name header was not set"}`
		resp := []byte(error_json)
		w.Write(resp)
		return
	}

	name := r.Header.Get("name")

	for _, app := range apps {
		if app.Name == name {
			aid, err := strconv.Atoi(alarmid)
			if err != nil {
				log.Println(err)
			}
			alarm, err := app.Alarm(int64(aid))
			if err != nil {
				log.Println(err.Error())
				w.WriteHeader(http.StatusNotFound)
				error_json := fmt.Sprintf(`{"Error": "%s"}`, err.Error())
				resp := []byte(error_json)
				w.Write(resp)
				return

			}

			resp, err := json.Marshal(alarm)
			w.Write(resp)
			return
		}
	}
}

func login(w http.ResponseWriter, r *http.Request) {

	provideduser := User{}
	err := json.NewDecoder(r.Body).Decode(&provideduser)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte("Bad Request"))
		if err != nil {
			return
		}

	}

	fmt.Println(provideduser.Username, provideduser.Password)

	for _, u := range users {
		if provideduser.Username == u.Username {
			passwordCheck := u.CheckPassword(provideduser.Password)
			if passwordCheck == nil {

				token, err := generateJWT(&provideduser)
				if err != nil {
					log.Println(err)
				}

				http.SetCookie(w, &http.Cookie{
					Name:    "token",
					Value:   token,
					Expires: time.Now().Add(8 * time.Hour),
				})

				log.Printf("%s Logged in", provideduser.Username)
				return
			}

		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	_, err = w.Write([]byte("Wrong User or Password"))
	if err != nil {
		return
	}

}

func verifyJWT(endpointHandler func(writer http.ResponseWriter, request *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {

		// use API token from Authorization header, otherwise use username password auth token
		// priority is for api token,

		token := ""

		reqToken := request.Header.Get("authorization")

		if reqToken != "" {
			splitToken := strings.Split(reqToken, "Bearer ")
			token = splitToken[1]

		} else {

			CookieToken, err := request.Cookie("token")

			if err != nil {
				writer.WriteHeader(http.StatusUnauthorized)
				writer.Write([]byte("You're Unauthorized, error fetching cookie"))
				return
			}

			token = CookieToken.Value

		}

		tkn, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {

			return jwtKey, nil

		})

		// parsing errors result
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("You're Unauthorized due to error parsing the JWT " + err.Error()))
			log.Println(err.Error())
			return
		}

		claims, ok := tkn.Claims.(*Claims)
		if !ok {
			_, err := writer.Write([]byte("You're Unauthorized"))
			if err != nil {
				return
			}
		}

		if claims.ExpiresAt < time.Now().UTC().Unix() {
			_, err := writer.Write([]byte("Token Expired"))
			if err != nil {
				return
			}
		}

		//validate token and user permission to call the instance
		if tkn.Valid {
			name := request.Header.Get("name")

			if name == "" {
				err_resp := `{"Error": "Name header was not found"}`
				writer.WriteHeader(http.StatusUnauthorized)
				writer.Write([]byte(err_resp))
				return
			}

			if name == "all" {
				// handler will take care of returning only cases or alarms from the allwed logRhythms based on assigned permission
				endpointHandler(writer, request)
			} else {
				if hasPermission(name, token) {
					endpointHandler(writer, request)
				} else {
					err_resp := fmt.Sprintf(`{"Error": "No permission found for one or more SIEMs"}`)
					writer.WriteHeader(http.StatusUnauthorized)
					writer.Write([]byte(err_resp))
					return
				}
			}

		} else {
			writer.WriteHeader(http.StatusUnauthorized)
			_, err := writer.Write([]byte("You're Unauthorized due to invalid token"))
			if err != nil {
				log.Println(err)
			}
			return
		}

	})
}
