package api

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"junjie.pro/informer/conf"
	"junjie.pro/informer/library"
	"log"
	"net/http"
	"time"
)

const messageTemplate = "{\"message\": \"%s\"}"

func Serve() {
	log.Println("Starting server")
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/login", Login)

	router.HandleFunc("/libraries", List)
	router.HandleFunc("/libraries/add", Add)
	router.HandleFunc("/libraries/remove", Remove)
	router.HandleFunc("/libraries/update", Update)

	router.HandleFunc("/change-password", ChangePassword)

	//Listen on specific port, if port not set, using 8080
	informer, err := conf.ReadConfig()
	if err != nil {
		log.Fatalln(err.Error())
	}
	var port string
	if informer.Port == "" {
		port = ":8080"
	} else {
		port = ":" + informer.Port
	}
	log.Fatalln(http.ListenAndServe(port, router))
}

func Login(w http.ResponseWriter, r *http.Request) {
	//Response message is json
	w.Header().Add("Content-Type", "application/json")

	//Read request body and close it
	body, err := ioutil.ReadAll(io.Reader(r.Body))
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}
	err = r.Body.Close()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read informer configurations
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read login token from cookie
	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err)
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err)
	}

	//Check user is already logged in whether
	if username != nil && tokenId != nil && informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(200)
		message := fmt.Sprintf(messageTemplate, "success")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//Parse user login information from request body
	var user conf.User
	err = json.Unmarshal(body, &user)
	if err != nil {
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, err.Error())
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//If login information correctly and successfully login, return 200 success,
	//else return 401 login information not correctly or 500
	if informerConfig.CheckUser(user) {
		tokenId := conf.GenerateToken()
		createDate := time.Now()
		token := conf.Token{ID: tokenId, CreateDate: createDate}
		expire := time.Now().AddDate(0, 0, informerConfig.RenewalCycle)

		//Save token
		informerConfig.User.AddToken(token)
		err = informerConfig.WriteConfig()
		if err != nil {
			w.WriteHeader(500)
			log.Fatalln(err)
		}

		//Set cookie: username and token
		usernameCookie := http.Cookie{
			Name:       "username",
			Value:      user.Username,
			Path:       "",
			Domain:     "",
			Expires:    expire,
			RawExpires: "",
			MaxAge:     0,
			Secure:     false,
			HttpOnly:   true,
			SameSite:   0,
			Raw:        "",
			Unparsed:   nil,
		}
		http.SetCookie(w, &usernameCookie)
		tokenCookie := http.Cookie{
			Name:       "token",
			Value:      tokenId,
			Path:       "",
			Domain:     "",
			Expires:    expire,
			RawExpires: "",
			MaxAge:     0,
			Secure:     false,
			HttpOnly:   true,
			SameSite:   0,
			Raw:        "",
			Unparsed:   nil,
		}
		http.SetCookie(w, &tokenCookie)

		w.WriteHeader(200)
		message := fmt.Sprintf(messageTemplate, "success")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		w.WriteHeader(401)
		message := fmt.Sprintf(messageTemplate, "username or password not correctly")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

//Return all of secures or query by query string
func List(w http.ResponseWriter, r *http.Request) {
	//Response message is json
	w.Header().Add("Content-Type", "application/json")

	//Read informer configurations
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read login token from cookie
	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err)
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err)
	}

	//Check user is already logged in whether
	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		message := fmt.Sprintf(messageTemplate, "not logged in")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//Read informer library
	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		panic(err)
	}

	//Using query parameters to query secures. If key is given, informer will decrypt secures
	queryParams := r.URL.Query()
	if queryParams["key"] != nil {
		err = informerLibrary.Unlock([]byte(queryParams["key"][0]))
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(500)
			message := fmt.Sprintf(messageTemplate, "data not correctly")
			err = json.NewEncoder(w).Encode(message)
			if err != nil {
				log.Fatalln(err.Error())
			}

			return
		}
	}
	//Find secures by query string, and results is encoded in json
	if queryParams["query"] != nil {
		found, secures := informerLibrary.Query(queryParams["query"][0])
		if found {
			w.WriteHeader(200)
			err = json.NewEncoder(w).Encode(secures)
			if err != nil {
				log.Fatalln(err.Error())
			}
		}

		return
	}

	//If not given any query string, just list all of secures without decrypt
	err = json.NewEncoder(w).Encode(informerLibrary.SecureStore)
	if err != nil {
		panic(err)
	}
}

type secureWithKey struct {
	Secure []library.SecureStore `json:"secure"`
	Key    string                `json:"key"`
}

func Add(w http.ResponseWriter, r *http.Request) {
	//Response message is json
	w.Header().Add("Content-Type", "application/json")

	//Read request body and close it
	body, err := ioutil.ReadAll(io.Reader(r.Body))
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}
	err = r.Body.Close()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read informer configurations
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read login token from cookie
	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err)
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err)
	}

	//Check user is already logged in whether
	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		message := fmt.Sprintf(messageTemplate, "not logged in")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//Parse encryption key and secure(s) from request body
	var secureNKey secureWithKey
	err = json.Unmarshal(body, &secureNKey)
	if err != nil {
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, "data not correctly")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err.Error())
		}

		return
	}

	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		log.Fatalln(err.Error())
	}

	err = informerLibrary.Unlock([]byte(secureNKey.Key))
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, "data not correctly")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err.Error())
		}

		return
	}

	for _, secure := range secureNKey.Secure {
		informerLibrary.Add(secure)
	}

	err = informerLibrary.Lock([]byte(secureNKey.Key))
	if err != nil {
		w.WriteHeader(500)
		log.Println(err.Error())

		return
	}

	err = informerLibrary.WriteLibrary()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err.Error())
	}

	w.WriteHeader(200)
	message := fmt.Sprintf(messageTemplate, "success")
	err = json.NewEncoder(w).Encode(message)
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func Remove(w http.ResponseWriter, r *http.Request) {
	//Response message is json
	w.Header().Add("Content-Type", "application/json")

	//Read request body and close it
	body, err := ioutil.ReadAll(io.Reader(r.Body))
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}
	err = r.Body.Close()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read informer configurations
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read login token from cookie
	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err)
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err)
	}

	//Check user is already logged in whether
	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		message := fmt.Sprintf(messageTemplate, "not logged in")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//Parse secure(s) from request body
	var secures []library.SecureStore
	err = json.Unmarshal(body, &secures)
	if err != nil {
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, "data not correctly")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err.Error())
		}

		return
	}

	//Read informer library
	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		log.Fatalln(err.Error())
	}

	//Find index of secure and remove it
	for _, secure := range secures {
		found, index := informerLibrary.QueryPrimaryKey(secure.ID, secure.Platform, secure.Username)
		if found {
			informerLibrary.Remove(index)
		}
	}

	//Write informer library
	err = informerLibrary.WriteLibrary()
	if err != nil {
		w.WriteHeader(500)
		log.Println(err.Error())

		return
	}

	w.WriteHeader(200)
	message := fmt.Sprintf(messageTemplate, "success")
	err = json.NewEncoder(w).Encode(message)
	if err != nil {
		log.Fatalln(err.Error())
	}
}

//Replace a secure by other one
func Update(w http.ResponseWriter, r *http.Request) {
	//Response message is json
	w.Header().Add("Content-Type", "application/json")

	//Read request body and close it
	body, err := ioutil.ReadAll(io.Reader(r.Body))
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}
	err = r.Body.Close()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read informer configurations
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read login token from cookie
	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err)
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err)
	}

	//Check user is already logged in whether
	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		message := fmt.Sprintf(messageTemplate, "not logged in")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//Parse encryption key and secure(s) from request body
	var secureNKey secureWithKey
	err = json.Unmarshal(body, &secureNKey)
	if err != nil {
		log.Println(err.Error())

		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, "data not correctly")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err.Error())
		}

		return
	}

	//Must send 2 secures, the first is origin, and the second is updated
	if len(secureNKey.Secure) != 2 {
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, "array must have 2 secure")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err.Error())
		}
	}
	original, updated := secureNKey.Secure[0], secureNKey.Secure[1]

	//Read informer library
	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		log.Fatalln(err.Error())
	}

	//Unlock informer library
	err = informerLibrary.Unlock([]byte(secureNKey.Key))
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, "data not correctly")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err.Error())
		}

		return
	}

	//Using origin secure to find index and replace by updated secure
	found, index := informerLibrary.QueryPrimaryKey(original.ID, original.Platform, original.Username)
	if found {
		informerLibrary.Update(index, updated)
	}

	//Lock informer library
	err = informerLibrary.Lock([]byte(secureNKey.Key))
	if err != nil {
		w.WriteHeader(500)
		log.Println(err.Error())

		return
	}

	//Write informer library
	err = informerLibrary.WriteLibrary()
	if err != nil {
		w.WriteHeader(500)
		log.Println(err.Error())

		return
	}

	//Return 200 success
	w.WriteHeader(200)
	message := fmt.Sprintf(messageTemplate, "success")
	err = json.NewEncoder(w).Encode(message)
	if err != nil {
		log.Fatalln(err.Error())
	}
}

type PasswordBundle struct {
	Old string `json:"old"`
	New string `json:"new"`
	Confirm string `json:"confirm"`
}

//Change user's password
func ChangePassword(w http.ResponseWriter, r *http.Request) {
	//Response message is json
	w.Header().Add("Content-Type", "application/json")

	//Read request body and close it
	body, err := ioutil.ReadAll(io.Reader(r.Body))
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}
	err = r.Body.Close()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read informer configurations
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err)
	}

	//Read login token from cookie
	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err)
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err)
	}

	//Check user is already logged in whether
	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		message := fmt.Sprintf(messageTemplate, "not logged in")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//Parse passwords from request body
	var passwords PasswordBundle
	err = json.Unmarshal(body, &passwords)
	if err != nil {
		log.Println(err.Error())

		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, "data not correctly")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err.Error())
		}

		return
	}

	//Confirm and change password
	user := conf.User{Username: username.Value, Password: passwords.Old}
	if passwords.New == passwords.Confirm && informerConfig.CheckUser(user) {
		user.Password = passwords.New
		informerConfig.ChangePassword(user)
	} else {
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, "data not correctly")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln()
		}

		return
	}

	//Write informer configurations
	err = informerConfig.WriteConfig()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err.Error())
	}

	w.WriteHeader(200)
	message := fmt.Sprintf(messageTemplate, "success")
	err = json.NewEncoder(w).Encode(message)
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err.Error())
	}
}
