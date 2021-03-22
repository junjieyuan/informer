package api

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"junjie.pro/informer/conf"
	"log"
	"net/http"
	"time"
)

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
		err = json.NewEncoder(w).Encode(SuccessMessage)
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
		message := Message{Message: err.Error()}
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
		err = json.NewEncoder(w).Encode(SuccessMessage)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		w.WriteHeader(401)
		message := Message{Message: "username or password not correctly"}
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			log.Fatalln(err)
		}
	}
}
