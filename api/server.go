package api

import (
	"encoding/json"
	"errors"
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

func List(w http.ResponseWriter, r *http.Request) {
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		panic(err)
	}

	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err.Error())
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err.Error())
	}

	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		err = json.NewEncoder(w).Encode(fmt.Sprintf(messageTemplate, "not logged in"))
		if err != nil {
			panic(err)
		}
		return
	}

	w.Header().Add("Content-Type", "application/json")

	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		panic(err)
	}

	queryParams := r.URL.Query()
	if queryParams["key"] != nil {
		err = informerLibrary.Unlock([]byte(queryParams["key"][0]))
		if err != nil {
			panic(err)
		}
	}

	if queryParams["query"] != nil {
		found, secures := informerLibrary.Query(queryParams["query"][0])
		if found {
			err = json.NewEncoder(w).Encode(secures)
			if err != nil {
				panic(err)
			}
		}

		return
	}

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
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		panic(err)
	}

	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err.Error())
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err.Error())
	}

	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		message := fmt.Sprintf(messageTemplate, "not logged in")
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			panic(err)
		}
		return
	}

	var secureNKey secureWithKey

	body, err := ioutil.ReadAll(io.Reader(r.Body))
	if err != nil {
		panic(err)
	}

	err = r.Body.Close()
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(body, &secureNKey)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(500)
		message := fmt.Sprintf("{\"message\": \"%s\"}", err.Error())
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			panic(err)
		}
	}

	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		panic(err)
	}

	err = informerLibrary.Unlock([]byte(secureNKey.Key))
	if err != nil {
		panic(err)
	}

	for _, secure := range secureNKey.Secure {
		found, index := informerLibrary.QueryPrimaryKey(secure.ID, secure.Platform, secure.Username)
		if found {
			informerLibrary.Remove(index)
		}
	}

	err = informerLibrary.Lock([]byte(secureNKey.Key))
	if err != nil {
		panic(err)
	}

	err = informerLibrary.WriteLibrary()
	if err != nil {
		panic(err)
	}
}

func Update(w http.ResponseWriter, r *http.Request) {
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		panic(err)
	}

	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err.Error())
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err.Error())
	}

	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		err = json.NewEncoder(w).Encode(fmt.Sprintf(messageTemplate, "not logged in"))
		if err != nil {
			panic(err)
		}
		return
	}

	var secureNKey secureWithKey

	body, err := ioutil.ReadAll(io.Reader(r.Body))
	if err != nil {
		panic(err)
	}

	err = r.Body.Close()
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(body, &secureNKey)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, err.Error())
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			panic(err)
		}
	}

	if len(secureNKey.Secure) != 2 {
		err = errors.New("array must have 2 secure")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, err.Error())
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			panic(err)
		}
	}
	original, updated := secureNKey.Secure[0], secureNKey.Secure[1]

	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		panic(err)
	}

	err = informerLibrary.Unlock([]byte(secureNKey.Key))
	if err != nil {
		panic(err)
	}

	found, index := informerLibrary.QueryPrimaryKey(original.ID, original.Platform, original.Username)
	if found {
		informerLibrary.Update(index, updated)
	}

	err = informerLibrary.Lock([]byte(secureNKey.Key))
	if err != nil {
		panic(err)
	}

	err = informerLibrary.WriteLibrary()
	if err != nil {
		panic(err)
	}
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	informerConfig, err := conf.ReadConfig()
	if err != nil {
		panic(err)
	}

	username, err := r.Cookie("username")
	if err != nil {
		log.Println(err.Error())
	}
	tokenId, err := r.Cookie("token")
	if err != nil {
		log.Println(err.Error())
	}

	if username == nil || tokenId == nil || !informerConfig.CheckLogin(username.Value, tokenId.Value) {
		w.WriteHeader(403)
		err = json.NewEncoder(w).Encode(fmt.Sprintf(messageTemplate, "not logged in"))
		if err != nil {
			panic(err)
		}
		return
	}

	var user conf.User

	w.Header().Add("Content-Type", "application/json")

	body, err := ioutil.ReadAll(io.Reader(r.Body))
	if err != nil {
		panic(err)
	}

	err = r.Body.Close()
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(body, &user)
	if err != nil {
		w.WriteHeader(500)
		message := fmt.Sprintf(messageTemplate, err.Error())
		err = json.NewEncoder(w).Encode(message)
		if err != nil {
			panic(err)
		}
		return
	}

	user.Username = username.Value
	informerConfig.ChangePassword(user)

	err = informerConfig.WriteConfig()
	if err != nil {
		panic(err)
	}
}
