package api

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"junjie.pro/informer/conf"
	"junjie.pro/informer/library"
	"log"
	"net/http"
	"time"
)

func Serve() {
	log.Println("Starting server")
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/login", Login)

	router.HandleFunc("/libraries", List)
	router.HandleFunc("/libraries/add", Add)
	router.HandleFunc("/libraries/remove", Remove)
	router.HandleFunc("/libraries/update", Update)

	log.Fatalln(http.ListenAndServe(":8080", router))
}

func Login(w http.ResponseWriter, r *http.Request) {
	var user conf.User

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
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(500)
		err = json.NewEncoder(w).Encode(err)
		if err != nil {
			panic(err)
		}
	}

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

	//If user is already logged in, don't login again.
	if username != nil && tokenId != nil {
		if informerConfig.CheckLogin(username.Value, tokenId.Value) {
			//TODO redirect
			log.Println("User already logged in")
			return
		}
	}

	if informerConfig.CheckUser(user) {
		tokenId := conf.GenerateToken()
		createDate := time.Now()
		token := conf.Token{ID: tokenId, CreateDate: createDate}
		expire := time.Now().AddDate(0, 0, informerConfig.RenewalCycle)

		informerConfig.User.AddToken(token)
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

		err := informerConfig.WriteConfig()
		if err != nil {
			panic(err)
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

	if username != nil && tokenId != nil {
		if !informerConfig.CheckLogin(username.Value, tokenId.Value) {
			//TODO 302 redirect to login page
			return
		}
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

	if username != nil && tokenId != nil {
		if !informerConfig.CheckLogin(username.Value, tokenId.Value) {
			//TODO 302 redirect to login page
			return
		}
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
		err = json.NewEncoder(w).Encode(err)
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
		informerLibrary.Add(secure)
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

	if username != nil && tokenId != nil {
		if !informerConfig.CheckLogin(username.Value, tokenId.Value) {
			//TODO 302 redirect to login page
			return
		}
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
		err = json.NewEncoder(w).Encode(err)
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

	if username != nil && tokenId != nil {
		if !informerConfig.CheckLogin(username.Value, tokenId.Value) {
			//TODO 302 redirect to login page
			return
		}
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
		err = json.NewEncoder(w).Encode(err)
		if err != nil {
			panic(err)
		}
	}

	if len(secureNKey.Secure) != 2 {
		err = errors.New("array must have 2 secure")
		//TODO return
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
