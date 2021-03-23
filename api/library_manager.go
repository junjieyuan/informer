package api

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"junjie.pro/informer/conf"
	"junjie.pro/informer/library"
	"log"
	"net/http"
)

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
		err = json.NewEncoder(w).Encode(NotLoggedInMessage)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//Read informer library
	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		log.Fatalln(err.Error())
	}

	//Using query parameters to query secures. If key is given, informer will decrypt secures
	queryParams := r.URL.Query()
	if queryParams["key"] != nil && queryParams["key"][0] != "" {
		err = informerLibrary.Unlock([]byte(queryParams["key"][0]))
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(500)
			err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
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
		log.Fatalln(err.Error())
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
		err = json.NewEncoder(w).Encode(NotLoggedInMessage)
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
		err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
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
		err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
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
	err = json.NewEncoder(w).Encode(SuccessMessage)
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
		err = json.NewEncoder(w).Encode(NotLoggedInMessage)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//Parse secure(s)' key from request body
	var secures PrimaryKeys
	err = json.Unmarshal(body, &secures)
	if err != nil {
		w.WriteHeader(500)
		err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
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
	for _, secure := range secures.PrimaryKey {
		informerLibrary.Remove(secure)
	}

	//Write informer library
	err = informerLibrary.WriteLibrary()
	if err != nil {
		w.WriteHeader(500)
		log.Println(err.Error())

		return
	}

	w.WriteHeader(200)
	err = json.NewEncoder(w).Encode(SuccessMessage)
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
		err = json.NewEncoder(w).Encode(NotLoggedInMessage)
		if err != nil {
			log.Fatalln(err)
		}

		return
	}

	//Parse encryption key and secure(s) from request body
	var secureNKey PrimaryKeyWithSecures
	err = json.Unmarshal(body, &secureNKey)
	if err != nil {
		log.Println(err.Error())

		w.WriteHeader(500)
		err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
		if err != nil {
			log.Fatalln(err.Error())
		}

		return
	}

	//Must send 2 secures, the first is origin, and the second is updated
	if secureNKey.PrimaryKey == "" || len(secureNKey.Secures) != 1 {
		w.WriteHeader(500)
		message := Message{Message: "array must have 1 Primary Key and 1 secure"}
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

	//Unlock informer library
	err = informerLibrary.Unlock([]byte(secureNKey.Key))
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(500)
		err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
		if err != nil {
			log.Fatalln(err.Error())
		}

		return
	}

	//Using origin secure to find index and replace by updated secure
	informerLibrary.Update(secureNKey.PrimaryKey, secureNKey.Secures[0])

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
	err = json.NewEncoder(w).Encode(SuccessMessage)
	if err != nil {
		log.Fatalln(err.Error())
	}
}

type PasswordBundle struct {
	OldPassword     string `json:"oldPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

//Change user's master password
func ChangeMasterPassword(w http.ResponseWriter, r *http.Request) {
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
		err = json.NewEncoder(w).Encode(NotLoggedInMessage)
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
		err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
		if err != nil {
			log.Fatalln(err.Error())
		}

		return
	}

	//Read informer library
	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err.Error())
	}

	//Change password when they correctly
	if passwords.NewPassword == passwords.ConfirmPassword {
		//Unlock informer library using old password
		err = informerLibrary.Unlock([]byte(passwords.OldPassword))
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(500)
			err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
			if err != nil {
				log.Fatalln(err.Error())
			}

			return
		}

		//Lock informer library using new password
		err = informerLibrary.Lock([]byte(passwords.NewPassword))
		if err != nil {
			w.WriteHeader(500)
			log.Println(err.Error())

			return
		}

		//Write informer library
		err = informerLibrary.WriteLibrary()
		if err != nil {
			w.WriteHeader(500)
			log.Fatalln(err.Error())
		}
	} else {
		//If passwords not correctly, return 500 data not correctly
		w.WriteHeader(500)
		err = json.NewEncoder(w).Encode(DataNotCorrectMessage)
		if err != nil {
			log.Fatalln()
		}

		return
	}

	w.WriteHeader(200)
	err = json.NewEncoder(w).Encode(SuccessMessage)
	if err != nil {
		w.WriteHeader(500)
		log.Fatalln(err.Error())
	}
}
