package api

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"junjie.pro/informer/library"
	"log"
	"net/http"
)

func Serve() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/libraries", List)
	router.HandleFunc("/libraries/add", Add)
	router.HandleFunc("/libraries/remove", Remove)

	log.Fatalln(http.ListenAndServe(":8080", router))
}

func List(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		panic(err)
	}

	err = json.NewEncoder(w).Encode(informerLibrary)
	if err != nil {
		panic(err)
	}
}

type secureWithKey struct {
	Secure []library.SecureStore `json:"secure"`
	Key    string                `json:"key"`
}

func Add(w http.ResponseWriter, r *http.Request) {
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
