package api

import (
	"github.com/gorilla/mux"
	"junjie.pro/informer/conf"
	"log"
	"net/http"
)

func Serve() {
	log.Println("Starting server")
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/login", Login)
	router.HandleFunc("/logout", Logout)

	router.HandleFunc("/libraries", List)
	router.HandleFunc("/libraries/add", Add)
	router.HandleFunc("/libraries/remove", Remove)
	router.HandleFunc("/libraries/update", Update)

	router.HandleFunc("/change-password", ChangePassword)
	router.HandleFunc("/change-master-password", ChangeMasterPassword)

	router.HandleFunc("/generate-password", GeneratePassword)

	router.HandleFunc("/otp", GeneratePassCode)

	//Listen on specific port
	informer, err := conf.ReadConfig()
	if err != nil {
		log.Fatalln(err.Error())
	}
	port := ":" + informer.Port

	log.Fatalln(http.ListenAndServe(port, router))
}
