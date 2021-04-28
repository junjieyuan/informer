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

	for _, route := range routes {
		router.Name(route.Name).Methods(route.Method).Path(route.Pattern).HandlerFunc(route.HandlerFunc)
	}

	//Listen on specific port
	informer, err := conf.ReadConfig()
	if err != nil {
		log.Fatalln(err.Error())
	}
	port := ":" + informer.Port

	log.Fatalln(http.ListenAndServe(port, router))
}
