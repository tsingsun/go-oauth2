package main

import (
	"github.com/tsingsun/go-oauth2"
	"io"
	"log"
	"net/http"
)

var (
	AuthorizationServer oauth2.AuthorizationServer
)

func main() {
	var ce = &ClientRepository{}
	option := &oauth2.Options{
		PrivateKey:       "",
		PublickKey:       "",
		ClientRepository: ce,
	}
	AuthorizationServer = oauth2.NewAuthorizationServer(option)

	http.HandleFunc("/token",
		func(writer http.ResponseWriter, request *http.Request) {
			io.WriteString(writer, "hello, world!\n")
		})
	log.Fatal(http.ListenAndServe(":9000", nil))
}
