package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	log.Println("Listening on http://localhost:3000/index.html")

	server := &http.Server{
		Addr:              ":3000",
		ReadHeaderTimeout: 20 * time.Second,
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
