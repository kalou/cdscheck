package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"
)

var c = NewChecker()

func main() {
	keypath := flag.String("config", "", "path for trusted keys and . referrals")
	flag.Parse()

	if keypath != nil {
		c.LoadTrustedKeys(*keypath)
	}

	http.HandleFunc("/domain/", CheckDomain)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func CheckDomain(w http.ResponseWriter, r *http.Request) {
	elems := strings.Split(r.URL.String(), "/")
	domain := elems[len(elems)-1]

	result, err := c.DomainKeys(domain)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	repr, err := json.Marshal(result)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Could not json encode result"))
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(repr)
}
