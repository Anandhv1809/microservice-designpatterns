package main

import (
	"io"
	"log"
	"net/http"
)

var serviceRegistry = map[string]string{
	"user-service":  "http://localhost:8081",
	"order-service": "http://localhost:8082",
}

func proxyHandler(serviceName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetURL := serviceRegistry[serviceName] + r.URL.Path
		resp, err := http.Get(targetURL)
		if err != nil {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}
}

func main() {
	http.HandleFunc("/users/", proxyHandler("user-service"))
	http.HandleFunc("/orders/", proxyHandler("order-service"))

	log.Println("API Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
