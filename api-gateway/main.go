package main

import (
	"io"         // for copying HTTP responses
	"log"        // for logging
	"net/http"   // for HTTP server
)

// Simulated service registry
// Map service names to their running address
var serviceRegistry = map[string]string{
	"user-service":  "http://localhost:8081",
	"order-service": "http://localhost:8082",
}

// proxyHandler creates a dynamic handler function
// It forwards the request to the correct service
func proxyHandler(serviceName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Build target URL (base service URL + path from client request)
		targetURL := serviceRegistry[serviceName] + r.URL.Path

		// Forward the HTTP GET request to the target service
		resp, err := http.Get(targetURL)
		if err != nil {
			// If the service is unavailable, return 503 error
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		// Copy the service's response body to the API Gateway response
		io.Copy(w, resp.Body)
	}
}

func main() {
	// Route /users/* to the user service
	http.HandleFunc("/users/", proxyHandler("user-service"))

	// Route /orders/* to the order service
	http.HandleFunc("/orders/", proxyHandler("order-service"))

	// Start the API Gateway on port 8080
	log.Println("API Gateway running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
