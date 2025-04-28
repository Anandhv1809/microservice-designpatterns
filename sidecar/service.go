package main

import (
	"log"        // For logging
	"net/http"   // For HTTP server
)

// Main service handler
func helloHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[Sidecar Log] Request received") // Sidecar would capture this
	w.Write([]byte("Hello from Main Service"))
}

func main() {
	// Route "/" to helloHandler
	http.HandleFunc("/", helloHandler)

	// Start service on port 8080
	log.Println("Service running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
