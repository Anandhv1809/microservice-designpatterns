package main

import (
	"net/http"  // For HTTP server
)

// Legacy system handler
func legacyHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Legacy Monolithic System"))
}

// New microservice feature handler
func newFeatureHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("New Microservice Feature"))
}

func main() {
	// Route old features to legacy handler
	http.HandleFunc("/legacy/", legacyHandler)

	// Route new features to newFeature handler
	http.HandleFunc("/new-feature/", newFeatureHandler)

	// Start on port 8080
	http.ListenAndServe(":8080", nil)
}
