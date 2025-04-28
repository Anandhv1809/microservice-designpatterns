package main

import (
	"encoding/json" // For JSON encoding/decoding
	"log"            // For logging
	"net/http"       // For HTTP server
	"sync"           // For concurrent safety (mutex)
)

// User struct defines user data
type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// In-memory storage for users
var users = make(map[string]User)
var mu sync.Mutex // Mutex to protect concurrent access

// Command Handler: Create User
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	// Parse JSON request body
	json.NewDecoder(r.Body).Decode(&user)

	// Lock before writing to shared map
	mu.Lock()
	users[user.ID] = user
	mu.Unlock()

	// Return HTTP 201 Created
	w.WriteHeader(http.StatusCreated)
}

// Query Handler: Get User
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/users/"):]
	
	// Lock before reading from shared map
	mu.Lock()
	user, ok := users[id]
	mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	// Send JSON response
	json.NewEncoder(w).Encode(user)
}

func main() {
	// Route POST /users to createUserHandler
	http.HandleFunc("/users", createUserHandler)
	// Route GET /users/{id} to getUserHandler
	http.HandleFunc("/users/", getUserHandler)

	// Start service on port 8081
	log.Println("CQRS User Service running on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
