package main

import "fmt"

// Simulated service registry
var registry = map[string]string{
	"user-service":  "http://localhost:8081",
	"order-service": "http://localhost:8082",
}

// Discover returns the service address
func discover(serviceName string) string {
	return registry[serviceName]
}

func main() {
	// Lookup user-service
	fmt.Println("User Service address:", discover("user-service"))

	// Lookup order-service
	fmt.Println("Order Service address:", discover("order-service"))
}
