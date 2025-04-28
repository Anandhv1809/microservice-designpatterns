package main

import (
	"fmt"     // For printing
	"time"    // For sleep timer
)

var failureCount int      // Number of failures
var circuitOpen bool      // Is circuit open?

// Simulates a service call
func callService() error {
	if circuitOpen {
		// If circuit is open, don't call service
		return fmt.Errorf("Circuit is OPEN - fallback triggered")
	}

	// Simulate service failure
	failureCount++
	if failureCount > 3 {
		// After 3 failures, open circuit
		circuitOpen = true
		go resetCircuitAfterDelay()
	}
	return fmt.Errorf("Service failed")
}

// Resets the circuit breaker after some time
func resetCircuitAfterDelay() {
	time.Sleep(5 * time.Second) // Wait before retrying
	circuitOpen = false
	failureCount = 0
	fmt.Println("Circuit RESET - ready for requests")
}

func main() {
	// Try calling the service multiple times
	for i := 0; i < 10; i++ {
		err := callService()
		fmt.Println(err)
		time.Sleep(1 * time.Second)
	}
}
