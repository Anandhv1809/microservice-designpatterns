package main

import (
	"fmt"      // For printing
	"time"     // For delays
)

// Simulates Order Creation step
func orderCreated(ch chan string) {
	fmt.Println("Saga Step 1: Order Created.")
	time.Sleep(1 * time.Second) // Simulate processing time
	ch <- "OrderCreated"        // Send event
}

// Simulates Payment Processing step
func paymentProcessed(ch chan string) {
	event := <-ch // Wait for OrderCreated event
	if event == "OrderCreated" {
		fmt.Println("Saga Step 2: Payment Processed.")
		time.Sleep(1 * time.Second)
		ch <- "PaymentProcessed" // Send event
	}
}

// Simulates Inventory Update step
func inventoryUpdated(ch chan string) {
	event := <-ch // Wait for PaymentProcessed event
	if event == "PaymentProcessed" {
		fmt.Println("Saga Step 3: Inventory Updated.")
	}
}

func main() {
	ch := make(chan string) // Channel to pass events

	// Run steps asynchronously
	go orderCreated(ch)
	go paymentProcessed(ch)
	go inventoryUpdated(ch)

	// Wait to allow goroutines to finish
	time.Sleep(5 * time.Second)
}
