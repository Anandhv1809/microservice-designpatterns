# microservice-designpatterns

**#--------------------------------------------------------------------------------**
**Pattern**             | **Purpose** 
**#-------------------------------------------------------------------------------**
1. API Gateway          | Single entry point for all microservices 
2. Database per Service | Each service owns its data 
3. CQRS                 | Separate models for reading and writing 
4. Saga Pattern         | Manage distributed transactions across services 
5. Circuit Breaker      | Handle service failure gracefully 
6. Service Discovery    | Locate services dynamically 
7. Sidecar Pattern      | Offload tasks like logging, monitoring from main service 
8. Strangler Pattern    | Gradual migration from monolith to microservices
**--------------------------------------------------------------------------------**

**API Gateway Pattern**
-----------------------

What is API Gateway?
  A single entry point for all microservice requests.
  Instead of clients calling services directly, they call API Gateway.

**Why API Gateway?
  Hide internal microservices details
  Authentication, logging, rate-limiting centralized
  Easier versioning
  
Example Code : api-gateway/main.go
 How to Run
Start API Gateway:
go run main.go
Test:
curl http://localhost:8080/users/1
curl http://localhost:8080/orders/100
