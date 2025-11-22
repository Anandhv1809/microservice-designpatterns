# microservice-designpatterns

**#--------------------------------------------------------------------------------**

**Design Pattern**            | **Description** 

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

## Tools

### GTP Analyzer

A comprehensive command-line tool for analyzing GTP (GPRS Tunnelling Protocol) packet captures from Wireshark.

**Features:**
- Parse PCAP files and extract GTP packets (GTPv1 and GTPv2)
- Track TEID lifecycles with ASCII diagrams
- Reconstruct complete GTP sessions
- Generate comprehensive statistics
- Export to JSON/CSV formats
- Advanced filtering capabilities

**Quick Start:**
```bash
cd gtp-analyzer
pip install -r requirements.txt
pip install -e .

# Generate sample PCAP for testing
python create_sample_pcap.py

# Analyze GTP traffic
gtp-analyzer stats sample_pcaps/gtp_sample.pcap --teid-summary
gtp-analyzer teid-track sample_pcaps/gtp_sample.pcap 12345
```

📖 **Documentation:** See [gtp-analyzer/README.md](gtp-analyzer/README.md) for complete documentation and [gtp-analyzer/USAGE_EXAMPLES.md](gtp-analyzer/USAGE_EXAMPLES.md) for real-world usage scenarios.

**--------------------------------------------------------------------------------**

Wiki Page Link: https://github.com/Anandhv1809/microservice-designpatterns/wiki

