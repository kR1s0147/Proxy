# DDoS Protection System
This project is a robust DDoS Protection System designed to detect and block Distributed Denial-of-Service (DDoS) attacks in real time. It employs entropy-based anomaly detection, multi-layer protection mechanisms, and rate limiting to safeguard systems from common DDoS attack vectors, such as SYN flooding, ICMP flooding, and DNS amplification.

## Features
- Multi-Layer Protection: Shields against multiple types of DDoS attacks, including SYN, ICMP, and DNS amplification attacks.
- Rate Limiting: Implements rate limiting to throttle excessive requests and mitigate abuse.
- Connection Throttling: Drops slow connections to prevent slow-rate DDoS attacks.
- IP Blocking: Automatically blocks malicious IP addresses at the OS level (e.g., using iptables on Linux).
- Real-Time Monitoring: Tracks and logs traffic metrics using Prometheus for monitoring and analytics.
