# ACDC — Automated Cyber Defence & Cryptanalysis Toolkit
*This project was developed during an internship at DRDO (Defence Research and Development Organisation) and is not publicly hosted.*
<img width="1351" height="639" alt="acdc" src="https://github.com/user-attachments/assets/8862ea1f-8a46-4255-bd23-4cdce370b6e4" />

## Overview

ACDC is a Python-based cybersecurity toolkit composed of four powerful modules:
- **Honeypot**: Lures and logs unauthorized access attempts to analyze attacker behavior.
- **Network Traffic Analysis**: Captures and inspects packets to identify suspicious network activity.
- **Endpoint Monitoring**: Keeps track of system-level events and alerts on anomalies.
- **Cryptanalysis**: Performs statistical and pattern-based analysis on encrypted data streams.

These modules are unified under a centralized dashboard for seamless execution, status tracking, and quick interaction—all built in Python using Scapy, regex, sockets, and RESTful APIs.

---

##  Tech Stack

- **Languages & Tools**: Python  
- **Key Libraries**:  
  - `Scapy` (network packet sniffing and crafting)  
  - `re` (regex for parsing and pattern detection)  
  - `socket` (network communication)  
  - Standard libraries and HTTP clients for API integration  
- **Dashboard**: Python-based CLI to orchestrate modules, view logs, and control operations

---

##  Getting Started

### Prerequisites
- Python 3.8+
- Dependencies listed in `requirements.txt` (install via `pip install -r requirements.txt`)

### Installation & Setup
```bash
git clone https://github.com/Shivika2934/acdc.git
cd acdc
pip install -r requirements.txt

