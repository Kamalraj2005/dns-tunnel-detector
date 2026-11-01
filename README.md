# Incident Detection for DNS Tunneling Attacks 🛡️

An end-to-end cybersecurity threat detection and incident response prototype engineered to detect, analyze, and reconstruct covert **DNS Tunneling and Data Exfiltration attacks** in real-time or from offline PCAP network captures.

---

## 📌 Problem Statement

> *"Entails the surveillance of DNS traffic for anomalous patterns, such as excessively large or irregular queries, which may suggest the illicit utilization of the DNS protocol to circumvent network security protocols, extract data, or initiate unauthorized communications."*

Standard firewalls and intrusion prevention systems frequently allow outbound Port 53 UDP/TCP traffic without deep payload inspection. Threat actors and malware (e.g., `dnscat2`, `iodine`, Cobalt Strike DNS beacons) exploit this blind spot to:
1. **Exfiltrate confidential enterprise data** (e.g., credit cards, database dumps, passwords) broken into encoded subdomain chunks.
2. **Establish covert Command and Control (C2)** communication channels bypassing network segregation.

---

## 🏗️ Architecture & Detection Methodology

```
┌─────────────────────────────────┐
│     DNS Ingestion Layer         │  (PCAP Captures or Live Sniffing)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│    Feature Extraction Engine    │  - Shannon Entropy (H(X) = -Σ P(x) log2 P(x))
│                                 │  - Lexical / FQDN / Subdomain Analysis
│                                 │  - Hexadecimal, Base64, & Vowel Ratios
│                                 │  - Record Types (TXT, NULL, CNAME)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│    Hybrid Detection Pipeline    │
│  ┌───────────────────────────┐  │  Layer 1: Heuristic & Signature Rules
│  │   Heuristic Rule Engine   │  │  (High entropy, oversized label, covert records)
│  └─────────────┬─────────────┘  │
│  ┌─────────────▼─────────────┐  │  Layer 2: Machine Learning Classifier
│  │  Random Forest Classifier │  │  (Supervised classification across 18 features)
│  └───────────────────────────┘  │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│   Incident Correlation Engine   │  - Client IP & Apex Domain Sessionization
│                                 │  - Cache-Busting DGA Detection
│                                 │  - Exfiltration Volume Metering
│                                 │  - Automated Payload Reconstruction
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│     SOC Incident Dashboard      │  Interactive Streamlit & Plotly Visualizer
└─────────────────────────────────┘
```

---

## 🎯 MITRE ATT&CK® Mapping

| Technique ID | Technique Name | Tactic | Detection Indicator |
| :--- | :--- | :--- | :--- |
| **`T1071.004`** | Application Layer Protocol: DNS | Command and Control | Periodic beaconing, bidirectional TXT/NULL queries |
| **`T1048.003`** | Exfiltration Over Alternative Protocol: DNS | Exfiltration | High-volume chunked base64/hex data inside subdomains |
| **`T1568.002`** | Dynamic Resolution: Domain Generation Algorithms | Defense Evasion / C2 | Excessive ratio of unique, randomized subdomains per apex |

---

## 🚀 Quickstart & One-Click Launchers (Windows)

You can launch any feature simply by double-clicking the included `.bat` files or running them in PowerShell:

| Feature / Tool | One-Click Batch Script | Manual PowerShell Command |
| :--- | :--- | :--- |
| **🌐 SOC Web Dashboard** | `run_dashboard.bat` | `.\.venv\Scripts\streamlit.exe run dashboard/app.py` |
| **📡 Real-Time Network Sniffer** | `run_live_monitor.bat` | `.\.venv\Scripts\python.exe live_monitor.py` |
| **⚡ Live Attack Injector** | `run_attack_demo.bat` | `.\.venv\Scripts\python.exe simulate_attack.py` |
| **🧪 Automated Unit Tests** | `run_tests.bat` | `.\.venv\Scripts\python.exe -m unittest tests/test_pipeline.py` |
| **📁 PCAP File Analyzer** | — | `.\.venv\Scripts\python.exe analyze_pcap.py <file.pcap>` |

---

## 🔐 Zero-Trust Identity & Multi-Factor Authentication (MFA / 2FA)

To ensure enterprise-grade SOC security compliance (**NIST SP 800-63B AAL2** & **PCI-DSS v4.0 Requirement 8.4**), the platform enforces **Zero-Trust Multi-Factor Authentication** before granting access to operational telemetry:

1. **Factor 1 (Knowledge):** Primary operator credentials (Email + Password) mapped to Role-Based Access Control (RBAC).
2. **Factor 2 (Possession):** RFC 6238 Time-Based One-Time Password (**TOTP**) generated on hardware or mobile authenticator apps (**Google Authenticator**, **Microsoft Authenticator**, **1Password**, **Authy**).
3. **1-Click Rapid Evaluation Quick-Pass:** Includes live rolling OTP injection for presentation examiners and evaluators without requiring mobile camera scanning.

### Pre-Configured Evaluation Profiles:

| Operator Identity | Role / Clearance | Login Email | Password | TOTP Secret |
| :--- | :--- | :--- | :--- | :--- |
| **Alex Mercer** | SOC Tier-2 Analyst (`RESTRICTED_INVESTIGATOR`) | `analyst@soc.corp` | `CyberDefense@2026` | `JBSWY3DPEHPK3PXP` |
| **Dr. Sarah Chen** | CISO & Red Team Admin (`FULL_COMMAND_AUTHORITY`) | `admin@soc.corp` | `RootAdmin@2026` | `KRMUY4TFOJQXEZ3T` |

---

### Dashboard Features Overview (8 Interactive Tabs)

1. **🚨 Security Incidents Feed:** Correlated session incidents with threat gauges (0-100), MITRE ATT&CK badges, triggered heuristics, and drill-down logs.
2. **🕵️ Exfiltration Forensics & Decoder:** Automated reassembly and plain-text decoding of chunked Base64, Hexadecimal, and Base32 data leaks.
3. **📈 Telemetry & Profiling:** Plotly visualizations of Shannon Entropy distributions, Query Length vs. Entropy scatter plots, and temporal query velocity.
4. **⚡ Live Single-Domain Inspector:** Real-time sandbox allowing analysts to type any custom domain/FQDN to calculate Shannon Entropy, view all 18 lexical properties, and run ML inferences on demand.
5. **🧠 AI Engine & Rules:** Feature importance breakdown showing how the Random Forest classifier weights mathematical anomalies.
6. **📋 Query Stream & Export:** Filter queries by suspicious/benign, search domains, and export to CSV or JSON SIEM formats.
7. **🧪 Red Team Simulation Lab:** Craft custom secret payloads (credit cards, credentials, bash history), choose attack profiles (Iodine, DNSCat2, Base32), and execute real-time in-app simulation or broadcast live UDP packets to port 53.
8. **🔐 Zero-Trust Identity & MFA:** Real-time authenticator clock health, TOTP synchronization countdown, SOC operator audit trails, and regulatory compliance validation (NIST, PCI-DSS, ISO 27001).

---

## 🔬 Key Detection Features

1. **Shannon Entropy**: Measures randomness of characters. Normal domains score between $2.0 - 3.2$, while encrypted/encoded data chunks exceed $3.85 - 4.8$.
2. **Subdomain Length & Max Label Length**: Tunneling software maximizes label space up to the 63-character RFC limit to achieve higher bandwidth.
3. **Record Type Profiling**: Flags high frequencies of `TXT` and `NULL` queries that carry bidirectional payloads.
4. **Vowel Ratio & Consonant Runs**: Hexadecimal and Base64 payloads have virtually no English vowel distribution, resulting in long consecutive consonant runs ($\ge 7$).
5. **Cache-Busting Ratio**: Detects high numbers of single-use unique subdomains under a single root apex domain.

---

## 📁 Repository Structure

```
dns-tunnel-detector/
├── dashboard/
│   └── app.py                      # Interactive Streamlit SOC Web Application with Glassmorphic MFA
├── data/
│   └── raw_pcaps/                  # Pre-generated sample PCAPs for immediate testing
├── src/
│   ├── auth/
│   │   ├── __init__.py             # Auth package initialization
│   │   └── mfa_manager.py          # RFC 6238 TOTP, QR Generator & RBAC Engine
│   ├── capture/
│   │   ├── pcap_parser.py          # Scapy PCAP extraction engine
│   │   └── live_sniffer.py         # Real-time network interface packet sniffer
│   ├── detection/
│   │   ├── rules.py                # Fast-path heuristic detection rules
│   │   ├── ml_engine.py            # Supervised Random Forest Classifier
│   │   └── incident_engine.py      # Incident correlation, threat scoring & payload decoder
│   ├── features/
│   │   ├── entropy.py              # Shannon entropy & lexical statistics
│   │   ├── lexical.py              # TLD extraction and domain structure parsing
│   │   └── extractor.py            # Complete 18-feature extraction vector
│   └── generator/
│       └── traffic_simulator.py    # Realistic traffic & attack simulator
├── tests/
│   └── test_pipeline.py            # Automated unit test suite (including MFA validation)
├── analyze_pcap.py                 # Standalone CLI PCAP analyzer
├── generate_sample_pcaps.py        # PCAP synthesis generator
├── live_monitor.py                 # Real-time console terminal monitor
├── simulate_attack.py              # Raw UDP packet injector tool
├── requirements.txt                # Frozen Python dependencies
└── README.md
```
