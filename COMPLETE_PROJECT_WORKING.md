# Complete Technical Working & Architecture Guide 🛡️
## Incident Detection for DNS Tunneling Attacks (DNS Armor)

---

## 📑 Table of Contents
1. [Executive Summary & Core Mission](#1-executive-summary--core-mission)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Zero-Trust Access Control & MFA Gateway (RFC 6238)](#3-zero-trust-access-control--mfa-gateway-rfc-6238)
4. [Data Ingestion Subsystem (PCAP & Live Wire Sniffing)](#4-data-ingestion-subsystem-pcap--live-wire-sniffing)
5. [Mathematical Feature Engineering & Shannon Entropy](#5-mathematical-feature-engineering--shannon-entropy)
6. [Two-Tier Hybrid Detection Engine](#6-two-tier-hybrid-detection-engine)
   - [Tier 1: Deterministic Heuristic Rules](#tier-1-deterministic-heuristic-rules)
   - [Tier 2: Supervised Random Forest Classifier](#tier-2-supervised-random-forest-classifier)
7. [Session Correlation, Threat Scoring & Exfiltration Forensics](#7-session-correlation-threat-scoring--exfiltration-forensics)
8. [Automated Exfiltration Payload Reconstructor](#8-automated-exfiltration-payload-reconstructor)
9. [Interactive SOC Console (The 8 Operational Tabs)](#9-interactive-soc-console-the-8-operational-tabs)
10. [Red Team Simulation & Tooling Suite](#10-red-team-simulation--tooling-suite)
11. [Compliance Standards & MITRE ATT&CK Mapping](#11-compliance-standards--mitre-attck-mapping)
12. [Viva Defense & Technical Evaluation Guide](#12-viva-defense--technical-evaluation-guide)

---

## 1. Executive Summary & Core Mission

### The Security Vulnerability: Abuse of Port 53
In traditional enterprise networking, **UDP/TCP Port 53 (Domain Name System)** is almost universally permitted through firewalls, proxies, and egress filters to ensure uninterrupted domain resolution.

Intrusion Prevention Systems (IPS) and firewalls typically treat DNS as a stateless utility protocol, inspecting only IP headers and query types without analyzing the lexical structure or information entropy of query names.

Adversaries exploit this design blind spot using covert tools such as:
- **`iodine`**: Establishes an IPv4 tunnel over DNS queries (`NULL`, `TXT`, `CNAME`, `A` records).
- **`dnscat2`**: Creates an interactive command-and-control (C2) shell and stage loader over DNS.
- **Cobalt Strike / Empire DNS Beacons**: Uses low-and-slow polling to exfiltrate database records or bash command histories.

### The Objective of DNS Armor
**DNS Armor** transforms uninspected DNS queries into high-fidelity security telemetry by implementing:
1. **Mathematical Information Theory**: Computing real-time Shannon Entropy ($H(X)$) to distinguish human-readable natural language from encrypted/compressed ciphertext.
2. **Hybrid Detection Engine**: Marrying deterministic heuristic rules with a supervised 18-feature Random Forest ML model.
3. **Session Correlation & Forensics**: Grouping queries into temporal sessions, calculating exfiltration volumes, and reversing multi-codec payloads (Base64, Hexadecimal, Base32).
4. **Zero-Trust MFA Gateway**: Gating operational telemetry behind RFC 6238 TOTP authentication and Role-Based Access Control (RBAC).

---

## 2. End-to-End System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                      INGESTION & TRAFFIC SENSORS                       │
│  - Offline PCAP / PCAPNG Files (Scapy rdpcap / PcapNgReader)           │
│  - Real-Time Wire Sniffing (Scapy AsyncSniffer on UDP port 53 via Npcap)│
│  - Live Attack Simulator (Raw UDP injection / Synthetic Generator)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Raw DNS Packets
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   FEATURE EXTRACTION SUBSYSTEM                         │
│  - Shannon Entropy Engine: H(X) = -Σ P(x) log2 P(x)                    │
│  - Lexical Parser: FQDN, Apex Domain, Subdomain, RFC 1035 Label Limits │
│  - Character Distribution: Hex Ratio, Vowel Ratio, Consonant Clusters  │
│  - Record Type Profiler: A, TXT, NULL, CNAME, AAAA, MX                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ 18-Dimensional Feature Vector
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     HYBRID DETECTION PIPELINE                          │
│  ┌─────────────────────────────┐     ┌──────────────────────────────┐  │
│  │ Tier 1: Fast Heuristics     │     │ Tier 2: Random Forest ML     │  │
│  │ 6 Expert Detection Rules    │     │ 50 Decision Trees, Depth 6   │  │
│  │ Heuristic Score (0 - 100)   │     │ Anomaly Probability (0 - 1)  │  │
│  └──────────────┬──────────────┘     └──────────────┬───────────────┘  │
│                 │                                   │                  │
│                 └─────────────────┬─────────────────┘                  │
│                                   │ Composite Threat Score             │
│                                   ▼                                    │
│                 Query Score = 0.45(Heur) + 0.55(ML)                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Query Stream Records
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                SESSION CORRELATION & FORENSIC DECODER                  │
│  - Sliding Window Sessionizer: Grouped by (Client IP, Apex Domain)     │
│  - Cache-Busting DGA Detection: Unique Subdomain Ratio                 │
│  - Cumulative Payload Volume Metering (Bytes/KB)                       │
│  - Automated Multi-Codec Reconstructor: Base64 / Hex / Base32 Decoder  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Correlated Security Incidents
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      ENTERPRISE SOC CONSOLE                            │
│  - Zero-Trust Authentication Gateway (NIST SP 800-63B / RFC 6238 TOTP) │
│  - 8 Interactive Glassmorphic Radar Tabs & Plotly Visualizations       │
│  - SIEM / SOAR JSON & CSV Export Facilities                            │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Zero-Trust Access Control & MFA Gateway (RFC 6238)

To enforce enterprise data privacy and comply with **NIST SP 800-63B Authenticator Assurance Level 2 (AAL2)** and **PCI-DSS v4.0 Requirement 8.4**, the console is locked behind a strict two-factor gatekeeper (`src/auth/mfa_manager.py`).

### Verification Steps:
1. **Factor 1 (Knowledge):** Primary operator credentials (Email + Password) mapped to Role-Based Access Control (RBAC).
2. **Factor 2 (Possession):** Cryptographic Time-based One-Time Password (TOTP) generated under **RFC 6238** (HMAC-SHA1, 30-second rotating window, 6 digits).

### Authenticator Device Integration:
- The backend generates standard provisioning URIs: `otpauth://totp/DNS-Armor-SOC:user?secret=...&issuer=DNS-Armor-SOC`
- Converts the URI into an inline Base64 PNG QR code readable by **Google Authenticator**, **Microsoft Authenticator**, **1Password**, and **Authy**.
- **Clock Drift Tolerance:** The verification engine evaluates `valid_window=1`, permitting $\pm 30$ seconds of drift between client device and server clock.
- **Viva Evaluator Quick-Pass:** Provides a 1-click live OTP injection button for testing and evaluation without requiring mobile camera scanning.

### Pre-Configured Operator Roles:

| Operator Identity | Role Title | Access Clearance Level | Login Email | Master Password | Base32 TOTP Secret |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Alex Mercer** | SOC Tier-2 Analyst | `RESTRICTED_INVESTIGATOR` | `analyst@soc.corp` | `CyberDefense@2026` | `JBSWY3DPEHPK3PXP` |
| **Dr. Sarah Chen** | CISO & Red Team Lead | `FULL_COMMAND_AUTHORITY` | `admin@soc.corp` | `RootAdmin@2026` | `KRMUY4TFOJQXEZ3T` |

---

## 4. Data Ingestion Subsystem (PCAP & Live Wire Sniffing)

### A. Offline PCAP & PCAPNG Parsing (`src/capture/pcap_parser.py`)
- Uses **Scapy** to read both standard `.pcap` files and next-generation `.pcapng` files.
- Employs an intelligent fallback mechanism: if `scapy.all.rdpcap` raises an exception on modern block types, it automatically transitions to `scapy.utils.PcapNgReader`.
- **Deduplication Engine:** Tracks query transaction IDs and packet timestamps `(dns_id, qname, qtype)`. If a DNS request query is echoed in a server response packet (`qr == 1`), the duplicate is filtered to avoid double-counting payload bytes.
- **In-Memory Streaming:** Handles raw bytes uploaded via browser without leaving lingering files on disk (`tempfile.NamedTemporaryFile` with Windows-safe file handles).

### B. Live Network Wire Sniffing (`src/capture/live_sniffer.py`)
- Employs Scapy's non-blocking `AsyncSniffer` bound to active network adapters (Wi-Fi, Ethernet, or Virtual Switch).
- Uses Kernel-level Berkeley Packet Filters (**BPF**): `"udp port 53"`.
- Intercepts outbound and inbound queries on the wire, extracts source IP, destination IP, packet size, and query records, and feeds them directly into the real-time detection pipeline with sub-millisecond latency.
- Supported on Windows via the **Npcap** packet capture driver.

---

## 5. Mathematical Feature Engineering & Shannon Entropy

Each intercepted query is parsed into an 18-dimensional numerical feature vector (`src/features/extractor.py`).

### Shannon Information Entropy Formula
Information entropy measures the degree of uncertainty, randomness, or information density contained within a string:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where:
- $n$ is the total number of unique characters appearing in the domain/subdomain string.
- $P(x_i)$ is the empirical probability of occurrence of character $x_i$ ($P(x_i) = \frac{\text{count}(x_i)}{\text{total length}}$).
- $\log_2$ measures information in bits.

### Entropy Threshold Interpretations:
- **Natural Language / Normal Domains:** $2.0 \le H(X) \le 3.2$ (e.g., `mail.google.com`, `api.github.com`).
- **CDN / Sharded Endpoints:** $3.2 < H(X) \le 3.7$ (e.g., `e1029.g.akamaiedge.net`).
- **Encrypted / Base64 / Hex Tunneling:** $3.85 \le H(X) \le 4.8+$ (e.g., `b64-dGhpcyBpcyBhIHNlY3Jld...`).

### The 18 Extracted Features:

| Index | Feature Name | Mathematical / Structural Meaning |
| :---: | :--- | :--- |
| **1** | `fqdn_len` | Total character length of Fully Qualified Domain Name ($\le 253$ RFC limit). |
| **2** | `subdomain_len` | Character length of the subdomain containing the exfiltrated payload. |
| **3** | `subdomain_entropy` | Shannon Entropy $H(X)$ calculated specifically over the subdomain. |
| **4** | `fqdn_entropy` | Shannon Entropy $H(X)$ calculated across the entire FQDN. |
| **5** | `max_label_len` | Length of the longest dot-separated label ($\le 63$ RFC 1035 limit). |
| **6** | `avg_label_len` | Mean character length across all labels in the domain. |
| **7** | `label_count` | Number of dot-separated hierarchical segments. |
| **8** | `digit_ratio` | Ratio of numeric digits ($0-9$) to total characters. |
| **9** | `hex_ratio` | Ratio of hexadecimal characters ($0-9, a-f$) to total length. |
| **10** | `vowel_ratio` | Ratio of English vowels ($a, e, i, o, u$) to total letters. |
| **11** | `consonant_ratio` | Ratio of consonants to total letters. |
| **12** | `longest_consonant_run` | Longest uninterrupted sequence of consonants (unpronounceability metric). |
| **13** | `base64_ratio` | Density of Base64 alphabet characters ($A-Z, a-z, 0-9, +, /, =, -, \_$). |
| **14** | `unique_char_ratio` | Ratio of unique character alphabet size to total string length. |
| **15** | `is_txt_record` | Binary indicator ($1$ if query type is `TXT`, otherwise $0$). |
| **16** | `is_null_record` | Binary indicator ($1$ if query type is `NULL` / `TYPE_10`, otherwise $0$). |
| **17** | `is_cname_record` | Binary indicator ($1$ if query type is `CNAME`, otherwise $0$). |
| **18** | `is_a_record` | Binary indicator ($1$ if query type is `A` or `AAAA`, otherwise $0$). |

---

## 6. Two-Tier Hybrid Detection Engine

The system uses a two-tier hybrid architecture combining deterministic rules with machine learning.

```
                    Raw Feature Vector
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
┌───────────────────────┐       ┌───────────────────────┐
│ Tier 1: Rule Engine   │       │ Tier 2: Random Forest │
│ Fast Heuristics       │       │ 50 Decision Trees     │
│ Score: 0 to 100       │       │ Probability: 0 to 1   │
└───────────┬───────────┘       └───────────┬───────────┘
            │                               │
            └───────────────┬───────────────┘
                            ▼
            Composite Query Threat Score:
         Score = (Heuristic * 0.45) + (ML * 0.55)
```

### Tier 1: Deterministic Heuristic Rules (`src/detection/rules.py`)

1. **`DNS_TUNNEL_001_HIGH_ENTROPY` (Weight: 25-35):**
   - Triggers when `subdomain_len >= 16` and `subdomain_entropy >= 3.85`.
   - Distinguishes high-density compressed/encrypted payloads.
2. **`DNS_TUNNEL_002_OVERSIZED_LABEL` (Weight: 25):**
   - Triggers when `subdomain_len >= 45` or `max_label_len >= 42`.
   - Threat actors maximize label bandwidth up to the RFC limit of 63 bytes.
3. **`DNS_TUNNEL_003_COVERT_RECORD_TYPE` (Weight: 25):**
   - Triggers when `record_type in ("TXT", "NULL", "TYPE_10")` and `subdomain_len >= 20`.
   - Identifies bidirectional high-bandwidth channels used by Iodine and DNSCat2.
4. **`DNS_TUNNEL_004_HEX_ENCODING` (Weight: 20):**
   - Triggers when `hex_ratio >= 0.85` or `digit_ratio > 0.40`.
   - Flags raw byte dumps converted into hex strings.
5. **`DNS_TUNNEL_005_LOW_VOWEL_RUN` (Weight: 20):**
   - Triggers when `vowel_ratio < 0.10` and `longest_consonant_run >= 7`.
   - Natural human domain names obey phonetic syllable rules. Encoded chunks contain long consonant runs without vowels.
6. **`DNS_TUNNEL_006_DEEP_HIERARCHY` (Weight: 15):**
   - Triggers when `label_count >= 4` and `subdomain_entropy >= 3.6`.
   - Detects multi-segment chunking structures (`chunk01.part02.tunnel.c2.com`).

*Curated Whitelist Bypass:* Verifies against known high-entropy CDN apexes (`akamaiedge.net`, `cloudfront.net`, `fastly.net`, `azureedge.net`) to prevent false positives on legitimate CDN traffic.

### Tier 2: Supervised Random Forest Classifier (`src/detection/ml_engine.py`)
- **Model Parameters:** `RandomForestClassifier(n_estimators=50, max_depth=6, random_state=42)`.
- Trained on balanced feature vectors of verified benign corporate lookups and representative attack tooling (`iodine`, `dnscat2`, Cobalt Strike).
- Emits continuous tunneling probabilities ($0.0 - 1.0$) and anomaly scores ($0.0 - 100.0\%$).
- Exports Global Feature Importance rankings for transparency and explainability.

---

## 7. Session Correlation, Threat Scoring & Exfiltration Forensics

Individual DNS queries are sessionized to detect cumulative attack patterns (`src/detection/incident_engine.py`).

### Sessionization Grouping
Queries are correlated by the 2-tuple:

$$\text{Session Key} = (\text{Client IP}, \text{Apex Domain})$$

Within sliding 300-second time windows.

### Behavioral Anomaly Indicators
1. **Cache-Busting Ratio:** Threat actors use unique, random subdomains for every query to force recursive resolvers to forward queries to their authoritative nameserver instead of answering from cache. The engine flags sessions where unique subdomains exceed 70% of total volume.
2. **Query Velocity:** Detects high-frequency bursts ($\ge 2.0\text{ queries/second}$).
3. **Covert Record Dominance:** Measures ratio of `TXT` and `NULL` queries relative to total volume.
4. **Bandwidth Metering:** Calculates exact cumulative bytes carried across subdomains.

### Composite Incident Threat Score Formulation
$$\text{Threat Score} = \min\left(100, (\text{Mean Query Threat} \times 0.65) + (\text{Behavioral Score} \times 0.35)\right)$$

### Incident Severity Tiers:
- **`CRITICAL` (Score $\ge 75$):** Active high-volume data exfiltration or interactive C2 session.
- **`HIGH` (Score $55 - 74$):** Consistent tunneling signatures with anomalous entropy.
- **`MEDIUM` (Score $35 - 54$):** Anomalous lexical properties or unclassified record types.
- **`LOW` (Score $< 35$):** Minor statistical deviations; non-tunneling traffic.

---

## 8. Automated Exfiltration Payload Reconstructor

When an incident is flagged, the forensics engine extracts and decrypts exfiltrated data:

1. **Prefix Stripping:** Removes sequencing markers (e.g., `b64-`, `exfil-`, `chunk01-`, `dnscat.`, `data-`).
2. **Stream Sequencing:** Reassembles chunked fragments into contiguous byte streams.
3. **Multi-Codec Decoding:**
   - **Base64 Decoder:** Resolves standard RFC 4648 Base64 strings with padding correction.
   - **Hexadecimal Decoder:** Converts even-length hex strings into ASCII bytes.
   - **Base32 Decoder:** Handles alphanumeric 32-character alphabet payloads.
4. **Printable ASCII Sanitization:** Strips non-printable control characters to prevent terminal corruption.
5. **Human-Readable Previews:** Displays reconstructed strings (credit cards, DB credentials, shell commands) on the analyst's dashboard.

---

## 9. Interactive SOC Console (The 8 Operational Tabs)

The Streamlit dashboard (`dashboard/app.py`) provides an interactive interface organized into 8 tabs:

| Tab | Name | Operational Purpose |
| :---: | :--- | :--- |
| **1** | **🚨 Security Incidents** | Correlated incident cards with threat score gauges (0-100), MITRE tags, triggered rules, and drill-down logs. |
| **2** | **🕵️ Exfiltration Forensics** | Reconstructed plain-text payload viewer, exfiltration metrics (bytes/KB), and chunk sequencing tables. |
| **3** | **📈 Telemetry & Profiling** | Plotly charts of Shannon Entropy distributions, Query Length vs. Entropy scatter plots, and temporal query timelines. |
| **4** | **⚡ Live Domain Inspector** | Real-time sandbox allowing analysts to type any custom FQDN to calculate Shannon Entropy, view all 18 lexical properties, and run ML inferences on demand. |
| **5** | **🧠 AI Engine & Rules** | Random Forest feature importance distributions and mathematical weight rankings. |
| **6** | **📋 Query Stream & Export** | Filterable raw query logs with one-click export to **CSV** and **JSON (SIEM format)**. |
| **7** | **🧪 Red Team Simulation Lab** | Interactive payload injection tool allowing analysts to craft custom exfiltration data, choose attack profiles, and broadcast live UDP packets to port 53. |
| **8** | **🔐 Zero-Trust Identity & MFA** | Real-time authenticator clock health, TOTP synchronization countdown, operator audit trails, and compliance verification. |

---

## 10. Red Team Simulation & Tooling Suite

The platform includes a complete suite of CLI tools and simulators:

| Script / Tool | Functionality | Execution Command |
| :--- | :--- | :--- |
| **`dashboard/app.py`** | Modern SOC Web Console with MFA Gateway | `.\.venv\Scripts\streamlit.exe run dashboard/app.py` |
| **`live_monitor.py`** | Real-time terminal sniffer streaming UDP 53 packets | `.\.venv\Scripts\python.exe live_monitor.py` |
| **`simulate_attack.py`** | Injects real UDP DNS tunneling packets on Port 53 | `.\.venv\Scripts\python.exe simulate_attack.py` |
| **`analyze_pcap.py`** | Standalone CLI analyzer for `.pcap` and `.pcapng` files | `.\.venv\Scripts\python.exe analyze_pcap.py <file.pcap>` |
| **`generate_sample_pcaps.py`** | Synthesizes realistic benign and attack capture files | `.\.venv\Scripts\python.exe generate_sample_pcaps.py` |
| **`tests/test_pipeline.py`** | Unit test suite (8 tests covering entropy, ML, PCAP, MFA) | `.\.venv\Scripts\python.exe -m unittest tests/test_pipeline.py` |

---

## 11. Compliance Standards & MITRE ATT&CK Mapping

### MITRE ATT&CK® Enterprise Matrix
- **`T1071.004` (Command and Control):** Application Layer Protocol: DNS.
  * *Detection:* Periodic beaconing, bidirectional `TXT`/`NULL` command channels.
- **`T1048.003` (Exfiltration):** Exfiltration Over Alternative Protocol: DNS Exfiltration.
  * *Detection:* High-volume chunked Base64/Hex exfiltration payloads in subdomains.
- **`T1568.002` (Defense Evasion):** Dynamic Resolution: Domain Generation Algorithms.
  * *Detection:* High ratio of single-use randomized subdomains under a single apex.

### Enterprise Compliance Frameworks
- **NIST SP 800-63B AAL2:** Cryptographic second-factor authentication (RFC 6238 TOTP).
- **PCI-DSS v4.0 Requirement 8.4:** Multi-factor authentication enforced for administrative and operational access.
- **MITRE ATT&CK Mitigation M1032:** Multi-Factor Authentication enforcement.
- **ISO/IEC 27001 Control A.9.4.2:** Secure user log-on procedures with audit trails.

---

## 12. Viva Defense & Technical Evaluation Guide

### Expected Panel Questions & Model Answers

#### Q1: Why not simply block domain names longer than 40 characters?
> **Answer:** "Hard-limiting domain length causes widespread false positives. Modern Content Delivery Networks (Akamai, AWS CloudFront) and cryptographic email verification records (DKIM, SPF) legitimately exceed 45 characters. Blocking them breaks legitimate internet traffic. DNS Armor uses Shannon Entropy to differentiate random encoded ciphertext from natural-language CDN names."

#### Q2: How does Shannon Entropy identify encrypted data?
> **Answer:** "Natural language English text has predictable character frequencies (e.g., 'e', 't', 'a' appear much more frequently than 'z' or 'q'), yielding entropy values between 2.0 and 3.2. Strong encryption, compression, or Base64 encoding flattens character distributions, pushing Shannon Entropy above 3.85 to 4.8. This allows us to detect encrypted data without needing decryption keys."

#### Q3: Why is DNS Tunneling difficult for traditional firewalls to detect?
> **Answer:** "Firewalls and stateless packet filters check Layer 3/4 headers (port 53 UDP/TCP). They verify that a DNS packet conforms to basic protocol formats, but do not inspect the content of the subdomain query string. Attackers take advantage of this by breaking sensitive files into small chunks and encoding them as subdomains."

#### Q4: What is the purpose of the Two-Tier Hybrid Detection model?
> **Answer:** "Tier 1 uses heuristic rules that execute in sub-millisecond time ($< 0.5\text{ ms}$), handling high-volume packet ingestion without dropping packets. Tier 2 uses a Random Forest classifier that detects subtle statistical anomalies that may bypass rigid threshold rules. Together, they provide both speed and high recall."

#### Q5: Why was Zero-Trust MFA integrated into this project?
> **Answer:** "In an enterprise SOC, incident telemetry and the payload reconstructor display reconstructed data—including recovered credit card numbers, password hashes, and bash histories. Unrestricted access creates data leakage risks. Integrating RFC 6238 TOTP ensures compliance with NIST SP 800-63B and PCI-DSS 4.0 standards."
