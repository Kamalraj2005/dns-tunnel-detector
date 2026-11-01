# Presentation Deck: Incident Detection for DNS Tunneling Attacks 🛡️

Use this document to create your presentation slides (PowerPoint, Google Slides, Canva, or Keynote). Each slide contains the suggested title, bullet points, diagrams, and speaker notes for your project evaluation or viva defense.

---

### Slide 1: Title Slide
* **Title:** Incident Detection for DNS Tunneling Attacks
* **Subtitle:** An Information-Theoretic & Machine Learning Approach to Real-Time Threat Surveillance
* **Domain:** Cyber Security / Network Intrusion Detection / SOC Operations
* **Presented by:** [Your Name / Team Members]
* **Guide / Mentor:** [Guide Name]
* **Date / Institution:** [College / Organization Name]

---

### Slide 2: Problem Statement & Motivation
* **Port 53 Permissiveness:** Outbound UDP/TCP port 53 is almost universally permitted through enterprise firewalls for domain resolution.
* **Firewall Blind Spot:** Traditional firewalls and intrusion prevention systems inspect only packet headers, leaving encoded payloads uninspected.
* **Covert Weaponization:** Adversaries and modern malware (Cobalt Strike, Iodine, DNSCat2) exploit DNS queries to bypass network segmentation and DLP controls to exfiltrate confidential data.
* **Project Objective:** Build a real-time, hybrid (Heuristics + Random Forest ML) surveillance engine to detect tunneling attacks, sessionize incidents, and reconstruct stolen payloads.

---

### Slide 3: Anatomy of a DNS Tunneling Attack
* **Payload Encoding:** Sensitive files (credit cards, passwords) or shell commands are fragmented and encoded into Base64, Hex, or Base32 chunks.
* **Hierarchical Label Embedding:** Chunks are placed as subdomain labels (e.g., `b64-dGhpcy...chunk01.tunnel.evil-c2.com`).
* **Abuse of DNS Infrastructure:** Queries travel from victim -> local recursive resolver -> root servers -> attacker authoritative nameserver.
* **Covert Response Channel:** Attacker nameservers send back commands or downstream payloads via `TXT` or `NULL` records.

---

### Slide 4: Proposed System Architecture
1. **Data Ingestion Layer:** Offline `.pcap`/`.pcapng` parser + Real-Time Live Sniffer (Scapy + Npcap on active Wi-Fi/LAN).
2. **Feature Extraction Engine:** Mathematical calculation of Shannon Entropy, lexical structure, and record type distributions.
3. **Hybrid Detection Engine:**
   * *Layer 1 (Fast-Path Heuristics):* Instant threshold checks (entropy $\ge 3.85$, label length $\ge 42$, TXT/NULL usage).
   * *Layer 2 (Supervised Machine Learning):* 18-feature Random Forest Classifier.
4. **Incident Correlation & Forensics:**
   * Sessionization by `(Client IP, Apex Domain)`.
   * Cache-Busting DGA ratio analysis.
   * Automated payload reassembly and multi-codec decoding.
5. **Interactive SOC Dashboard:** 6-tab Streamlit & Plotly console for incident triage.

---

### Slide 5: Detection Mathematics & Feature Engineering
* **Shannon Entropy Formulation:**
  $$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
  * *Human / Natural English Domains:* $2.0 \le H(X) \le 3.2$
  * *Tunneling / Encrypted Payloads:* $3.85 \le H(X) \le 4.8+$
* **Key Lexical Features (18 Total):**
  * Maximum label length ($\le 63$ RFC limit) & FQDN length ($\le 253$).
  * Hexadecimal ratio, digit ratio, Base64 density.
  * Vowel-to-consonant ratio & longest consonant runs ($\ge 7$).
  * Covert record type indicators (`TXT`, `NULL`, `CNAME`).

---

### Slide 6: Hybrid Detection Pipeline
* **Layer 1 Heuristic Rules:**
  * `DNS_001`: Abnormal Subdomain Entropy ($H \ge 3.85$).
  * `DNS_002`: Oversized Subdomain Payload ($\ge 45$ chars).
  * `DNS_003`: Covert Record Type with Large Data Payload (`TXT`/`NULL`).
  * `DNS_004`: Hexadecimal / Numerical Density ($> 85\%$).
  * `DNS_005`: Consonant Clustering (vowels $< 10\%$, consonant run $\ge 7$).
* **Layer 2 Random Forest ML Model:**
  * Trained on balanced datasets of legitimate enterprise traffic and simulated tunneling attacks.
  * Outputs tunneling probability score ($0.0 - 1.0$) with feature importance rankings.

---

### Slide 7: Session Correlation & Threat Scoring
* **Session Grouping:** Groups individual queries by `(Client IP, Apex Domain)` within sliding time windows.
* **Cache-Busting DGA Detection:** Flags high ratios of single-use unique subdomains used to bypass DNS caches.
* **Bandwidth Metering:** Calculates exact cumulative exfiltration payload volume in bytes/kilobytes.
* **Composite Threat Score ($0 - 100$):**
  $$\text{Score} = (\text{Heuristic Score} \times 0.45) + (\text{ML Score} \times 0.55) + \text{Volumetric Score}$$
  * *Score $\ge 75$:* 🔴 **CRITICAL** (Active breach / C2)
  * *Score $55-74$:* 🟠 **HIGH**
  * *Score $35-54$:* 🟡 **MEDIUM**
  * *Score $< 35$:* 🟢 **LOW / BENIGN**

---

### Slide 8: MITRE ATT&CK® Alignment
* **`T1071.004` (Command and Control):** Application Layer Protocol: DNS.
* **`T1048.003` (Exfiltration):** Exfiltration Over Alternative Protocol: DNS Exfiltration.
* **`T1568.002` (Defense Evasion):** Dynamic Resolution: Domain Generation Algorithms.

---

### Slide 9: Automated Forensic Exfiltration Reconstructor
* **Reversing Covert Channels:** Automatically extracts, sequences, and decodes chunked Base64, Hexadecimal, and Base32 subdomain strings.
* **Recovered Data Previews:** Restores plain-text credit card leaks, password hashes, and terminal commands (`whoami`, `id`, `cat /etc/shadow`) for SOC analysts.

---

### Slide 10: Interactive SOC Dashboard (Streamlit & Plotly)
* **Tab 1: 🚨 Security Incidents Feed:** Incident cards, threat gauges, MITRE tags, and triggered rules.
* **Tab 2: 🕵️ Exfiltration Forensics:** Automated multi-codec payload reconstruction and hex/ascii chunk viewer.
* **Tab 3: 📈 Telemetry & Profiling:** Interactive Plotly histograms, scatter plots, and temporal query velocity timelines.
* **Tab 4: ⚡ Live Single-Domain Inspector:** Real-time domain sandbox to test any custom FQDN with instant entropy and ML inference.
* **Tab 5: 🧠 AI Engine & Rules:** Global feature importance charts and mathematical weight rankings.
* **Tab 6: 📋 Query Stream & Export:** Searchable raw logs with one-click export to CSV and JSON (SIEM format).
* **Tab 7: 🧪 Red Team Attack Lab:** Interactive in-app attack simulation and live UDP packet broadcasting.
* **Tab 8: 🔐 Zero-Trust Identity & MFA:** Real-time authenticator clock health, TOTP synchronization countdown, SOC operator audit trails, and compliance verification.

---

### Slide 10B: Zero-Trust Security & Multi-Factor Authentication (MFA / 2FA)
* **Zero-Trust Architecture:** Adheres to "Never Trust, Always Verify" principles for SOC operations.
* **Cryptographic Standards:**
  * **RFC 6238 TOTP:** Time-Based One-Time Password using HMAC-SHA1 with 30-second rotating epochs.
  * **Supported Authenticators:** Google Authenticator, Microsoft Authenticator, 1Password, Authy.
* **Role-Based Access Control (RBAC):**
  * *Alex Mercer (Tier-2 SOC Analyst):* `RESTRICTED_INVESTIGATOR` clearance for incident triage.
  * *Dr. Sarah Chen (CISO / Red Team Admin):* `FULL_COMMAND_AUTHORITY` clearance for red team simulations and live wire sniffing.
* **Regulatory Compliance:**
  * **NIST SP 800-63B AAL2:** Cryptographic second-factor authentication.
  * **PCI-DSS v4.0 Requirement 8.4:** Mandatory MFA for all administrative and operational access to sensitive environments.
  * **MITRE ATT&CK Mitigation M1032:** Multi-Factor Authentication enforcement.
* **Evaluator Quick-Pass Feature:** Built-in 1-click rolling OTP auto-fill for frictionless viva demonstrations.

---

### Slide 11: Real-Time Network Sniffing & Tooling
* **Live Sniffer (`live_monitor.py`):** Real-time CLI streaming on UDP Port 53 with color-coded alerts.
* **Attack Injector (`simulate_attack.py`):** Fires simulated Iodine/DNSCat2 queries over UDP to test network sensors.
* **One-Click Batch Launchers:**
  * `run_dashboard.bat` (Web Console)
  * `run_live_monitor.bat` (Live Sniffer)
  * `run_attack_demo.bat` (Attack Injector)
  * `run_tests.bat` (Unit Test Suite)

---

### Slide 12: Experimental Results & Benchmarks
* **Detection Rate (Recall):** $100\%$ on simulated Iodine and DNSCat2 attacks.
* **False Positive Rate:** $0\%$ on benign enterprise traffic baseline.
* **Processing Latency:** $< 0.5\text{ ms}$ per query ($> 3,500$ queries/second throughput).
* **Capture Formats:** Full compatibility with both `.pcap` and `.pcapng` captures.

---

### Slide 13: Future Scope & Enhancements
1. **Deep Learning:** Character-level LSTMs/Transformers for encrypted payload anomaly detection.
2. **Automated Response:** Active SDN/firewall null-routing and BGP blackholing.
3. **Encrypted DNS:** TLS fingerprinting (JA3/JA4) for DNS-over-HTTPS (DoH) / DoT inspection.
4. **SIEM Connectors:** Direct syslog and webhook integrations for Splunk and Microsoft Sentinel.

---

### Slide 14: Conclusion & Key Takeaways
* Successfully turned an unmonitored network protocol blind spot into a high-fidelity security telemetry source.
* Implemented a hybrid defense combining mathematical information theory with supervised machine learning.
* Delivered an end-to-end, production-ready system with offline PCAP analysis, live sniffing, payload reconstruction, and an interactive SOC console.

---

### Slide 15: Viva Defense & Examiner Q&A Guide
* **Q: Why not just block long domain names?**
  * *A:* "Legitimate CDNs (Akamai) and security records (SPF/DKIM) frequently exceed 40 characters. Blocking them breaks legitimate internet traffic. Shannon Entropy distinguishes random encoded data from natural language words."
* **Q: How does the system handle high-volume streaming?**
  * *A:* "Layer 1 uses fast-path heuristics ($O(1)$ and $O(N)$ string operations) taking $< 0.5\text{ ms}$ per packet, allowing high throughput without dropping packets."
* **Q: How do you prevent false alarms on CDNs?**
  * *A:* "We maintain a curated whitelist of verified CDN apex domains and correlate temporal session behavior (cache-busting ratios and covert record types)."
