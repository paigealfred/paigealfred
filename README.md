# Detection Engineering Portfolio

## About Me

Detection Engineer specializing in SIEM correlation rule development, threat hunting, and network forensics. Proven ability to build detection pipelines, investigate security incidents, and perform deep packet analysis across multiple security tools.

**Currently seeking:** Remote Detection Engineer or SIEM Engineer roles

## Technical Expertise

**SIEM Platforms & Query Languages**
- Splunk Enterprise (SPL) - Correlation searches, real-time alerting, custom field extraction
- Elastic Stack (KQL, Kibana, Logstash) - Detection rules, dashboards, log pipeline design

**Network Security & Forensics**
- Wireshark - Packet capture analysis, protocol investigation, TCP stream reconstruction
- Zeek - Network traffic monitoring and protocol analysis
- Suricata - IDS alert analysis and signature tuning
- Docket - Targeted PCAP extraction and filtering

**Protocol Analysis**
- TCP/IP, DNS, FTP, SMB, SSL/TLS
- Authentication protocols and attack patterns
- Network-based threat detection

**Detection & Response**
- MITRE ATT&CK framework mapping
- Incident investigation and timeline reconstruction
- Alert engineering and false positive reduction
- Threat hunting methodologies
- IOC extraction and correlation

**Security Frameworks**
- NIST 800-61 Incident Response
- Cyber Kill Chain
- PCI DSS
- CVSS scoring

**Programming & Automation**
- Python scripting
- Bash automation
- SPL and KQL query development

---

## Featured Projects

### 🔍 [FTP Data Exfiltration Investigation](https://github.com/paigealfred/ftp-exfiltration-investigation)
**Tools:** Elastic SIEM, Zeek, Wireshark, Docket

Comprehensive investigation of unauthorized file transfer to external infrastructure. Reconstructed complete attack timeline from initial SMB access through FTP exfiltration with precise timestamps.

**Key Results:**
- Traced sensitive document from internal host (172.16.100.3) to external IP (85.93.20.10)
- Analyzed PCAP traffic and identified exact exfiltration timestamp (12:17:15 UTC)
- Correlated SMB file access with FTP transfer using multi-tool analysis
- Documented full attack chain with protocol-level details

---

### 🚨 [SSH Brute Force Detection](https://github.com/paigealfred/splunk-ssh-brute-force-detection)
**Tools:** Splunk, SPL

Built correlation search to detect SSH brute force attacks by identifying patterns of failed login attempts followed by successful authentication.

**Key Results:**
- Engineered SPL queries to analyze 300+ authentication events
- Created real-time alerting for automated SOC escalation
- Developed detection logic correlating failed and successful logins
- Implemented proactive monitoring for authentication-based attacks

---

### 🌐 [Network Scan Forensics Investigation](https://github.com/paigealfred/network-scan-forensics)
**Tools:** Wireshark, Docket

Deep dive PCAP analysis investigating network reconnaissance activity. Used TCP stream reconstruction to trace scan results and identify communication endpoints.

**Key Results:**
- Isolated scan traffic between compromised host and external IP
- Followed TCP streams to reconstruct complete session data
- Identified final scan target (172.16.100.253) before connection termination
- Demonstrated targeted PCAP filtering to reduce noise

---

### 🛡️ [Suricata IDS Alert Analysis](https://github.com/paigealfred/suricata-ids-analysis)
**Tools:** Suricata, Elastic

Analyzed large-scale IDS alert dataset to identify signature patterns and validate detection coverage across network traffic.

**Key Results:**
- Analyzed 109,487 alerts for specific signature pattern
- Used correlation filters to isolate traffic between specific hosts
- Demonstrated understanding of alert severity levels and prioritization
- Showed ability to work with high-volume security telemetry

---

### 📊 [DNS Log Analysis & Field Extraction](https://github.com/paigealfred/splunk-dns-log-analysis)
**Tools:** Splunk, SPL

Ingested and normalized DNS log data to identify communication patterns and potential anomalies through custom field extraction and aggregation.

**Key Results:**
- Created custom field extractions for source IPs, destinations, and domains
- Built SPL queries to aggregate and visualize DNS communication patterns
- Transformed raw log data into structured analysis format
- Demonstrated log parsing and data normalization skills

---

### 📁 [SMB Lateral Movement Investigation](https://github.com/paigealfred/smb-lateral-movement-investigation)
**Tools:** Elastic SIEM, Zeek

Traced internal file access patterns using SMB protocol analysis to identify origin point of sensitive document before external exfiltration. Demonstrated multi-stage attack investigation tracking lateral movement within enterprise network.

**Key Results:**
- Identified SMB protocol as internal file access method before FTP exfiltration
- Traced sensitive document movement from internal host (172.16.100.3) to external server
- Mapped complete attack chain from internal access to external data theft
- Applied KQL file tracking queries to investigate file movement across network protocols

---

### 🔐 [Multi-Protocol C2 Detection](https://github.com/paigealfred/multi-protocol-c2-detection)
**Tools:** Elastic SIEM, Zeek, Wireshark

Identified concurrent SSL/TLS encrypted C2 channel coordinating FTP data exfiltration between same hosts. Demonstrated advanced protocol correlation to detect attacker OPSEC using separate command and control infrastructure.

**Key Results:**
- Discovered SSL/TLS encrypted session operating alongside FTP exfiltration (same source/destination)
- Correlated protocol timing to determine SSL connection was C2 channel coordinating FTP transfers
- Analyzed multi-protocol attack infrastructure showing attacker operational security
- Demonstrated ability to expand investigation beyond single-protocol analysis

---

- **CompTIA CySA+** (Cybersecurity Analyst) - Expected October 2025
- **Splunk Core Certified Power User** - 2025
- **CompTIA Security+** - 2025

## Professional Training

**Elastic SIEM Engineering Professional Course** ($3,000 investment) | 2025  
Advanced detection engineering curriculum covering SIEM architecture, correlation logic, KQL optimization, threat hunting methodologies, and incident investigation. Completed hands-on capstone project with multi-stage threat scenarios.

**TryHackMe Security Labs** | 2025  
Python automation, Linux system administration, network traffic analysis, incident response scenarios

---

## Contact

📧 Email: alfredpaige761@gmail.com  
💼 LinkedIn: [Connect with me](https://www.linkedin.com/in/paige-alfred-1671ba386/)  
📄 Portfolio: [github.com/paigealfred](https://github.com/paigealfred)

---

*All projects demonstrate practical application of detection engineering principles using industry-standard tools and methodologies.*
