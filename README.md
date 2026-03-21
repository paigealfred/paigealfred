# Cybersecurity Portfolio

## About Me
Cybersecurity professional specializing in Detection Engineering, SIEM operations, and Identity & Access Management. Experienced in building detection pipelines, developing correlation rules, investigating security incidents, and implementing enterprise IAM solutions across cloud and on-premises environments.

## Technical Expertise

### SIEM Platforms & Query Languages
* **Splunk Enterprise (SPL)** - Correlation searches, real-time alerting, custom field extraction
* **Elastic Stack (KQL, Kibana, Logstash)** - Detection rules, dashboards, log pipeline design

### Identity & Access Management
* **Microsoft Entra ID (Azure AD)** - User provisioning, RBAC, Conditional Access policies
* **Privileged Access Management** - Role assignments, zero-trust implementation
* **Identity Governance** - Security groups, least privilege access control
* **Privileged Access Management:** Implemented foundational PAM principles through role segregation, least privilege assignments, and MFA enforcement for administrative accounts via Conditional Access policies.

### Network Security & Forensics
* **Wireshark** - Packet capture analysis, protocol investigation, TCP stream reconstruction
* **Zeek** - Network traffic monitoring and protocol analysis
* **Suricata** - IDS alert analysis and signature tuning
* **Docket** - Targeted PCAP extraction and filtering

### Protocol Analysis
* TCP/IP, DNS, FTP, SMB, SSL/TLS
* Authentication protocols and attack patterns
* Network-based threat detection

### Detection & Response
* MITRE ATT&CK framework mapping
* Incident investigation and timeline reconstruction
* Alert engineering and false positive reduction
* Threat hunting methodologies
* IOC extraction and correlation

### Security Frameworks
* NIST 800-61 Incident Response
* Cyber Kill Chain
* PCI DSS
* CVSS scoring

### Programming & Automation
* Python scripting
* Bash automation
* PowerShell (Azure AD module)
* SPL and KQL query development

### Cribl & SIEM Migration
* Cribl Stream pipeline design and log routing
* Splunk HEC endpoint configuration (token-based auth, port 8088)
* Key=value and JSON log parsing for firewall and Windows Security logs
* Field normalization for SIEM/data-lake analytics (IPs, users, actions, zones, etc.)
* Log routing and filtering to multiple destinations (SIEM + data lake)
* AWS S3 integration for cold log storage (buckets, prefixes, gzip)
* AWS IAM user/access key configuration for secure log delivery
* Log volume reduction and optimization for cost/performance

## Certifications
* CompTIA Security+
* CompTIA CySA+
* Splunk Core Certified Power User
---

## Featured Projects

### 🛡️ [SSH Brute Force Detection Pipeline](https://github.com/paigealfred/SSH-Brute-Force-Detection---End-to-End-Detection-Engineering-Pipeline)
**Tools:** Cribl.Cloud, Elastic Cloud, PowerShell, MITRE ATT&CK

Built an end to end detection engineering pipeline for T1110.001 Brute Force: Password Guessing. Took raw Linux syslog authentication events, routed them through Cribl Stream for ECS normalization, landed the data in Elastic Cloud, and wrote a detection rule that fires on the spray to success pattern.

**Key Results:**
* Built a 3 function Cribl pipeline (Parser, Rename, Eval) that normalizes raw syslog to ECS including host.name, source.ip, user.name, event.outcome, and event.action
* Sent fake auth logs from a Windows machine to Cribl.Cloud via UDP using PowerShell confirming full ingestion of 14 events
* Wrote and validated a KQL detection query in Kibana Discover returning 11 matching documents across the brute force sequence
* Created a Kibana Elasticsearch query rule with threshold tuning and documented a SOC playbook covering what to check when encountered and when to escalate

### 🔒 [Cribl Stream Sensitive Data Redaction Pipeline](https://github.com/paigealfred/Cribl-Stream-Sensitive-Data-Redaction-Pipeline)
**Tools:** Cribl Stream, Regex, VS Code

Built a sensitive data redaction pipeline in Cribl Stream that intercepts log data in transit and masks PII, PCI, and PHI fields before they reach downstream destinations, ensuring compliance with PCI DSS and HIPAA requirements.

**Key Results:**
* Configured 5 Mask functions using custom regex rules targeting credit cards, SSNs, passwords, API tokens, and email addresses
* Applied Luhn-format card number detection covering Visa, Mastercard, Amex, and Discover patterns
* Validated full redaction across 6 synthetic log events confirming zero sensitive data reaches downstream systems
* Exported pipeline as importable JSON for version control and redeployment across environments

### 🔁 [Splunk to Elastic Pipeline via Cribl Stream](https://github.com/paigealfred/Splunk-to-Elastic-Pipeline-via-Cribl-Stream)
**Tools:** Cribl Stream, Splunk Enterprise, Elastic Cloud, Kibana

Configured a Cribl Stream pipeline to ingest logs from Splunk Enterprise via TCP forwarding, normalize and map fields into ECS-compliant schema, and route processed data to Elastic Cloud. Validated end-to-end pipeline functionality in Kibana Discover confirming field extraction accuracy across 807+ ingested documents.

**Key Results:**
- Forwarded Splunk Enterprise logs to Cribl Stream via TCP on port 9997
- Built normalization pipeline mapping Splunk fields to ECS schema with 33 output fields
- Delivered processed events to Elastic Cloud index `splunk-logs` via authenticated Elasticsearch bulk API
- Confirmed 807+ documents ingested and queryable in Kibana Discover with full field fidelity

### 🧱 [Cribl Stream Log Normalization Pipeline](https://github.com/paigealfred/Cribl-Stream-Log-Normalization-Pipeline)
**Tools:** Cribl Stream (Cribl.Cloud), AWS S3, AWS IAM, PowerShell  

Built an end-to-end log pipeline that ingests firewall and Windows Security logs over a Splunk-compatible HEC endpoint, normalizes key fields, and archives compressed events into AWS S3 to simulate SIEM/data-lake migration work.

**Key Results:**
* Configured Splunk HEC-compatible input on port 8088 with token-based authentication  
* Built `palo_alto_traffic` and `wineventlogs` pipelines for key=value and JSON log formats  
* Normalized core fields such as `src_ip`, `dst_ip`, `action`, `user`, and `zone_src/zone_dst` for analytics  
* Implemented routing logic to send only `sourcetype=pan:traffic` events to the S3 cold archive  
* Deployed AWS S3 destination (`cribl-security-logs-paige`) with gzip compression for long-term storage  
* Secured S3 access using a dedicated IAM user and access keys configured in Cribl

### 🔑 [Azure Entra ID IAM Lab](https://github.com/paigealfred/Azure-Entra-ID-Identity-Access-Management-Lab)
**Tools:** Microsoft Entra ID, Azure Portal, Entra ID Premium P1, PowerShell

Configured enterprise identity and access management in Microsoft Entra ID with user provisioning, RBAC role assignments, security group management, and Conditional Access policies enforcing MFA for privileged accounts.

**Key Results:**
* Provisioned 5 users with role-based security group assignments
* Implemented RBAC with 3 administrative roles following least privilege principles
* Created 4 security groups for department-based access control
* Deployed Conditional Access policy enforcing MFA for IT_Admins group
* Configured zero-trust security controls in report-only mode for testing
* Demonstrated PAM principles through privileged account segregation

### 🐍 [Python Automated Brute Force Attempt](https://github.com/paigealfred/Brute-Force-Detection-Alert-Automation)
**Tools:** Python, CSV

Automated SOC tool that monitors authentication logs for SSH brute force attacks, detects suspicious activity based on configurable thresholds, and generates severity-based alerts for incident response.

**Key Results:**
- Built automated log parsing system analyzing authentication events
- Created real-time alerting with configurable detection thresholds (5+ failed attempts)
- Developed severity classification logic (high/medium risk levels)
- Implemented CSV export for SOC workflow integration
- Reduced manual log review through dictionary-based tracking
  
---

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

### 🔐 [Multi-Protocol C2 Detection](https://github.com/paigealfred/Multi-Protocol-Correlation-C2-Channel-Detection-)
**Tools:** Elastic SIEM, Zeek

Identified concurrent SSL/TLS encrypted C2 channel coordinating FTP data exfiltration between same hosts. Demonstrated advanced protocol correlation to detect attacker OPSEC using separate command and control infrastructure.

**Key Results:**
- Discovered SSL/TLS encrypted session operating alongside FTP exfiltration (same source/destination)
- Correlated protocol timing to determine SSL connection was C2 channel coordinating FTP transfers
- Analyzed multi-protocol attack infrastructure showing attacker operational security
- Demonstrated ability to expand investigation beyond single-protocol analysis

---

- **CompTIA CySA+** (Cybersecurity Analyst) - 2025
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
