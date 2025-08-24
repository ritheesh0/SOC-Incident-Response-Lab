# 🛡️ SOC Incident Response Lab  

This project simulates a **Security Operations Center (SOC) workflow** using real-world cybersecurity artifacts.  
It demonstrates end-to-end skills in **vulnerability assessment, network forensics, log analysis, threat intelligence, incident documentation, and automated response**.  

---

## 📂 Project Structure  

SOC-Incident-Response-Lab/
│── Nessus_Report/nessus_scan_results.html
│── Attack_Analysis/attack_scenario.pcap
│── Windows_Logs/windows_event_logs.csv
│── IOC_Analysis/ioc_list.csv
│── Playbooks/sentinel_playbook.json
│── Incident_Response/hive_case_template.json


---

## 🔎 Analysis  

### 1. Vulnerability Assessment (Nessus)  
**File:** [`nessus_scan_results.html`](./Nessus_Report/nessus_scan_results.html)  

| Severity   | Vulnerability              | CVE            | Host            | Port    | CVSS | Description |
|------------|----------------------------|----------------|-----------------|---------|------|-------------|
| 🔴 Critical | OpenSSH User Enumeration   | CVE-2016-0777  | 192.168.56.110  | 22/tcp  | 9.1  | Info disclosure vulnerability in OpenSSH |
| 🟠 High    | Apache Path Traversal       | CVE-2021-41773 | 192.168.56.110  | 80/tcp  | 8.1  | Allows path traversal on Apache server |
| 🟠 High    | SMBv1 Enabled               | CVE-2017-0144  | 192.168.56.110  | 445/tcp | 8.3  | SMBv1 protocol enabled (EternalBlue exploit possible) |
| 🟡 Medium  | Weak SSH Password Policy    | N/A            | 192.168.56.110  | 22/tcp  | 6.5  | Weak password configuration on SSH service |

**Key Finding:** Multiple high-severity issues, including **SMBv1 (EternalBlue-related)** and **Apache Path Traversal**, make the host highly exploitable.  
**Remediation:** Patch vulnerable services, disable SMBv1, enforce strong SSH password policy.  

---

### 2. Attack Scenario (PCAP Analysis)  
**File:** [`attack_scenario.pcap`](./Attack_Analysis/attack_scenario.pcap)  

- Opened in **Wireshark** for packet inspection.  
- Observations:  
  - 📌 Multiple failed login attempts (brute-force attack on SSH).  
  - 📌 Unusual outbound traffic patterns → possible C2 communication.  
  - 📌 Suspicious source IP matches threat intelligence (see IOC section).  

**Evidence from Wireshark:**  
- Repeated `TCP SYN` packets on port 22 (SSH).  
- Failed authentication messages.  
- Suspicious external IP connections not typical for normal traffic.  

---

### 3. Windows Event Log Analysis  
**File:** [`windows_event_logs.csv`](./Windows_Logs/windows_event_logs.csv)  

Analyzed using Excel/Splunk queries.  

| Event ID | Description | Observation |
|----------|-------------|-------------|
| 4625 | Failed Logon Attempt | Multiple failures from attacker IP (brute-force). |
| 4672 | Special Privileges Assigned | Privilege escalation observed post-compromise. |

**Key Finding:** Confirms brute-force activity from PCAP + shows escalation after successful access.  

---

### 4. IOC Analysis (Threat Intelligence)  
**File:** [`ioc_list.csv`](./IOC_Analysis/ioc_list.csv)  

- IOC file contained **malicious IPs/domains/hashes**.  
- One attacker IP matched with SSH brute-force source.  
- Checked on **VirusTotal** → flagged as malicious.  

**Action:**  
- Block malicious IP at firewall.  
- Monitor for further connections from similar ranges.  

---

### 5. Incident Documentation (TheHive Case)  
**File:** [`hive_case_template.json`](./Incident_Response/hive_case_template.json)  

- Imported into **TheHive** for case management.  
- Case includes:  
  - Attack summary  
  - Affected system (192.168.56.110)  
  - IOCs involved  
  - Recommended remediation steps  

This ensures proper SOC documentation and knowledge sharing.  

---

### 6. Automated Response (Microsoft Sentinel Playbook)  
**File:** [`sentinel_playbook.json`](./Playbooks/sentinel_playbook.json)  

- Playbook designed in **Azure Sentinel (SOAR)**.  
- Automated actions include:  
  - 🚫 Block malicious IP in firewall  
  - 🔒 Disable compromised account  
  - 📢 Send SOC team alerts  

**Benefit:** Reduces manual response time and enables proactive defense.  

---

## 📊 Conclusion  

This lab demonstrates a **complete SOC workflow**:  

1. ✅ Detected vulnerabilities with **Nessus**  
2. ✅ Identified brute-force + C2 via **PCAP (Wireshark)**  
3. ✅ Confirmed attack with **Windows Event Logs**  
4. ✅ Correlated data using **IOC threat intel**  
5. ✅ Documented in **TheHive** for case management  
6. ✅ Automated response with **Sentinel Playbook**  

**Skills Practiced:**  
- Vulnerability Assessment  
- Network Forensics  
- Log Analysis  
- Threat Intelligence  
- Incident Documentation  
- SOAR Automation  

---

## 📌 Author  
👤 **Ritheesh Putta**  
- [LinkedIn](https://www.linkedin.com/in/ritheeshputta)  
- 📧 puttaritheesh@gmail.com  
