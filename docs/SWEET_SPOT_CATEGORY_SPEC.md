# Sweet Spot Category Architecture Specification
## Wazuh Alert Grouping Pipeline — 21-Category Taxonomy with OS Dimension

---

### 1. OVERVIEW

This specification defines the revised categorization architecture for the Wazuh alert grouping pipeline, expanding from 9 categories to 21 "Sweet Spot" categories. The design principles are:

1. **Field-Based Classification** — Categories are determined by `rule.groups[]` and `rule.mitre.tactic` fields, NOT by keyword matching on `rule.description`
2. **OS as a Separate Aggregation Dimension** — Operating system is extracted from `agent.labels.os` with `data.win.system.channel` fallback, and added to the deduplication key
3. **Full Precedence Ordering** — A strict 21-tier precedence chain ensures deterministic, consistent classification with highest-threat categories evaluated first
4. **OCSF v1.3 Alignment** — Every category maps to an OCSF class_uid, category_uid, and activity_id

---

### 2. THE 21 SWEET SPOT CATEGORIES

| # | Category Name | Window Class | Window (s) | OCSF class_uid | Description |
|---|---------------|-------------|-----------|----------------|-------------|
| 1 | `RANSOMWARE` | FAST | 300 | 2004 | Ransomware: shadow copy deletion, mass encryption, backup tampering |
| 2 | `MALWARE` | FAST | 600 | 2004 | Virus, trojan, rootkit, YARA match, AV detection |
| 3 | `COMMAND_AND_CONTROL` | FAST | 600 | 4002 | C2 beaconing, DNS tunneling, known-bad IP connections |
| 4 | `EXFILTRATION` | FAST | 600 | 4002 | Data exfiltration, large outbound transfers |
| 5 | `LATERAL_MOVEMENT` | FAST | 600 | 3002 | Admin share, WMI/PSExec/RDP pivot, cross-host auth |
| 6 | `PRIVILEGE_ESCALATION` | FAST | 600 | 3004 | Sudo abuse, UAC bypass, token manipulation |
| 7 | `CREDENTIAL_ACCESS` | FAST | 600 | 3002 | Credential dump, kerberoast, brute force |
| 8 | `DEFENSE_EVASION` | FAST | 600 | 1007 | Log clearing, timestomping, AV disabling |
| 9 | `EXECUTION` | STANDARD | 900 | 1007 | Process creation, script execution, PowerShell |
| 10 | `PERSISTENCE` | STANDARD | 900 | 1007 | Scheduled tasks, cron, registry run keys, webshells |
| 11 | `DISCOVERY` | STANDARD | 900 | 5001 | Network/port scanning, system enumeration |
| 12 | `INITIAL_ACCESS` | STANDARD | 900 | 4001 | Public-facing exploit, drive-by, supply chain |
| 13 | `AUTH_FAILURE` | FAST | 600 | 3002 | Failed login, invalid user, bad password |
| 14 | `AUTH_SUCCESS` | STANDARD | 900 | 3002 | Successful login, session opened |
| 15 | `WEB_ATTACK` | STANDARD | 900 | 4001 | SQLi, XSS, RFI/LFI, web exploit |
| 16 | `WEB_OPERATIONAL` | STANDARD | 900 | 4001 | HTTP 4xx/5xx, web server operational noise |
| 17 | `FILE_INTEGRITY` | SLOW | 1800 | 1001 | FIM: file added, modified, deleted |
| 18 | `VULNERABILITY` | SLOW | 3600 | 2002 | Vulnerability scan findings, CVE detections |
| 19 | `COMPLIANCE` | SLOW | 3600 | 2003 | SCA checks, CIS benchmarks, PCI-DSS/GDPR |
| 20 | `CLOUD_CONTAINER` | STANDARD | 900 | 1010 | Docker, Kubernetes, container lifecycle |
| 21 | `SYSTEM_HEALTH` | SLOW | 1800 | 1004 | Agent status, syscollector, service telemetry |

---

### 3. PRECEDENCE CHAIN (Highest Threat First)

Classification evaluates categories in this strict order. The FIRST match wins.

```
1.  RANSOMWARE          — groups:{ransomware,vssadmin,shadow_copy,backup_tamper} OR tactic=Impact+evasion
2.  MALWARE             — groups:{malware,virus,trojan,rootcheck,yara,rootkit}
3.  COMMAND_AND_CONTROL — groups:{c2,command_and_control,dns_tunnel,beacon} OR tactic=Command and Control
4.  EXFILTRATION        — groups:{exfiltration,data_theft,dns_exfil} OR tactic=Exfiltration
5.  LATERAL_MOVEMENT    — groups:{lateral_movement,admin_share,wmi_exec,psexec} OR tactic=Lateral Movement
6.  PRIVILEGE_ESCALATION— groups:{privilege_escalation,sudo,setuid,uac_bypass} OR tactic=Privilege Escalation
7.  CREDENTIAL_ACCESS   — groups:{credential_access,credential_dump,kerberoast} OR tactic=Credential Access
8.  DEFENSE_EVASION     — groups:{defense_evasion,log_clear,timestomp,amsi_bypass} OR tactic=Defense Evasion
9.  EXECUTION           — groups:{execution,powershell,script,wscript} OR tactic=Execution
10. PERSISTENCE         — groups:{persistence,cron,scheduled_task,webshell} OR tactic=Persistence
11. DISCOVERY           — groups:{discovery,recon,network_scan,port_scan} OR tactic=Discovery/Reconnaissance
12. INITIAL_ACCESS      — groups:{initial_access,exploit,supply_chain} OR tactic=Initial Access
13. AUTH_FAILURE         — groups:{authentication_failed,authentication_failures,invalid_login}
14. AUTH_SUCCESS         — groups:{authentication_success,login_success,session_opened}
15. WEB_ATTACK          — groups:{web_attack,sqli,xss,rfi,lfi,web_exploit,attack}
16. WEB_OPERATIONAL     — groups:{web,apache,nginx,httpd,access_denied} + rule.groups contains "web"
17. FILE_INTEGRITY      — groups:{syscheck,integrity,checksum,fim,file_added,file_modified}
18. VULNERABILITY       — groups:{vulnerability,vulnerability-detector,cve}
19. COMPLIANCE          — groups:{sca,cis,compliance,pci_dss,gdpr,nist,policy}
20. CLOUD_CONTAINER     — groups:{docker,kubernetes,container,cloud,aws,azure,gcp}
21. SYSTEM_HEALTH       — Universal fallback (all unmatched events)
```

---

### 4. OS DIMENSION EXTRACTION

Extraction Priority:
1. `agent.labels.os` — Wazuh agent label (e.g., `"linux"`, `"windows"`, `"macos"`)
2. `data.win.system.channel` — If present → `"windows"`
3. Decoder heuristic — `decoder.name` contains `windows`/`eventchannel` → `"windows"`
4. Location heuristic — `location` contains `EventChannel`/`WinEvtLog` → `"windows"`
5. Rule groups — groups contain `syslog`/`pam`/`sshd` → `"linux"`
6. Default — `"unknown"`

Normalized Values: `linux`, `windows`, `macos`, `unknown`

---

### 5. DEDUPLICATION KEY COMPOSITION (with OS)

```
MD5(category | actor | target | os_platform | tenant_id)
```

---

### 6. MAPPING FROM rule_classification_mapping.json

| Mapping JSON `cat` | → Sweet Spot Category |
|--------------------|-----------------------|
| `AUTHENTICATION` | `AUTH_FAILURE` or `AUTH_SUCCESS` (by groups subtype) |
| `LATERAL_MOVEMENT` | `LATERAL_MOVEMENT` |
| `PRIVILEGE_ESCALATION` | `PRIVILEGE_ESCALATION` |
| `MALWARE` | `MALWARE` |
| `NETWORK_ANOMALY` | `INITIAL_ACCESS` or `DISCOVERY` (by tactic) |
| `DEFENSE_EVASION` | `DEFENSE_EVASION` |
| `POLICY_VIOLATION` | `COMPLIANCE` |
| `DATA_ACCESS` | `EXFILTRATION` or `CREDENTIAL_ACCESS` (by tactic) |
| `PROCESS_EXECUTION` | `EXECUTION` |
| `CONFIGURATION_CHANGE` | `SYSTEM_HEALTH` |
| `PERSISTENCE` | `PERSISTENCE` |
| `VULNERABILITY` | `VULNERABILITY` |
| `CLOUD_CONTAINER` | `CLOUD_CONTAINER` |
| `SYSTEM_HEALTH` | `SYSTEM_HEALTH` |
| `COMPLIANCE` | `COMPLIANCE` |
| `NETWORK_WEB` | `WEB_OPERATIONAL` or `WEB_ATTACK` (by groups) |
| `ENDPOINT_PROCESS` | `EXECUTION` |
| `FILE_INTEGRITY` | `FILE_INTEGRITY` |

---

### 7. CORRELATION RULE CATEGORY UPDATES

| Old Category | → New Category(s) |
|-------------|-------------------|
| `AUTH` | `AUTH_FAILURE`, `AUTH_SUCCESS`, `CREDENTIAL_ACCESS` |
| `HOST` | `EXECUTION`, `PERSISTENCE`, `DEFENSE_EVASION`, `PRIVILEGE_ESCALATION` |
| `NETWORK` | `WEB_ATTACK`, `INITIAL_ACCESS`, `COMMAND_AND_CONTROL`, `DISCOVERY` |

