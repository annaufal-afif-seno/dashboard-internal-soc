"""
Unified 6-Category & Functional Subcategories Taxonomy Constants
Single source of truth for all layers (DB, backend, frontend via API)
Strictly 6 pure categories with clean, functional subcategories.
"""

# Primary Categories (exact DB values)
class PrimaryCategory:
    ATTACK = "Attack"
    VULNERABILITY = "Vulnerability"
    CONFIGURATION_COMPLIANCE = "Configuration / Compliance"
    IDENTITY_ACCESS = "Identity / Access"
    MALWARE = "Malware"
    SYSTEM_AVAILABILITY = "System / Availability"
    
    ALL = [
        ATTACK,
        VULNERABILITY,
        CONFIGURATION_COMPLIANCE,
        IDENTITY_ACCESS,
        MALWARE,
        SYSTEM_AVAILABILITY
    ]

# Subcategories per primary category (Best Practice SOC & OCSF Aligned)
SUBCATEGORIES = {
    PrimaryCategory.IDENTITY_ACCESS: [
        "Auth Success",
        "Auth Failure",
        "Auth Anomaly",
        "Privilege Escalation"
    ],
    PrimaryCategory.ATTACK: [
        "Web Attack",
        "Exploitation / RCE",
        "Recon / Scan",
        "Command & Control",
        "Lateral Movement"
    ],
    PrimaryCategory.VULNERABILITY: [
        "CVE Detected",
        "Missing Patch / Outdated"
    ],
    PrimaryCategory.CONFIGURATION_COMPLIANCE: [
        "SCA / CIS Benchmark",
        "File Integrity (FIM)",
        "Policy Violation"
    ],
    PrimaryCategory.MALWARE: [
        "Ransomware",
        "Rootkit / Backdoor",
        "Virus / Trojan (YARA)"
    ],
    PrimaryCategory.SYSTEM_AVAILABILITY: [
        "Web Operational",
        "Service Health / Error",
        "Cloud / Container Event"
    ]
}

# Group to Primary Category mapping
GROUP_TO_CATEGORY = {
    # Attack
    "attack": PrimaryCategory.ATTACK,
    "web_attack": PrimaryCategory.ATTACK,
    "sqli": PrimaryCategory.ATTACK,
    "xss": PrimaryCategory.ATTACK,
    "rfi": PrimaryCategory.ATTACK,
    "lfi": PrimaryCategory.ATTACK,
    "web_exploit": PrimaryCategory.ATTACK,
    "recon": PrimaryCategory.ATTACK,
    "web_scan": PrimaryCategory.ATTACK,
    "brute_force": PrimaryCategory.ATTACK,
    "lateral_movement": PrimaryCategory.ATTACK,
    "defense_evasion": PrimaryCategory.ATTACK,
    "execution": PrimaryCategory.ATTACK,
    "persistence": PrimaryCategory.ATTACK,
    "c2": PrimaryCategory.ATTACK,
    "command_and_control": PrimaryCategory.ATTACK,
    "exfiltration": PrimaryCategory.ATTACK,
    "initial_access": PrimaryCategory.ATTACK,
    "discovery": PrimaryCategory.ATTACK,
    
    # Malware
    "malware": PrimaryCategory.MALWARE,
    "ransomware": PrimaryCategory.MALWARE,
    "rootkit": PrimaryCategory.MALWARE,
    "rootcheck": PrimaryCategory.MALWARE,
    "yara": PrimaryCategory.MALWARE,
    "virus": PrimaryCategory.MALWARE,
    "trojan": PrimaryCategory.MALWARE,

    # Vulnerability
    "vulnerability-detector": PrimaryCategory.VULNERABILITY,
    "vulnerability": PrimaryCategory.VULNERABILITY,
    "cve": PrimaryCategory.VULNERABILITY,
    "vuln": PrimaryCategory.VULNERABILITY,

    # Configuration / Compliance
    "syscheck": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "sca": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "config_changed": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "dpkg": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "integrity": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "fim": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "configuration_assessment": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "cis": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "compliance": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "policy": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "pci_dss": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "gdpr": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "nist": PrimaryCategory.CONFIGURATION_COMPLIANCE,

    # Identity / Access
    "authentication_failed": PrimaryCategory.IDENTITY_ACCESS,
    "authentication_failures": PrimaryCategory.IDENTITY_ACCESS,
    "authentication_success": PrimaryCategory.IDENTITY_ACCESS,
    "invalid_login": PrimaryCategory.IDENTITY_ACCESS,
    "login_failed": PrimaryCategory.IDENTITY_ACCESS,
    "login_success": PrimaryCategory.IDENTITY_ACCESS,
    "sudo": PrimaryCategory.IDENTITY_ACCESS,
    "pam": PrimaryCategory.IDENTITY_ACCESS,
    "sshd": PrimaryCategory.IDENTITY_ACCESS,
    "credential_access": PrimaryCategory.IDENTITY_ACCESS,
    "credential_dump": PrimaryCategory.IDENTITY_ACCESS,
    "privilege_escalation": PrimaryCategory.IDENTITY_ACCESS,

    # System / Availability
    "apparmor": PrimaryCategory.SYSTEM_AVAILABILITY,
    "systemd": PrimaryCategory.SYSTEM_AVAILABILITY,
    "docker": PrimaryCategory.SYSTEM_AVAILABILITY,
    "docker-error": PrimaryCategory.SYSTEM_AVAILABILITY,
    "nginx": PrimaryCategory.SYSTEM_AVAILABILITY,
    "apache": PrimaryCategory.SYSTEM_AVAILABILITY,
    "httpd": PrimaryCategory.SYSTEM_AVAILABILITY,
    "agent_flooding": PrimaryCategory.SYSTEM_AVAILABILITY,
    "ossec": PrimaryCategory.SYSTEM_AVAILABILITY,
    "wazuh": PrimaryCategory.SYSTEM_AVAILABILITY,
    "web": PrimaryCategory.SYSTEM_AVAILABILITY,
    "accesslog": PrimaryCategory.SYSTEM_AVAILABILITY,
    "appsec": PrimaryCategory.SYSTEM_AVAILABILITY,
    "web_error": PrimaryCategory.SYSTEM_AVAILABILITY,
    "access_denied": PrimaryCategory.SYSTEM_AVAILABILITY,
    "cloud": PrimaryCategory.SYSTEM_AVAILABILITY,
    "kubernetes": PrimaryCategory.SYSTEM_AVAILABILITY,
    "container": PrimaryCategory.SYSTEM_AVAILABILITY,
    "aws": PrimaryCategory.SYSTEM_AVAILABILITY,
    "azure": PrimaryCategory.SYSTEM_AVAILABILITY,
    "gcp": PrimaryCategory.SYSTEM_AVAILABILITY,
    "local": PrimaryCategory.SYSTEM_AVAILABILITY,
    "syslog": PrimaryCategory.SYSTEM_AVAILABILITY,
}
