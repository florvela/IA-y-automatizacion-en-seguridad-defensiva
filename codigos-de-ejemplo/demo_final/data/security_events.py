"""
Dataset de eventos de seguridad etiquetados para el clasificador NLP.

Cada entrada es una tupla (descripción_del_evento, categoría).
Categorías:
  - DATA_EXFILTRATION
  - MALWARE_EXECUTION
  - LATERAL_MOVEMENT
  - CREDENTIAL_COMPROMISE
  - RECONNAISSANCE
"""

TRAINING_DATA = [
    # ── DATA_EXFILTRATION ──────────────────────────────────────────────────
    ("Large outbound data transfer to external IP, 271MB sent in 14 minutes",           "DATA_EXFILTRATION"),
    ("Unusual upload volume from workstation to unknown cloud storage",                  "DATA_EXFILTRATION"),
    ("HTTP POST requests with large payloads to suspicious external domain",             "DATA_EXFILTRATION"),
    ("FTP transfer of sensitive files to external server at 3am",                        "DATA_EXFILTRATION"),
    ("DNS tunneling detected, encoded data in DNS queries to external resolver",         "DATA_EXFILTRATION"),
    ("Employee workstation sending gigabytes to personal Dropbox account",               "DATA_EXFILTRATION"),
    ("Encrypted channel to Tor exit node with high upload volume",                       "DATA_EXFILTRATION"),
    ("Database dump followed by large outbound transfer to unknown server",              "DATA_EXFILTRATION"),
    ("Outbound SFTP session transferring compressed archives overnight",                 "DATA_EXFILTRATION"),
    ("Sustained high-bandwidth connection to IP in high-risk country",                   "DATA_EXFILTRATION"),
    ("Bulk email with attachments sent to external recipients from compromised account", "DATA_EXFILTRATION"),
    ("Cloud sync uploading unusually large volume of documents at night",                "DATA_EXFILTRATION"),

    # ── MALWARE_EXECUTION ─────────────────────────────────────────────────
    ("Process cmd.exe spawned by winword.exe, executed encoded PowerShell command",      "MALWARE_EXECUTION"),
    ("Suspicious DLL injection detected in explorer.exe process memory",                 "MALWARE_EXECUTION"),
    ("Ransomware behavior detected: mass file encryption with .locked extension",        "MALWARE_EXECUTION"),
    ("Mimikatz-like activity detected, LSASS memory access attempt",                     "MALWARE_EXECUTION"),
    ("Macro-enabled Office document executed PowerShell downloader",                     "MALWARE_EXECUTION"),
    ("New scheduled task created by unknown process for persistence",                    "MALWARE_EXECUTION"),
    ("Registry run key modified by suspicious executable in temp folder",                "MALWARE_EXECUTION"),
    ("Unsigned executable running from temp directory with outbound connections",        "MALWARE_EXECUTION"),
    ("WMI event subscription created for persistence mechanism",                         "MALWARE_EXECUTION"),
    ("Process hollowing detected: legitimate process replaced with malicious code",      "MALWARE_EXECUTION"),
    ("Unusual parent-child process: svchost spawning cmd.exe",                           "MALWARE_EXECUTION"),
    ("Fileless malware: PowerShell running entirely in memory without disk artifact",    "MALWARE_EXECUTION"),

    # ── LATERAL_MOVEMENT ──────────────────────────────────────────────────
    ("Authentication attempts from single host to 45 different internal servers",        "LATERAL_MOVEMENT"),
    ("Pass-the-hash attack detected, NTLM authentication with stolen credentials",      "LATERAL_MOVEMENT"),
    ("Unusual RDP session from workstation to server at odd hours",                      "LATERAL_MOVEMENT"),
    ("SMB connections to multiple hosts in rapid succession from single source",         "LATERAL_MOVEMENT"),
    ("Admin credentials used from non-admin workstation to access file server",          "LATERAL_MOVEMENT"),
    ("PsExec execution detected, remote command execution on multiple hosts",            "LATERAL_MOVEMENT"),
    ("Kerberos ticket with abnormal lifetime detected across multiple systems",           "LATERAL_MOVEMENT"),
    ("WMI remote execution from compromised host to domain controller",                  "LATERAL_MOVEMENT"),
    ("SSH keypair authenticating to multiple internal servers sequentially",              "LATERAL_MOVEMENT"),
    ("Internal port scanning from compromised workstation targeting server subnet",      "LATERAL_MOVEMENT"),
    ("Remote registry access from unauthorized workstation to production server",        "LATERAL_MOVEMENT"),
    ("Unusual service installation on remote hosts via admin shares",                    "LATERAL_MOVEMENT"),

    # ── CREDENTIAL_COMPROMISE ─────────────────────────────────────────────
    ("Multiple failed login attempts followed by successful authentication",             "CREDENTIAL_COMPROMISE"),
    ("User account logging in simultaneously from two different countries",              "CREDENTIAL_COMPROMISE"),
    ("Password spray attack: same password tried against 200 accounts",                 "CREDENTIAL_COMPROMISE"),
    ("Service account used interactively for the first time in months",                 "CREDENTIAL_COMPROMISE"),
    ("Credential stuffing detected: automated login attempts with leaked passwords",     "CREDENTIAL_COMPROMISE"),
    ("Admin account accessed outside business hours from unknown location",              "CREDENTIAL_COMPROMISE"),
    ("Brute force attack on VPN gateway, 500 attempts in 10 minutes",                   "CREDENTIAL_COMPROMISE"),
    ("MFA bypass attempt: second factor repeatedly failing then suddenly succeeding",    "CREDENTIAL_COMPROMISE"),
    ("API key exposed in public repository, immediately used from external IP",          "CREDENTIAL_COMPROMISE"),
    ("OAuth token used from different IP than original authentication session",          "CREDENTIAL_COMPROMISE"),
    ("Privileged account created by non-admin using stolen domain credentials",          "CREDENTIAL_COMPROMISE"),
    ("Service account password changed outside maintenance window by unknown process",   "CREDENTIAL_COMPROMISE"),

    # ── RECONNAISSANCE ────────────────────────────────────────────────────
    ("Network port scan detected from external IP, 65535 ports scanned",                "RECONNAISSANCE"),
    ("Unusual volume of DNS lookups for internal hostnames from single source",          "RECONNAISSANCE"),
    ("LDAP enumeration of Active Directory users and groups detected",                   "RECONNAISSANCE"),
    ("Vulnerability scanner signature detected in web application logs",                 "RECONNAISSANCE"),
    ("Service enumeration via SNMP from unauthorized internal host",                     "RECONNAISSANCE"),
    ("Repeated access to sensitive file shares without downloading files",               "RECONNAISSANCE"),
    ("Web application fingerprinting detected in server access logs",                    "RECONNAISSANCE"),
    ("Internal subnet sweep via ICMP ping from single compromised host",                 "RECONNAISSANCE"),
    ("SharePoint search queries for sensitive terms: password, confidential, secret",    "RECONNAISSANCE"),
    ("Enumeration of cloud storage buckets using stolen access key",                     "RECONNAISSANCE"),
    ("Banner grabbing activity detected across multiple exposed services",               "RECONNAISSANCE"),
    ("Automated crawling of internal wiki pages for credential information",             "RECONNAISSANCE"),
]


def get_training_data() -> tuple[list[str], list[str]]:
    """Devuelve (textos, etiquetas) listos para entrenar."""
    texts  = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]
    return texts, labels


CATEGORIES = [
    "DATA_EXFILTRATION",
    "MALWARE_EXECUTION",
    "LATERAL_MOVEMENT",
    "CREDENTIAL_COMPROMISE",
    "RECONNAISSANCE",
]
