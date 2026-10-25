# backend/config.py
# ─────────────────────────────────────────────────────────────
#  SOC Platform — Central Configuration
# ─────────────────────────────────────────────────────────────
import os
import ipaddress

from dotenv import load_dotenv

# Load persistent environment variables from .env
load_dotenv()

# ── Lab network ───────────────────────────────────────────────
LAB_SUBNET   = ipaddress.ip_network("192.168.56.0/24")
HOST_IP      = "192.168.56.1"
KALI_IP      = "192.168.56.10"
TARGET_IP    = "192.168.56.30"
HONEYPOT_IP  = "192.168.56.40"

LAB_HOSTS = {
    "192.168.56.1":  "Windows Host (SOC Backend)",
    "192.168.56.10": "Kali Linux (Attacker)",
    "192.168.56.30": "Ubuntu Target VM",
    "192.168.56.40": "Cowrie / DVWA Honeypot",
}

# ── Network capture ───────────────────────────────────────────
# Run: python -c "from scapy.all import get_if_list,get_if_addr
# [print(i) for i in get_if_list() if '192.168.56' in get_if_addr(i)]"
CAPTURE_IFACE = r"\Device\NPF_{55BA4787-0525-4480-98A4-8E06CF65E111}"

# ── Detection thresholds ──────────────────────────────────────
PORT_SCAN_THRESHOLD   = 5     # unique dst ports in TIME_WINDOW secs
BRUTE_FORCE_THRESHOLD = 5      # SSH/Telnet attempts in TIME_WINDOW secs
DDOS_PPS_THRESHOLD    = 50    # packets per second from one source
TIME_WINDOW           = 10     # sliding detection window in seconds

# ── Dataset paths ─────────────────────────────────────────────
DB_DIR             = "db"
NF_UQ_PATH         = "db/NF-UQ-NIDS-v2.csv"
NF_CIC_PATH        = "db/NF-CICIDS2018-v3.csv"
CICIOT_DIR         = "db/CICIoT2023"
EDGE_IIOT_DIR      = "db/Edge-IIoTset Cyber Security Dataset of Io..."
MITRE_ATTACK_PATH  = "db/enterprise-attack.json"

# ── Confirmed shared features (41 columns in both datasets) ───
SHARED_FEATURES = [
    'L4_SRC_PORT', 'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO',
    'IN_BYTES', 'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS',
    'TCP_FLAGS', 'CLIENT_TCP_FLAGS', 'SERVER_TCP_FLAGS',
    'FLOW_DURATION_MILLISECONDS', 'DURATION_IN', 'DURATION_OUT',
    'MIN_TTL', 'MAX_TTL', 'LONGEST_FLOW_PKT', 'SHORTEST_FLOW_PKT',
    'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN',
    'SRC_TO_DST_SECOND_BYTES', 'DST_TO_SRC_SECOND_BYTES',
    'RETRANSMITTED_IN_BYTES', 'RETRANSMITTED_IN_PKTS',
    'RETRANSMITTED_OUT_BYTES', 'RETRANSMITTED_OUT_PKTS',
    'SRC_TO_DST_AVG_THROUGHPUT', 'DST_TO_SRC_AVG_THROUGHPUT',
    'NUM_PKTS_UP_TO_128_BYTES', 'NUM_PKTS_128_TO_256_BYTES',
    'NUM_PKTS_256_TO_512_BYTES', 'NUM_PKTS_512_TO_1024_BYTES',
    'NUM_PKTS_1024_TO_1514_BYTES',
    'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT',
    'ICMP_TYPE', 'ICMP_IPV4_TYPE',
    'DNS_QUERY_ID', 'DNS_QUERY_TYPE', 'DNS_TTL_ANSWER',
    'FTP_COMMAND_RET_CODE',
]

# ── Label columns ─────────────────────────────────────────────
LABEL_COL  = 'Label'
ATTACK_COL = 'Attack'

# ── Attack label normalisation map ────────────────────────────
ATTACK_LABEL_MAP = {
    'Benign': 'BENIGN', 'benign': 'BENIGN', 'BENIGN': 'BENIGN',
    'PortScan': 'PORT_SCAN', 'port scan': 'PORT_SCAN',
    'Reconnaissance': 'PORT_SCAN', 'Recon': 'PORT_SCAN',
    'scanning': 'PORT_SCAN',
    'SSH-Bruteforce': 'BRUTE_FORCE', 'FTP-BruteForce': 'BRUTE_FORCE',
    'Brute Force': 'BRUTE_FORCE', 'BruteForce': 'BRUTE_FORCE',
    'Brute-Force': 'BRUTE_FORCE', 'password': 'BRUTE_FORCE',
    'DDoS': 'DDOS', 'DDoS attack-HOIC': 'DDOS',
    'DDoS attack-LOIC': 'DDOS', 'DDoS-UDP': 'DDOS',
    'DDoS-TCP': 'DDOS', 'DDoS-ICMP': 'DDOS',
    'DoS attacks-Hulk': 'DOS', 'DoS attacks-Slowloris': 'DOS',
    'DoS': 'DOS', 'DoS-UDP': 'DOS', 'DoS-TCP': 'DOS',
    'Botnet': 'BOTNET', 'Bot': 'BOTNET', 'Mirai': 'BOTNET',
    'Web attacks-XSS': 'WEB_ATTACK',
    'Web attacks-Sql Injection': 'WEB_ATTACK',
    'Web Attack': 'WEB_ATTACK', 'Injection': 'WEB_ATTACK',
    'XSS': 'WEB_ATTACK', 'SQL Injection': 'WEB_ATTACK',
    'xss': 'WEB_ATTACK', 'injection': 'WEB_ATTACK',
    'Infiltration': 'INFILTRATION',
    'MITM': 'MITM',
    'Spoofing': 'SPOOFING', 'ARP Spoofing': 'SPOOFING',
    'DNS Spoofing': 'SPOOFING',
}

ATTACK_CLASSES = [
    'BENIGN', 'PORT_SCAN', 'BRUTE_FORCE', 'DDOS', 'DOS',
    'BOTNET', 'WEB_ATTACK', 'INFILTRATION', 'MITM', 'SPOOFING', 'OTHER',
]

# ── ML model paths ────────────────────────────────────────────
MODEL_PATH      = "backend/models/attack_model.pkl"
ISO_MODEL_PATH  = "backend/models/iso_forest.pkl"
SCALER_PATH     = "backend/models/scaler.pkl"
ENCODER_PATH    = "backend/models/label_encoder.pkl"
ML_CONFIDENCE   = 0.75

# ── MITRE ATT&CK TTP mapping ──────────────────────────────────
ATTACK_TTP_MAP = {
    'PORT_SCAN': {
        'tactic': 'Discovery', 'tactic_id': 'TA0007',
        'technique': 'Network Service Discovery', 'tech_id': 'T1046',
        'url': 'https://attack.mitre.org/techniques/T1046/'
    },
    'BRUTE_FORCE': {
        'tactic': 'Credential Access', 'tactic_id': 'TA0006',
        'technique': 'Brute Force: Password Guessing', 'tech_id': 'T1110.001',
        'url': 'https://attack.mitre.org/techniques/T1110/001/'
    },
    'DDOS': {
        'tactic': 'Impact', 'tactic_id': 'TA0040',
        'technique': 'Network Denial of Service', 'tech_id': 'T1498',
        'url': 'https://attack.mitre.org/techniques/T1498/'
    },
    'DOS': {
        'tactic': 'Impact', 'tactic_id': 'TA0040',
        'technique': 'Endpoint Denial of Service', 'tech_id': 'T1499',
        'url': 'https://attack.mitre.org/techniques/T1499/'
    },
    'BOTNET': {
        'tactic': 'Command and Control', 'tactic_id': 'TA0011',
        'technique': 'Application Layer Protocol', 'tech_id': 'T1071',
        'url': 'https://attack.mitre.org/techniques/T1071/'
    },
    'WEB_ATTACK': {
        'tactic': 'Initial Access', 'tactic_id': 'TA0001',
        'technique': 'Exploit Public-Facing Application', 'tech_id': 'T1190',
        'url': 'https://attack.mitre.org/techniques/T1190/'
    },
    'INFILTRATION': {
        'tactic': 'Lateral Movement', 'tactic_id': 'TA0008',
        'technique': 'Exploitation of Remote Services', 'tech_id': 'T1210',
        'url': 'https://attack.mitre.org/techniques/T1210/'
    },
    'MITM': {
        'tactic': 'Collection', 'tactic_id': 'TA0009',
        'technique': 'Adversary-in-the-Middle', 'tech_id': 'T1557',
        'url': 'https://attack.mitre.org/techniques/T1557/'
    },
    'SPOOFING': {
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005',
        'technique': 'Masquerading', 'tech_id': 'T1036',
        'url': 'https://attack.mitre.org/techniques/T1036/'
    },
}

# ── Mitigation recommendations ────────────────────────────────
MITIGATIONS = {
    'PORT_SCAN': [
        'Block attacker IP at perimeter firewall immediately',
        'Disable or filter unused open ports on target',
        'Enable port-knocking on sensitive services (SSH, RDP)',
        'Configure IDS rule to alert on SYN scan patterns',
        'Review firewall rules and ensure default-deny policy',
    ],
    'BRUTE_FORCE': [
        'Enable fail2ban — auto-block after 5 failed attempts',
        'Enforce key-based SSH authentication, disable password auth',
        'Disable root SSH login (PermitRootLogin no)',
        'Enable Multi-Factor Authentication on all remote access',
        'Implement account lockout policy after repeated failures',
    ],
    'DDOS': [
        'Activate rate-limiting on affected network interface',
        'Block source IP subnet at perimeter firewall',
        'Enable SYN cookie protection on target hosts',
        'Redirect excess traffic to null route or sinkhole',
        'Contact upstream provider if scale exceeds local capacity',
    ],
    'DOS': [
        'Rate-limit connections per source IP',
        'Enable TCP connection timeout tuning',
        'Deploy reverse proxy to absorb HTTP flood',
        'Block offending source at firewall level',
        'Monitor application logs for slowloris signatures',
    ],
    'BOTNET': [
        'Isolate infected host from network immediately',
        'Block C2 IP and domain at DNS and firewall level',
        'Scan all hosts for malware indicators of compromise',
        'Review outbound traffic for unusual beacon patterns',
        'Reset all credentials on potentially compromised systems',
    ],
    'WEB_ATTACK': [
        'Enable Web Application Firewall (WAF) rules',
        'Patch identified vulnerable web application immediately',
        'Sanitise all user inputs to prevent SQL injection and XSS',
        'Review application logs for successful injection attempts',
        'Implement Content Security Policy (CSP) headers',
    ],
    'INFILTRATION': [
        'Isolate compromised segment from rest of network',
        'Revoke all credentials that may have been exposed',
        'Audit lateral movement indicators in event logs',
        'Apply principle of least privilege across all accounts',
        'Deploy EDR solution on all internal endpoints',
    ],
    'MITM': [
        'Enable ARP inspection on managed switches',
        'Enforce HTTPS with HSTS on all web services',
        'Deploy 802.1X network access control',
        'Monitor ARP tables for duplicate MAC/IP entries',
        'Use VPN for all sensitive communications',
    ],
    'SPOOFING': [
        'Enable BCP38 anti-spoofing filters at network edge',
        'Implement SPF, DKIM, DMARC for email spoofing prevention',
        'Enable uRPF (unicast reverse path forwarding)',
        'Validate source addresses on ingress interfaces',
        'Alert on traffic from spoofed or reserved address ranges',
    ],
}

# ── Threat intelligence API keys ──────────────────────────────
# Register free accounts and paste your keys below
# AbuseIPDB  -> https://www.abuseipdb.com/account/api
# AlienVault -> https://otx.alienvault.com/api
# VirusTotal -> https://www.virustotal.com/gui/my-apikey
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
OTX_KEY       = os.getenv("OTX_KEY",        "")
VT_KEY        = os.getenv("VT_KEY",          "")

# ── Telegram alerts (optional) ────────────────────────────────
# Create bot -> https://t.me/BotFather -> /newbot
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT  = os.getenv("TELEGRAM_CHAT",  "")

# ── Database ──────────────────────────────────────────────────
MONGO_URI   = "mongodb://localhost:27017/"
MONGO_DB    = "soc_platform"
SQLITE_PATH = "db/detections.db"

# ── Output paths ──────────────────────────────────────────────
REPORTS_DIR = "reports/"
LOGS_DIR    = "logs/"