# 🌙 Blue Moon Lab Suite
### NIST-Aligned Automated SOC Framework

> **MegaMan Battle Network–inspired cybersecurity automation lab for network discovery, telemetry detection, threat intelligence enrichment, automated containment, and incident recovery.**

The **Blue Moon Lab Suite** is a modular defensive cybersecurity framework built around a Python CLI orchestrator. It demonstrates how individual security capabilities can be connected into an automated SOC-style workflow.

The suite combines:

- 🔎 Network reconnaissance
- 📡 Container telemetry monitoring
- 🧠 Threat intelligence enrichment
- 🛡️ Automated firewall containment
- 🔄 Incident recovery and rollback
- 📊 Structured JSON evidence logging
- 🧩 Modular Python-based security tooling

The architecture is organized around the **NIST Cybersecurity Framework (CSF)** functions most directly represented by the lab: **Identify, Detect, Protect, and Recover**.

---

## 🏗️ System Architecture

```text
                         ┌────────────────────────────┐
                         │     blue_moon_suite.py     │
                         │      Master Orchestrator   │
                         └──────────────┬─────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
              ▼                         ▼                         ▼
     ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
     │  KillerMan.EXE  │      │  ChargeMan.EXE  │      │  NumberMan.EXE  │
     │    IDENTIFY     │      │      DETECT     │      │     PROTECT     │
     │                 │      │                 │      │                 │
     │ Nmap Discovery  │─────▶│ Docker Logs     │─────▶│ Threat Intel    │
     │ Host / Port     │      │ Pattern         │      │ Enrichment      │
     │ Enumeration     │      │ Detection       │      │ + Containment   │
     └─────────────────┘      └─────────────────┘      └────────┬────────┘
                                                                  │
                                                                  ▼
                                                        ┌─────────────────┐
                                                        │    Meddy.EXE    │
                                                        │     RECOVER     │
                                                        │                 │
                                                        │ Rollback        │
                                                        │ Firewall        │
                                                        │ Recovery        │
                                                        └─────────────────┘

        External IP Detection
                 │
                 ▼
        ┌─────────────────────┐
        │ Threat Intelligence │
        │      Pipeline       │
        └──────────┬──────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │ Automated Firewall  │
        │      Containment    │
        └─────────────────────┘
🧭 NIST CSF Mapping
Module	NIST CSF Function	Technical Function	Primary Tooling
KillerMan.EXE	Identify	Performs network and host discovery using Nmap and identifies external IP activity for downstream processing.	python-nmap, Nmap
ChargeMan.EXE	Detect	Streams Docker container logs and analyzes telemetry for suspicious patterns such as authentication failures and SQL injection indicators.	docker-py, Python Regex
NumberMan.EXE	Protect	Enriches suspicious IP addresses with threat intelligence and can apply firewall containment rules.	AbuseIPDB API, VirusTotal API, iptables
Meddy.EXE	Recover	Performs containment rollback, firewall rule removal, and recovery operations.	iptables, Docker SDK

Note: The NIST CSF mapping describes how the lab's technical capabilities are organized. It is not intended to represent a complete implementation of every CSF category or subcategory.

⚙️ Security Workflow

The suite is designed around a simple defensive pipeline:

       DISCOVER
          │
          ▼
   ┌─────────────┐
   │ KillerMan   │
   │ Network     │
   │ Discovery   │
   └──────┬──────┘
          │
          ▼
       DETECT
          │
          ▼
   ┌─────────────┐
   │ ChargeMan   │
   │ Container   │
   │ Telemetry   │
   └──────┬──────┘
          │
          ▼
      ENRICH
          │
          ▼
   ┌─────────────┐
   │ NumberMan   │
   │ Threat Intel│
   └──────┬──────┘
          │
          ▼
      CONTAIN
          │
          ▼
   ┌─────────────┐
   │ iptables    │
   │ Firewall    │
   └──────┬──────┘
          │
          ▼
       RECOVER
          │
          ▼
   ┌─────────────┐
   │ Meddy       │
   │ Recovery    │
   └─────────────┘
🚀 Installation
Prerequisites
Kali Linux or another Debian-based Linux distribution
Python 3.10+
Docker Engine
Docker service running
sudo privileges
Network access for threat intelligence API queries
iptables available for firewall enforcement

Verify the environment:

python3 --version
docker --version
sudo iptables --version
📦 Install Python Dependencies

From the repository root:

pip install python-nmap docker python-dotenv requests --break-system-packages

If you prefer to isolate the project dependencies, a Python virtual environment can be used instead.

🔐 Configuration

Create the environment configuration file:

mkdir -p config
nano config/.env

Add the required API credentials:

ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_API_KEY"
VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
Security Notice

Do not commit API credentials to GitHub.

The repository should contain only the configuration template or an example file containing placeholder values.

For example:

config/
├── .env          # Local secrets — DO NOT COMMIT
└── .env.example  # Safe configuration template

Recommended .gitignore entry:

config/.env
*.log
__pycache__/
*.pyc
🛠️ Usage
Launch the Master Orchestrator

From the repository root:

python3 blue_moon_suite.py

The master CLI provides access to the individual security modules.

🔎 KillerMan.EXE — Network Discovery

Run a network reconnaissance scan:

python3 modules/killerman/killerman_recon.py 8.8.8.0/24

KillerMan is responsible for the Identify stage of the pipeline.

Typical workflow:

Target Network
      │
      ▼
   Nmap Scan
      │
      ▼
Host / Port Discovery
      │
      ▼
External IP Identification
📡 ChargeMan.EXE — Telemetry Detection

Monitor Docker container logs:

python3 modules/chargeman/chargeman_monitor.py <container_name_or_id>

ChargeMan analyzes container telemetry for suspicious patterns.

Example detection categories include:

Authentication failures
SQL injection indicators
Suspicious requests
Repeated error patterns
Other configurable regex-based indicators
🧠 NumberMan.EXE — Threat Intelligence & SOAR

Manually submit an IP address for threat intelligence enrichment:

python3 threat_intel/numberman_soar.py <ip_address>

Example:

python3 threat_intel/numberman_soar.py 185.220.101.5

The NumberMan pipeline can:

Suspicious IP
     │
     ▼
AbuseIPDB Query
     │
     ├───────────────┐
     ▼               ▼
VirusTotal       Reputation
     │               │
     └───────┬───────┘
             ▼
       Threat Decision
             │
             ▼
      Firewall Action
             │
             ▼
      JSON Evidence

Threat intelligence results should be treated as enrichment data and validated before taking consequential containment actions.

🔄 Meddy.EXE — Recovery

Remove a previously applied firewall block:

python3 modules/meddy/meddy_recover.py --unblock <ip_address>

Flush managed firewall rules:

python3 modules/meddy/meddy_recover.py --flush

Meddy provides the recovery path for reversing containment actions and restoring the lab to a known state.

📁 Repository Structure
MegaMan-Blue-Moon-Lab-Suite/
│
├── assets/
│   └── # Visual assets and documentation diagrams
│
├── config/
│   ├── .env.example
│   └── .env
│
├── modules/
│   ├── chargeman/
│   │   └── chargeman_monitor.py
│   │
│   ├── killerman/
│   │   └── killerman_recon.py
│   │
│   └── meddy/
│       └── meddy_recover.py
│
├── threat_intel/
│   ├── logs/
│   │   └── # JSON threat intelligence evidence
│   │
│   └── numberman_soar.py
│
├── blue_moon_suite.py
├── .gitignore
└── README.md
📊 Evidence & Logging

Threat intelligence and containment operations can generate structured JSON evidence under:

threat_intel/logs/

Example evidence workflow:

Detection
   │
   ▼
Indicator
   │
   ▼
Threat Intelligence
   │
   ▼
Containment Decision
   │
   ▼
Firewall Action
   │
   ▼
JSON Evidence

This provides a lightweight audit trail that can be reviewed during incident-response exercises.

🧪 Defensive Lab Use

Blue Moon Lab Suite is designed as a controlled cybersecurity training and portfolio environment.

Recommended testing should be performed against:

Your own systems
Authorized lab infrastructure
Intentionally vulnerable containers
Private test networks
Simulated indicators

Network discovery, threat intelligence queries, and firewall automation should be used only where you have authorization.

🎯 Project Goals

The project demonstrates practical SOC concepts including:

Network reconnaissance
Security telemetry collection
Detection engineering
Regex-based event analysis
Threat intelligence enrichment
Security automation
Firewall-based containment
Incident recovery
Evidence generation
Modular Python security tooling
NIST CSF-aligned security workflows
🧩 Design Philosophy

Blue Moon Lab Suite follows a simple principle:

        OBSERVE
           │
           ▼
        DETECT
           │
           ▼
        ENRICH
           │
           ▼
       VALIDATE
           │
           ▼
       CONTAIN
           │
           ▼
        RECOVER
           │
           ▼
        DOCUMENT

Automation is used to accelerate repetitive SOC tasks while keeping security decisions observable and auditable.

🌙 Project Identity

Project: MegaMan Blue Moon Lab Suite
Architecture: Modular Python SOC Automation
Platform: Kali Linux / Debian-based Linux
Primary Language: Python 3
Security Model: Detect → Enrich → Contain → Recover
Framework Alignment: NIST Cybersecurity Framework
Environment: Defensive Cybersecurity Home Lab

⚠️ Disclaimer

This project is intended for authorized defensive cybersecurity research, education, and laboratory use.

The author is responsible for operating the tools only against systems and networks for which appropriate authorization has been obtained.

📜 License

Add your preferred open-source license here, such as MIT, if you intend to distribute the project under an open-source license.
# MegaMan-Blue-Moon-Lab-Suite
