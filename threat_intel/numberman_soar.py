#!/usr/bin/env python3
"""
Blue Moon Lab Suite - NumberMan.EXE
Automated IP Enrichment & Defensive Response

Threat Intelligence:
    - AbuseIPDB API v2
    - VirusTotal API v3

Response:
    - Structured JSON evidence
    - Optional iptables containment

Architecture:

    ChargeMan.EXE
          |
          v
    NumberMan.EXE
          |
       +--+--+
       |     |
       v     v
   AbuseIPDB VirusTotal
       |     |
       +--+--+
          |
          v
    Evidence Report
          |
          v
    Containment Logic
"""

import ipaddress
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv


# ============================================================
# NumberMan.EXE Configuration
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent
SUITE_ROOT = SCRIPT_DIR.parent

ENV_FILE = SUITE_ROOT / ".env"

# Explicitly load the project-level .env file.
load_dotenv(ENV_FILE)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# ============================================================
# Paths
# ============================================================

LOG_DIR = SCRIPT_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "numberman_soar.log"


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# ============================================================
# Threat Thresholds
# ============================================================

ABUSE_CONFIDENCE_THRESHOLD = 50
VT_MALICIOUS_THRESHOLD = 2


# ============================================================
# Request Configuration
# ============================================================

REQUEST_TIMEOUT = 10
FIREWALL_TIMEOUT = 15


# ============================================================
# Validation
# ============================================================

def validate_ip(ip_address):
    """Validate that the supplied target is a valid IPv4 address."""

    try:
        ip = ipaddress.ip_address(ip_address)

        if ip.version != 4:
            print(f"[-] IPv4 address required: {ip_address}")
            return False

        return True

    except ValueError:
        print(f"[-] Invalid IP address: {ip_address}")
        return False


# ============================================================
# API Key Validation
# ============================================================

def check_api_keys():
    """Verify that required threat-intelligence API keys are loaded."""

    abuse_loaded = bool(ABUSEIPDB_API_KEY)
    vt_loaded = bool(VIRUSTOTAL_API_KEY)

    if abuse_loaded:
        print("[+] AbuseIPDB API key loaded.")
    else:
        print("[!] AbuseIPDB API key not configured.")

    if vt_loaded:
        print("[+] VirusTotal API key loaded.")
    else:
        print("[!] VirusTotal API key not configured.")

    return abuse_loaded and vt_loaded


# ============================================================
# AbuseIPDB
# ============================================================

def query_abuseipdb(ip_address):
    """Query AbuseIPDB API v2 for IP reputation."""

    if not ABUSEIPDB_API_KEY:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY,
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            print(
                f"[-] AbuseIPDB HTTP Error: "
                f"{response.status_code}"
            )

            logging.warning(
                "AbuseIPDB returned HTTP %s for %s",
                response.status_code,
                ip_address,
            )

            return None

        data = response.json().get("data", {})

        result = {
            "score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "isp": data.get("isp", "Unknown"),
            "country": data.get("countryCode", "Unknown"),
        }

        print("[+] AbuseIPDB enrichment successful.")

        return result

    except requests.exceptions.RequestException as exc:
        print(f"[-] AbuseIPDB Request Failed: {exc}")

        logging.error(
            "AbuseIPDB request failed for %s: %s",
            ip_address,
            exc,
        )

        return None

    except (ValueError, KeyError, TypeError) as exc:
        print(f"[-] AbuseIPDB response parsing failed: {exc}")

        logging.error(
            "AbuseIPDB response parsing failed for %s: %s",
            ip_address,
            exc,
        )

        return None


# ============================================================
# VirusTotal
# ============================================================

def query_virustotal(ip_address):
    """Query VirusTotal API v3 for IP analysis statistics."""

    if not VIRUSTOTAL_API_KEY:
        return None

    url = (
        "https://www.virustotal.com/api/v3/"
        f"ip_addresses/{ip_address}"
    )

    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            print(
                f"[-] VirusTotal HTTP Error: "
                f"{response.status_code}"
            )

            logging.warning(
                "VirusTotal returned HTTP %s for %s",
                response.status_code,
                ip_address,
            )

            return None

        attributes = (
            response.json()
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        result = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

        print("[+] VirusTotal enrichment successful.")

        return result

    except requests.exceptions.RequestException as exc:
        print(f"[-] VirusTotal Request Failed: {exc}")

        logging.error(
            "VirusTotal request failed for %s: %s",
            ip_address,
            exc,
        )

        return None

    except (ValueError, KeyError, TypeError) as exc:
        print(f"[-] VirusTotal response parsing failed: {exc}")

        logging.error(
            "VirusTotal response parsing failed for %s: %s",
            ip_address,
            exc,
        )

        return None


# ============================================================
# Firewall Containment
# ============================================================

def execute_iptables_block(ip_address):
    """
    Attempt to block an IP using iptables.

    sudo -n is intentionally used so the SOAR engine cannot
    hang waiting for an interactive sudo password prompt.
    """

    try:
        check_cmd = [
            "sudo",
            "-n",
            "iptables",
            "-C",
            "INPUT",
            "-s",
            ip_address,
            "-j",
            "DROP",
        ]

        check_result = subprocess.run(
            check_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=FIREWALL_TIMEOUT,
            check=False,
        )

        if check_result.returncode == 0:
            print(
                f"[*] IP {ip_address} is already blocked."
            )

            logging.info(
                "IP %s already present in iptables.",
                ip_address,
            )

            return True

        block_cmd = [
            "sudo",
            "-n",
            "iptables",
            "-A",
            "INPUT",
            "-s",
            ip_address,
            "-j",
            "DROP",
        ]

        result = subprocess.run(
            block_cmd,
            capture_output=True,
            text=True,
            timeout=FIREWALL_TIMEOUT,
            check=False,
        )

        if result.returncode == 0:
            print(
                "[!] [NUMBERMAN PLAYBOOK EXECUTION] "
                f"Blocked {ip_address} via iptables."
            )

            logging.info(
                "PLAYBOOK EXECUTION: Successfully blocked %s",
                ip_address,
            )

            return True

        error_message = result.stderr.strip()

        if "password" in error_message.lower():
            print(
                "[-] Firewall action requires sudo authentication."
            )
        else:
            print(
                f"[-] Failed to block IP: {error_message}"
            )

        logging.error(
            "Failed to block %s: %s",
            ip_address,
            error_message,
        )

        return False

    except subprocess.TimeoutExpired:
        print(
            "[-] Firewall command timed out."
        )

        logging.error(
            "Firewall command timed out for %s",
            ip_address,
        )

        return False

    except Exception as exc:
        print(
            f"[-] Firewall execution error: {exc}"
        )

        logging.error(
            "Firewall execution error for %s: %s",
            ip_address,
            exc,
        )

        return False


# ============================================================
# SOAR Engine
# ============================================================

def run_numberman_soar(target_ip):
    """Run the complete NumberMan enrichment and response workflow."""

    print("=" * 60)
    print(
        "[NumberMan.EXE] Initiating SOAR Enrichment "
        f"for: {target_ip}"
    )
    print("=" * 60)

    # --------------------------------------------------------
    # Validate target IP
    # --------------------------------------------------------

    if not validate_ip(target_ip):
        return False

    # --------------------------------------------------------
    # Validate API configuration
    # --------------------------------------------------------

    if not check_api_keys():
        print(
            "\n[-] NumberMan cannot perform complete "
            "external threat-intelligence enrichment."
        )

        logging.error(
            "NumberMan API configuration incomplete."
        )

        return False

    # --------------------------------------------------------
    # AbuseIPDB
    # --------------------------------------------------------

    print("\n[*] Querying AbuseIPDB...")

    abuse_data = query_abuseipdb(target_ip)

    # --------------------------------------------------------
    # VirusTotal
    # --------------------------------------------------------

    print("\n[*] Querying VirusTotal...")

    vt_data = query_virustotal(target_ip)

    # --------------------------------------------------------
    # Display AbuseIPDB results
    # --------------------------------------------------------

    if abuse_data:
        print(
            "\n[+] AbuseIPDB Confidence Score: "
            f"{abuse_data['score']}%"
        )

        print(
            f"    ISP / Country: "
            f"{abuse_data['isp']} "
            f"({abuse_data['country']})"
        )

        print(
            f"    Total Reports: "
            f"{abuse_data['total_reports']}"
        )

    else:
        print(
            "\n[!] AbuseIPDB enrichment unavailable."
        )

    # --------------------------------------------------------
    # Display VirusTotal results
    # --------------------------------------------------------

    if vt_data:
        print(
            "\n[+] VirusTotal Malicious Engines: "
            f"{vt_data['malicious']}"
        )

        print(
            f"    Suspicious / Harmless: "
            f"{vt_data['suspicious']} / "
            f"{vt_data['harmless']}"
        )

        print(
            f"    Undetected: "
            f"{vt_data['undetected']}"
        )

    else:
        print(
            "\n[!] VirusTotal enrichment unavailable."
        )

    # --------------------------------------------------------
    # Determine available evidence
    # --------------------------------------------------------

    if not abuse_data and not vt_data:
        print(
            "\n[-] No threat-intelligence providers "
            "returned usable data."
        )

        print(
            "[+] Original ChargeMan detection preserved."
        )

        logging.warning(
            "No enrichment data available for %s",
            target_ip,
        )

        return False

    # --------------------------------------------------------
    # Evaluate response thresholds
    # --------------------------------------------------------

    abuse_flag = (
        abuse_data is not None
        and abuse_data["score"]
        >= ABUSE_CONFIDENCE_THRESHOLD
    )

    vt_flag = (
        vt_data is not None
        and vt_data["malicious"]
        >= VT_MALICIOUS_THRESHOLD
    )

    should_block = abuse_flag or vt_flag

    status = (
        "MALICIOUS - ACTION TAKEN"
        if should_block
        else "NO CONTAINMENT TRIGGERED"
    )

    # --------------------------------------------------------
    # Build structured evidence report
    # --------------------------------------------------------

    report = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "module": "NumberMan.EXE",

        "target_ip": target_ip,

        "status": status,

        "abuseipdb": abuse_data,

        "virustotal": vt_data,

        "response": {
            "abuse_threshold":
                ABUSE_CONFIDENCE_THRESHOLD,

            "vt_malicious_threshold":
                VT_MALICIOUS_THRESHOLD,

            "abuse_flag":
                abuse_flag,

            "vt_flag":
                vt_flag,

            "containment_triggered":
                should_block,
        },

        "action_taken": (
            "IPTABLES_BLOCK"
            if should_block
            else "NONE"
        ),
    }

    # --------------------------------------------------------
    # Write evidence report
    # --------------------------------------------------------

    report_path = (
        LOG_DIR
        / f"report_{target_ip.replace('.', '_')}.json"
    )

    try:
        with open(
            report_path,
            "w",
            encoding="utf-8",
        ) as report_file:

            json.dump(
                report,
                report_file,
                indent=4,
            )

        print(
            "\n[+] Threat Report Written To: "
            f"{report_path}"
        )

    except OSError as exc:
        print(
            f"[-] Failed to write threat report: {exc}"
        )

        logging.error(
            "Failed to write report for %s: %s",
            target_ip,
            exc,
        )

    # --------------------------------------------------------
    # Automated response
    # --------------------------------------------------------

    if should_block:
        print(
            "\n[!] THREAT THRESHOLD BREACHED."
        )

        print(
            "[!] Triggering NumberMan containment playbook..."
        )

        containment_success = execute_iptables_block(
            target_ip
        )

        if containment_success:
            report["containment_result"] = "SUCCESS"
        else:
            report["containment_result"] = "FAILED"

        # Update evidence with actual containment result.
        try:
            with open(
                report_path,
                "w",
                encoding="utf-8",
            ) as report_file:

                json.dump(
                    report,
                    report_file,
                    indent=4,
                )

        except OSError as exc:
            logging.error(
                "Failed to update report for %s: %s",
                target_ip,
                exc,
            )

    else:
        print(
            "\n[+] Containment threshold not reached."
        )

        print(
            "[+] No firewall action taken."
        )

    logging.info(
        "SOAR analysis completed for %s",
        target_ip,
    )

    print(
        "\n[+] NumberMan SOAR analysis complete."
    )

    return True


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) > 1:
        ip_to_check = sys.argv[1]

    else:
        ip_to_check = input(
            "Enter Target IP for NumberMan Analysis: "
        ).strip()

    run_numberman_soar(ip_to_check)
