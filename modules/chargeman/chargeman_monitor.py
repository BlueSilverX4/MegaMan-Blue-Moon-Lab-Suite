#!/usr/bin/env python3
"""
Blue Moon Lab Suite - ChargeMan.EXE
Detection & Telemetry Pipeline

Docker Container Logs
        │
        ▼
ChargeMan.EXE
        │
        ├── Signature Detection
        ├── IP Extraction
        └── Threat Handoff
                │
                ▼
        NumberMan.EXE SOAR
"""

from pathlib import Path
import ipaddress
import re
import subprocess
import sys

import docker


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MODULE_DIR = Path(__file__).resolve().parent
SUITE_ROOT = MODULE_DIR.parent.parent

NUMBERMAN_SCRIPT = SUITE_ROOT / "threat_intel" / "numberman_soar.py"

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

SUSPICIOUS_PATTERNS = [
    re.compile(r"FAILED PASSWORD", re.IGNORECASE),
    re.compile(r"UNAUTHORIZED ACCESS", re.IGNORECASE),
    re.compile(r"403 FORBIDDEN", re.IGNORECASE),
    re.compile(r"SQL SYNTAX", re.IGNORECASE),
    re.compile(r"UNION SELECT", re.IGNORECASE),
    re.compile(r"PATH TRAVERSAL", re.IGNORECASE),
    re.compile(r"ETC/PASSWD", re.IGNORECASE),
    re.compile(r"COMMAND INJECTION", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def extract_ips(log_line):
    """
    Extract valid IPv4 addresses from a log line.
    """

    valid_ips = set()

    for candidate in IP_PATTERN.findall(log_line):
        try:
            ip = ipaddress.ip_address(candidate)

            if ip.version == 4:
                valid_ips.add(str(ip))

        except ValueError:
            continue

    return valid_ips


def is_private_or_local(ip_address):
    """
    Determine whether an IPv4 address is local/private.

    These addresses do not need external threat-intelligence enrichment.
    """

    try:
        ip = ipaddress.ip_address(ip_address)

        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
        )

    except ValueError:
        return True


# ---------------------------------------------------------------------------
# NumberMan SOAR Integration
# ---------------------------------------------------------------------------

def trigger_numberman_soar(ip_address):
    """
    Forward a suspicious external IP to NumberMan.EXE.

    ChargeMan preserves the original detection even if NumberMan,
    the network, or external threat intelligence is unavailable.
    """

    print(
        f"\n[!] [CHARGEMAN PIPELINE TRIGGER] "
        f"Forwarding suspicious IP ({ip_address}) to NumberMan SOAR..."
    )

    if not NUMBERMAN_SCRIPT.exists():
        print(
            f"[-] NumberMan SOAR script not found:\n"
            f"    {NUMBERMAN_SCRIPT}"
        )
        return False

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(NUMBERMAN_SCRIPT),
                ip_address,
            ],
            capture_output=False,
            timeout=30,
            check=False,
        )

        if result.returncode == 0:
            print(
                f"[+] NumberMan SOAR completed for {ip_address}"
            )
            return True

        print(
            f"[-] NumberMan SOAR returned exit code "
            f"{result.returncode}"
        )

        print(
            "[!] Original ChargeMan detection remains valid."
        )

        return False

    except subprocess.TimeoutExpired:
        print(
            f"[-] NumberMan SOAR timed out while processing "
            f"{ip_address}"
        )
        print(
            "[!] External enrichment may be unavailable."
        )
        print(
            "[+] Original ChargeMan detection preserved."
        )
        return False

    except Exception as exc:
        print(
            f"[-] NumberMan execution error: {exc}"
        )
        print(
            "[+] Original ChargeMan detection preserved."
        )
        return False


# ---------------------------------------------------------------------------
# Docker Telemetry Pipeline
# ---------------------------------------------------------------------------

def monitor_container_logs(container_name_or_id):
    """
    Connect to Docker and continuously monitor container logs.
    """

    try:
        client = docker.from_env()
        container = client.containers.get(container_name_or_id)

    except docker.errors.NotFound:
        print(
            f"[-] Error: Container "
            f"'{container_name_or_id}' not found."
        )
        return

    except docker.errors.DockerException as exc:
        print(
            f"[-] Docker connection error: {exc}"
        )
        return

    except Exception as exc:
        print(
            f"[-] Unexpected Docker error: {exc}"
        )
        return

    print("=" * 60)
    print("[ChargeMan.EXE] Telemetry Pipeline Active")
    print(
        f"Monitoring Container: "
        f"{container.name} ({container.short_id})"
    )
    print("=" * 60)

    try:

        for chunk in container.logs(
            stream=True,
            follow=True,
            tail=0,
        ):

            log_line = chunk.decode(
                "utf-8",
                errors="replace"
            ).strip()

            if not log_line:
                continue

            detected_pattern = None

            # ---------------------------------------------------------------
            # Signature Detection
            # ---------------------------------------------------------------

            for pattern in SUSPICIOUS_PATTERNS:

                if pattern.search(log_line):
                    detected_pattern = pattern
                    break

            if not detected_pattern:
                continue

            print()
            print(
                f"[ALERT] Suspicious Pattern Detected: "
                f"'{detected_pattern.pattern}'"
            )

            print(
                f"        Log Line: {log_line}"
            )

            # ---------------------------------------------------------------
            # IP Extraction
            # ---------------------------------------------------------------

            found_ips = extract_ips(log_line)

            if not found_ips:
                print(
                    "        [*] No IPv4 address found in alert."
                )
                continue

            # ---------------------------------------------------------------
            # SOAR Handoff
            # ---------------------------------------------------------------

            for ip_address in found_ips:

                if is_private_or_local(ip_address):

                    print(
                        f"        [*] Internal/local IP detected: "
                        f"{ip_address}"
                    )

                    print(
                        "        [*] Skipping external SOAR lookup."
                    )

                    continue

                trigger_numberman_soar(ip_address)

    except KeyboardInterrupt:

        print(
            "\n[*] Stopping ChargeMan Telemetry Pipeline."
        )

    except docker.errors.DockerException as exc:

        print(
            f"\n[-] Docker telemetry stream error: {exc}"
        )

    except Exception as exc:

        print(
            f"\n[-] Pipeline Stream Error: {exc}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) > 1:

        target_container = sys.argv[1]

    else:

        target_container = input(
            "Enter Docker Container Name or ID to monitor: "
        ).strip()

    if not target_container:

        print(
            "[-] No Docker container specified."
        )

        sys.exit(1)

    monitor_container_logs(target_container)
