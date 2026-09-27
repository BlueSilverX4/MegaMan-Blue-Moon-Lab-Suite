#!/usr/bin/env python3
"""
Blue Moon Lab Suite - Master Orchestrator
NIST-Aligned Defensive SOC Engine inspired by MegaMan Battle Network 4
"""

import os
import sys
import subprocess
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
KILLERMAN_SCRIPT = BASE_DIR / "modules" / "killerman" / "killerman_recon.py"
CHARGEMAN_SCRIPT = BASE_DIR / "modules" / "chargeman" / "chargeman_monitor.py"
NUMBERMAN_SCRIPT = BASE_DIR / "threat_intel" / "numberman_soar.py"
MEDDY_SCRIPT = BASE_DIR / "modules" / "meddy" / "meddy_recover.py"


def print_banner():
    print("""
    ============================================================
       ██████╗ ██╗     ██╗██╗███████╗   ███╗   ███╗██████╗ 
       ██╔══██╗██║     ██║██║██╔════╝   ████╗ ████║██╔══██╗
       ██████╔╝██║     ██║██║█████╗     ██╔████╔██║██████╔╝
       ██╔══██╗██║     ██║██║██╔══╝     ██║╚██╔╝██║██╔══██╗
       ██████╔╝███████╗╚█████╔╝███████╗ ██║ ╚═╝ ██║██║  ██║
             B L U E   M O O N   L A B   S U I T E
    ============================================================
    [+] NIST CSF Mapping:
        • KillerMan.EXE  -> IDENTIFY (Nmap / Network Recon)
        • ChargeMan.EXE  -> DETECT   (Docker Telemetry Pipeline)
        • NumberMan.EXE  -> PROTECT  (SOAR Enrichment & Containment)
        • Meddy.EXE      -> RECOVER  (State Restoration & Unblock)
    ============================================================
    """)


def run_killerman():
    target = input("\n[KillerMan] Enter Target Subnet or IP (e.g., 127.0.0.1 or 8.8.8.8): ").strip()
    if target:
        subprocess.run([sys.executable, str(KILLERMAN_SCRIPT), target])


def run_chargeman():
    container = input("\n[ChargeMan] Enter Target Docker Container Name or ID: ").strip()
    if container:
        subprocess.run([sys.executable, str(CHARGEMAN_SCRIPT), container])


def run_numberman():
    ip = input("\n[NumberMan] Enter IP Address for SOAR Analysis/Containment: ").strip()
    if ip:
        subprocess.run([sys.executable, str(NUMBERMAN_SCRIPT), ip])


def run_meddy():
    subprocess.run([sys.executable, str(MEDDY_SCRIPT)])


def main():
    while True:
        print_banner()
        print("Select Module to Execute:")
        print("1. [KillerMan.EXE] Run Network Reconnaissance Scan")
        print("2. [ChargeMan.EXE] Start Container Telemetry Pipeline")
        print("3. [NumberMan.EXE] Manual Threat Intelligence & SOAR Analysis")
        print("4. [Meddy.EXE]     Launch Incident Recovery & Restoration Utility")
        print("5. Exit")
        print("=" * 60)

        choice = input("Select Option (1-5): ").strip()

        if choice == "1":
            run_killerman()
        elif choice == "2":
            run_chargeman()
        elif choice == "3":
            run_numberman()
        elif choice == "4":
            run_meddy()
        elif choice == "5":
            print("\n[*] Exiting Blue Moon Lab Suite. Power down.")
            sys.exit(0)
        else:
            print("[-] Invalid selection. Try again.")

        input("\n[Press Enter to return to main menu...]")


if __name__ == "__main__":
    main()
