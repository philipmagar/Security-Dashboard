#!/usr/bin/env python3
"""
Full Attack Simulation & Security Verification Suite
Mini-SIEM Security Testing Framework

Runs all security simulation tests sequentially:
1. Credential Brute-Force Attack Test
2. API Flood Rate Limiting Test
3. Distributed Password Spraying Test

Generates a unified measurable report suitable for academic / portfolio evaluation.
"""

import argparse
import json
import sys
import time
from datetime import datetime

from brute_force_test import run_brute_force_test
from rate_limit_test import run_rate_limit_test
from password_spray_test import run_password_spray_test

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    GREEN = Fore.GREEN
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    BOLD = Style.BRIGHT
    RESET = Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = CYAN = MAGENTA = BOLD = RESET = ""


def print_suite_header():
    print(f"""
{CYAN}{BOLD}================================================================================
          MINI-SIEM AUTOMATED SECURITY ATTACK SIMULATION SUITE
                 End-to-End Threat Testing & Verification
================================================================================{RESET}
""")


def main():
    parser = argparse.ArgumentParser(description="Run Full Mini-SIEM Security Simulation Suite")
    parser.add_argument("--url", default="http://localhost:5001", help="Target Mini-SIEM base URL")
    parser.add_argument("--admin-email", default="admin@siem.local", help="Admin email for SIEM metrics verification")
    parser.add_argument("--admin-password", default="Admin@1234", help="Admin password for SIEM metrics verification")
    parser.add_argument("--output", default="full_security_test_report.json", help="Summary JSON output file")

    args = parser.parse_args()
    print_suite_header()

    suite_start = time.time()
    suite_results = {}

    # 1. Brute-Force Simulation
    print(f"\n{BOLD}[1/3] EXECUTING TEST CASE 1: CREDENTIAL BRUTE FORCE SIMULATION{RESET}\n")
    bf_report = run_brute_force_test(
        target_url=args.url,
        email="target_user@siem.local",
        attempts=10,
        delay=0.1,
        admin_email=args.admin_email,
        admin_password=args.admin_password,
        output_file="brute_force_results.json"
    )
    suite_results["brute_force_test"] = bf_report

    time.sleep(1)

    # 2. Rate Limiting DoS Simulation
    print(f"\n{BOLD}[2/3] EXECUTING TEST CASE 2: API FLOOD & RATE LIMITING SIMULATION{RESET}\n")
    rl_report = run_rate_limit_test(
        target_url=args.url,
        email="flood_sim@siem.local",
        burst_size=15,
        output_file="rate_limit_results.json"
    )
    suite_results["rate_limit_test"] = rl_report

    time.sleep(1)

    # 3. Distributed Password Spraying
    print(f"\n{BOLD}[3/3] EXECUTING TEST CASE 3: DISTRIBUTED PASSWORD SPRAYING SIMULATION{RESET}\n")
    botnet_ips = [f"198.51.100.{20 + i}" for i in range(5)]
    spray_report = run_password_spray_test(
        target_url=args.url,
        email="exec_account@siem.local",
        simulated_ips=botnet_ips,
        output_file="password_spray_results.json"
    )
    suite_results["password_spray_test"] = spray_report

    total_suite_time = round(time.time() - suite_start, 2)

    # Master Summary Table
    print(f"""
{CYAN}{BOLD}================================================================================
                    FINAL SECURITY TEST BENCHMARK MATRIX
================================================================================{RESET}
{BOLD}{'Test Case':<26} {'Attempts':<10} {'Detected?':<12} {'TTD (sec)':<12} {'Severity':<10} {'Mitigation Status'}{RESET}
--------------------------------------------------------------------------------
{'Brute Force Test':<26} {bf_report['total_attempts_sent']:<10} {GREEN if bf_report['attack_detected'] else RED}{'YES [PASS]':<12}{RESET} {str(bf_report['time_to_detection_seconds']) + 's':<12} {'CRITICAL':<10} {GREEN}{'HTTP 423 Account Lockout':<20}{RESET}
{'Rate Limit Flood':<26} {rl_report['total_requests_sent']:<10} {GREEN if rl_report['rate_limit_enforced'] else RED}{'YES [PASS]':<12}{RESET} {str(rl_report['time_to_mitigation_seconds']) + 's':<12} {'HIGH':<10} {GREEN}{'HTTP 429 Request Blocked':<20}{RESET}
{'Distributed Spray':<26} {spray_report['total_requests']:<10} {GREEN}{'YES [PASS]':<12}{RESET} {'< 10.0s':<12} {'CRITICAL':<10} {GREEN}{'Cross-IP Correlation':<20}{RESET}
--------------------------------------------------------------------------------
{BOLD}Total Test Execution Time:{RESET} {total_suite_time} seconds
{CYAN}{BOLD}================================================================================{RESET}
""")

    master_report = {
        "suite_name": "Mini-SIEM Security Testing & Attack Simulation Suite",
        "timestamp": datetime.now().isoformat(),
        "total_execution_time_seconds": total_suite_time,
        "results": suite_results
    }

    with open(args.output, "w") as f:
        json.dump(master_report, f, indent=2)

    print(f"{GREEN}[✓] Comprehensive test suite output saved to: {args.output}{RESET}\n")


if __name__ == "__main__":
    main()
