#!/usr/bin/env python3
"""
Distributed Password Spraying Attack Simulation Test
Mini-SIEM Security Testing Suite

This script simulates a distributed brute-force / password spraying campaign
where multiple distinct source IPs attempt to guess credentials for a single targeted account.
This evaluates the Python Detection Engine's `detect_password_spraying` rule.
"""

import argparse
import json
import sys
import time
from datetime import datetime

try:
    import requests
except ImportError:
    print("Error: 'requests' package is required. Run: pip install requests")
    sys.exit(1)

# Terminal color helper with fallback
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


def print_banner():
    banner = f"""
{CYAN}{BOLD}======================================================================
  MINI-SIEM SECURITY TESTING SUITE — ATTACK SIMULATION
  Test Case: Distributed Password Spraying Attack Simulation
======================================================================{RESET}
"""
    print(banner)


def run_password_spray_test(target_url, email, simulated_ips, output_file=None):
    endpoint = f"{target_url.rstrip('/')}/api/auth/login"
    
    print(f"{BOLD}[*] Target Endpoint   :{RESET} {endpoint}")
    print(f"{BOLD}[*] Targeted Account  :{RESET} {email}")
    print(f"{BOLD}[*] Simulated Botnet  :{RESET} {len(simulated_ips)} distinct IP addresses")
    print(f"{BOLD}[*] Detection Rule    :{RESET} Python Engine -> detect_password_spraying (CRITICAL Severity)")
    print(f"{BOLD}[*] Start Time        :{RESET} {datetime.now().isoformat()}\n")
    print("-" * 70)
    print(f"{BOLD}{'#':<4} {'Simulated IP':<18} {'Attempt Password':<22} {'HTTP':<6} {'Result'}{RESET}")
    print("-" * 70)

    start_time = time.time()
    results = []

    for idx, ip in enumerate(simulated_ips, 1):
        fake_pass = f"SprayPass_{idx}_{int(time.time())}"
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-For": ip
        }

        try:
            resp = requests.post(
                endpoint,
                json={"email": email, "password": fake_pass},
                headers=headers,
                timeout=5
            )
            status_code = resp.status_code
        except Exception as e:
            status_code = 0

        status_desc = f"{YELLOW}HTTP {status_code} (Logged with IP {ip}){RESET}"
        print(f"{idx:<4} {ip:<18} {fake_pass[:20]:<22} {status_code:<6} {status_desc}")

        results.append({
            "ip": ip,
            "status_code": status_code,
            "timestamp": datetime.now().isoformat()
        })
        time.sleep(0.05)

    duration = round(time.time() - start_time, 3)

    report = {
        "test_name": "Distributed Password Spraying Simulation",
        "target_url": target_url,
        "target_account": email,
        "simulated_ips_count": len(simulated_ips),
        "total_requests": len(simulated_ips),
        "duration_seconds": duration,
        "expected_detection": "PASSWORD_SPRAYING (Severity: CRITICAL)",
        "details": results
    }

    print(f"\n{CYAN}{BOLD}======================================================================{RESET}")
    print(f"{CYAN}{BOLD}               PASSWORD SPRAYING SIMULATION SUMMARY                   {RESET}")
    print(f"{CYAN}{BOLD}======================================================================{RESET}")
    print(f" {BOLD}Simulated Attack Nodes :{RESET} {len(simulated_ips)} unique IPs")
    print(f" {BOLD}Targeted Account       :{RESET} {email}")
    print(f" {BOLD}Total Events Logged    :{RESET} {len(simulated_ips)}")
    print(f" {BOLD}Expected SIEM Alert    :{RESET} {RED}{BOLD}PASSWORD_SPRAYING [CRITICAL]{RESET}")
    print(f" {BOLD}Python Engine Status   :{RESET} Engine polls every 10s and correlates cross-IP logins")
    print(f"{CYAN}{BOLD}======================================================================{RESET}\n")

    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"{GREEN}[+] Report saved to {output_file}{RESET}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Distributed Password Spraying Simulation Test")
    parser.add_argument("--url", default="http://localhost:5001", help="Target Mini-SIEM base URL")
    parser.add_argument("--email", default="corporate_target@siem.local", help="Target account email")
    parser.add_argument("--ips", type=int, default=6, help="Number of distinct spoofed IPs to simulate")
    parser.add_argument("--output", default="password_spray_results.json", help="JSON output file")

    args = parser.parse_args()
    print_banner()
    
    botnet_ips = [f"198.51.100.{10 + i}" for i in range(args.ips)]
    run_password_spray_test(
        target_url=args.url,
        email=args.email,
        simulated_ips=botnet_ips,
        output_file=args.output
    )


if __name__ == "__main__":
    main()
