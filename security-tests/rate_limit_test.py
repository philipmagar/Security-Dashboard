#!/usr/bin/env python3
"""
API Flood / Rate Limiting Attack Simulation Test
Mini-SIEM Security Testing Suite

This script sends a high-volume burst of rapid requests to the authentication
endpoint (POST /api/auth/login) to evaluate:
1. Express-rate-limit mitigation threshold.
2. Status code transition from 401/423 to HTTP 429 Too Many Requests.
3. Generation of RATE_LIMIT_EXCEEDED / LOGIN_RATE_LIMIT alerts.
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
  Test Case: API Burst & Rate Limit Denial-of-Service Defense
======================================================================{RESET}
"""
    print(banner)


def run_rate_limit_test(target_url, email, burst_size, output_file=None):
    endpoint = f"{target_url.rstrip('/')}/api/auth/login"
    
    print(f"{BOLD}[*] Target Endpoint  :{RESET} {endpoint}")
    print(f"{BOLD}[*] Target Account   :{RESET} {email}")
    print(f"{BOLD}[*] Burst Size       :{RESET} {burst_size} requests (zero delay)")
    print(f"{BOLD}[*] Start Time       :{RESET} {datetime.now().isoformat()}\n")
    print("-" * 70)
    print(f"{BOLD}{'#':<4} {'Timestamp':<12} {'HTTP Code':<10} {'Latency':<9} {'Mitigation Status'}{RESET}")
    print("-" * 70)

    start_time = time.time()
    rate_limit_triggered = False
    first_429_index = None
    first_429_time_sec = None
    results = []
    status_counts = {}

    for i in range(1, burst_size + 1):
        req_start = time.time()
        try:
            resp = requests.post(
                endpoint,
                json={"email": email, "password": f"FloodTest_{i}_{int(time.time())}"},
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            req_latency_ms = round((time.time() - req_start) * 1000, 2)
            status_code = resp.status_code
        except Exception as e:
            req_latency_ms = round((time.time() - req_start) * 1000, 2)
            status_code = 0

        status_counts[status_code] = status_counts.get(status_code, 0) + 1
        timestamp_str = datetime.now().strftime("%H:%M:%S.%f")[:12]

        if status_code == 429:
            status_desc = f"{MAGENTA}{BOLD}429 TOO MANY REQUESTS (Rate Limiter Tripped){RESET}"
            if not rate_limit_triggered:
                rate_limit_triggered = True
                first_429_index = i
                first_429_time_sec = round(time.time() - start_time, 3)
        elif status_code == 423:
            status_desc = f"{RED}423 LOCKED (Account Lockout Active){RESET}"
        elif status_code == 401:
            status_desc = f"{YELLOW}401 Invalid Credentials{RESET}"
        else:
            status_desc = f"HTTP {status_code}"

        print(f"{i:<4} {timestamp_str:<12} {status_code:<10} {req_latency_ms:<7}ms {status_desc}")

        results.append({
            "request_index": i,
            "status_code": status_code,
            "latency_ms": req_latency_ms
        })

    total_duration = round(time.time() - start_time, 3)

    report = {
        "test_name": "API Flood Rate Limiting Simulation",
        "target_url": target_url,
        "total_requests_sent": burst_size,
        "total_duration_seconds": total_duration,
        "rate_limit_enforced": rate_limit_triggered,
        "first_blocked_request": first_429_index,
        "time_to_mitigation_seconds": first_429_time_sec,
        "status_distribution": status_counts,
        "requests_per_second": round(burst_size / max(total_duration, 0.001), 2)
    }

    print(f"\n{CYAN}{BOLD}======================================================================{RESET}")
    print(f"{CYAN}{BOLD}                     RATE LIMIT TEST SUMMARY                          {RESET}")
    print(f"{CYAN}{BOLD}======================================================================{RESET}")
    print(f" {BOLD}Total Requests Sent    :{RESET} {burst_size}")
    print(f" {BOLD}Total Test Duration    :{RESET} {total_duration}s ({report['requests_per_second']} req/sec)")
    print(f" {BOLD}Rate Limiting Tripped? :{RESET} {GREEN if rate_limit_triggered else RED}{'YES [PASS]' if rate_limit_triggered else 'NO [FAIL]'}{RESET}")
    print(f" {BOLD}First Blocked at Req   :{RESET} Request #{first_429_index or 'N/A'}")
    print(f" {BOLD}Time to Mitigation     :{RESET} {first_429_time_sec or 'N/A'}s")
    print(f" {BOLD}Status Code Breakdown  :{RESET} {status_counts}")
    print(f"{CYAN}{BOLD}======================================================================{RESET}\n")

    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"{GREEN}[+] Results written to {output_file}{RESET}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Mini-SIEM Rate Limiting Flood Test")
    parser.add_argument("--url", default="http://localhost:5001", help="Target Mini-SIEM base URL")
    parser.add_argument("--email", default="flood_test@siem.local", help="Target account email")
    parser.add_argument("--burst", type=int, default=20, help="Number of burst requests to send")
    parser.add_argument("--output", default="rate_limit_results.json", help="JSON output file")

    args = parser.parse_args()
    print_banner()
    run_rate_limit_test(target_url=args.url, email=args.email, burst_size=args.burst, output_file=args.output)


if __name__ == "__main__":
    main()
