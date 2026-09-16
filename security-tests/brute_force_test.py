#!/usr/bin/env python3
"""
Credential Brute-Force Attack Simulation Test
Mini-SIEM Security Testing Suite

This script sends a controlled burst of invalid login attempts to the Mini-SIEM
authentication endpoint (POST /api/auth/login). It tracks:
1. Per-attempt response status (HTTP 401 Unauthorized -> HTTP 423 Locked / HTTP 429 Rate Limited).
2. Exact time-to-detection and mitigation trigger.
3. Post-attack SIEM verification: checks risk score calculation, threat level,
   and alert generation in the backend database.
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
  Test Case: Controlled Credential Brute-Force Simulation
======================================================================{RESET}
"""
    print(banner)


def run_brute_force_test(target_url, email, attempts, delay, admin_email, admin_password, output_file=None):
    login_endpoint = f"{target_url.rstrip('/')}/api/auth/login"
    
    print(f"{BOLD}[*] Target Endpoint  :{RESET} {login_endpoint}")
    print(f"{BOLD}[*] Target Account   :{RESET} {email}")
    print(f"{BOLD}[*] Planned Attempts :{RESET} {attempts}")
    print(f"{BOLD}[*] Inter-burst Delay:{RESET} {delay}s")
    print(f"{BOLD}[*] Start Time       :{RESET} {datetime.now().isoformat()}\n")
    print("-" * 70)
    print(f"{BOLD}{'#':<4} {'Timestamp':<12} {'Payload Password':<22} {'HTTP':<6} {'Latency':<9} {'Status / SIEM Response'}{RESET}")
    print("-" * 70)

    test_start_time = time.time()
    detection_time_sec = None
    lockout_detected = False
    lockout_attempt_num = None
    rate_limit_detected = False
    results = []

    for i in range(1, attempts + 1):
        fake_password = f"WrongPassword_{i}_{int(time.time())}"
        payload = {
            "email": email,
            "password": fake_password
        }
        
        req_start = time.time()
        try:
            resp = requests.post(
                login_endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            req_latency_ms = round((time.time() - req_start) * 1000, 2)
            status_code = resp.status_code
            resp_json = {}
            try:
                resp_json = resp.json()
            except Exception:
                resp_json = {"raw": resp.text}

        except Exception as e:
            req_latency_ms = round((time.time() - req_start) * 1000, 2)
            status_code = 0
            resp_json = {"error": str(e)}

        timestamp_str = datetime.now().strftime("%H:%M:%S.%f")[:12]
        
        # Determine status classification
        if status_code == 401:
            status_desc = f"{YELLOW}401 Invalid Credentials{RESET}"
        elif status_code == 423:
            status_desc = f"{RED}{BOLD}423 LOCKED (Account Locked by SIEM){RESET}"
            if not lockout_detected:
                lockout_detected = True
                lockout_attempt_num = i
                detection_time_sec = round(time.time() - test_start_time, 3)
        elif status_code == 429:
            status_desc = f"{MAGENTA}{BOLD}429 RATE LIMITED (Express Limiter){RESET}"
            rate_limit_detected = True
            if not detection_time_sec:
                detection_time_sec = round(time.time() - test_start_time, 3)
        elif status_code == 200:
            status_desc = f"{GREEN}200 OK (Unexpected Success){RESET}"
        else:
            status_desc = f"{RED}HTTP {status_code}: {resp_json.get('message', '')}{RESET}"

        print(f"{i:<4} {timestamp_str:<12} {fake_password[:20]:<22} {status_code:<6} {req_latency_ms:<7}ms {status_desc}")

        results.append({
            "attempt": i,
            "timestamp": datetime.now().isoformat(),
            "password_sent": fake_password,
            "status_code": status_code,
            "latency_ms": req_latency_ms,
            "response": resp_json
        })

        if delay > 0 and i < attempts:
            time.sleep(delay)

    total_duration_sec = round(time.time() - test_start_time, 3)

    print("-" * 70)
    print(f"\n{BOLD}[*] Querying Mini-SIEM Verification & Threat Metrics...{RESET}")

    # Query SIEM Dashboard & Threat state using admin credentials
    siem_verification = verify_siem_state(target_url, admin_email, admin_password, email)

    # Compile Final Report
    report = {
        "test_name": "Credential Brute-Force Attack Simulation",
        "target_url": target_url,
        "target_account": email,
        "total_attempts_sent": attempts,
        "total_duration_seconds": total_duration_sec,
        "attack_detected": lockout_detected or rate_limit_detected or siem_verification.get("alert_generated", False),
        "mitigation_triggered": lockout_detected,
        "lockout_threshold_attempt": lockout_attempt_num,
        "time_to_detection_seconds": detection_time_sec or total_duration_sec,
        "rate_limiting_triggered": rate_limit_detected,
        "siem_metrics": siem_verification,
        "detailed_results": results
    }

    print_summary(report)

    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n{GREEN}[+] Full test results saved to: {output_file}{RESET}")

    return report


def verify_siem_state(target_url, admin_email, admin_password, target_user_email):
    """Authenticate to SIEM API to retrieve real risk scores, threat level, and generated alerts."""
    state = {
        "admin_authenticated": False,
        "risk_score": "N/A",
        "threat_level": "N/A",
        "alert_generated": False,
        "alert_count": 0,
        "recent_alerts": [],
        "brute_force_active_locks": 0
    }

    try:
        login_url = f"{target_url.rstrip('/')}/api/auth/login"
        resp = requests.post(login_url, json={"email": admin_email, "password": admin_password}, timeout=5)
        if resp.status_code != 200:
            state["auth_error"] = f"Admin login returned HTTP {resp.status_code}"
            return state

        token = resp.json().get("token")
        state["admin_authenticated"] = True
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Threat Level
        try:
            tl_resp = requests.get(f"{target_url.rstrip('/')}/api/dashboard/threat-level", headers=headers, timeout=5)
            if tl_resp.status_code == 200:
                tl_data = tl_resp.json()
                state["threat_level"] = tl_data.get("level", "UNKNOWN")
                state["threat_score"] = tl_data.get("score", 0)
        except Exception:
            pass

        # 2. Risk Scores
        try:
            rs_resp = requests.get(f"{target_url.rstrip('/')}/api/security/risk-scores", headers=headers, timeout=5)
            if rs_resp.status_code == 200:
                scores = rs_resp.json()
                state["ip_risk_scores"] = scores
                if scores and isinstance(scores, list):
                    state["risk_score"] = scores[0].get("score")
                    state["risk_level"] = scores[0].get("level")
        except Exception:
            pass

        # 3. Alerts
        try:
            al_resp = requests.get(f"{target_url.rstrip('/')}/api/alerts?limit=10", headers=headers, timeout=5)
            if al_resp.status_code == 200:
                alerts_data = al_resp.json().get("data", [])
                bf_alerts = [a for a in alerts_data if "BRUTE_FORCE" in a.get("type", "") or "RATE_LIMIT" in a.get("type", "")]
                state["alert_generated"] = len(bf_alerts) > 0
                state["alert_count"] = len(bf_alerts)
                state["recent_alerts"] = [{"type": a.get("type"), "severity": a.get("severity"), "message": a.get("message")} for a in bf_alerts[:3]]
        except Exception:
            pass

        # 4. Brute Force Lock Status
        try:
            bf_resp = requests.get(f"{target_url.rstrip('/')}/api/security/brute-force", headers=headers, timeout=5)
            if bf_resp.status_code == 200:
                bf_data = bf_resp.json()
                state["brute_force_active_locks"] = bf_data.get("currentlyLocked", 0)
        except Exception:
            pass

    except Exception as e:
        state["verification_error"] = str(e)

    return state


def print_summary(report):
    print(f"\n{CYAN}{BOLD}======================================================================{RESET}")
    print(f"{CYAN}{BOLD}                     MEASURABLE TEST RESULTS                          {RESET}")
    print(f"{CYAN}{BOLD}======================================================================{RESET}")
    
    det_color = GREEN if report["attack_detected"] else RED
    mit_color = GREEN if report["mitigation_triggered"] else RED

    print(f" {BOLD}Target Endpoint        :{RESET} {report['target_url']}/api/auth/login")
    print(f" {BOLD}Targeted Account       :{RESET} {report['target_account']}")
    print(f" {BOLD}Total Attack Attempts  :{RESET} {report['total_attempts_sent']}")
    print(f" {BOLD}Attack Detected?       :{RESET} {det_color}{'YES [PASS]' if report['attack_detected'] else 'NO [FAIL]'}{RESET}")
    print(f" {BOLD}Detection Trigger Step :{RESET} Attempt #{report['lockout_threshold_attempt'] or 'N/A'}")
    print(f" {BOLD}Time-to-Detection      :{RESET} {report['time_to_detection_seconds']}s")
    print(f" {BOLD}Mitigation Triggered?  :{RESET} {mit_color}{'YES (Account Locked - HTTP 423)' if report['mitigation_triggered'] else 'NO'}{RESET}")
    print(f" {BOLD}Rate Limiting Active?  :{RESET} {'YES (HTTP 429)' if report['rate_limiting_triggered'] else 'NO'}")
    
    siem = report.get("siem_metrics", {})
    if siem.get("admin_authenticated"):
        print(f" {BOLD}SIEM Threat Level      :{RESET} {YELLOW}{siem.get('threat_level', 'N/A')} (Score: {siem.get('threat_score', 0)}){RESET}")
        print(f" {BOLD}Calculated IP Risk Score:{RESET} {RED if siem.get('risk_level') in ['HIGH', 'CRITICAL'] else YELLOW}{siem.get('risk_score', 'N/A')} [{siem.get('risk_level', 'N/A')}]{RESET}")
        print(f" {BOLD}Security Alerts Created:{RESET} {GREEN}{siem.get('alert_count', 0)} alert(s) generated in DB{RESET}")
        for idx, alert in enumerate(siem.get("recent_alerts", []), 1):
            print(f"    - Alert {idx}: [{alert.get('severity', '').upper()}] {alert.get('type')} — {alert.get('message')}")
    print(f"{CYAN}{BOLD}======================================================================{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Mini-SIEM Brute-Force Attack Simulation Test")
    parser.add_argument("--url", default="http://localhost:5001", help="Target Mini-SIEM API base URL (default: http://localhost:5001)")
    parser.add_argument("--email", default="admin@siem.local", help="Target email for brute force test")
    parser.add_argument("--attempts", type=int, default=10, help="Number of failed login attempts to send (default: 10)")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay in seconds between requests (default: 0.1)")
    parser.add_argument("--admin-email", default="admin@siem.local", help="SIEM Admin email for verification")
    parser.add_argument("--admin-password", default="Admin@1234", help="SIEM Admin password for verification")
    parser.add_argument("--output", default="brute_force_results.json", help="JSON output file path")

    args = parser.parse_args()

    print_banner()
    run_brute_force_test(
        target_url=args.url,
        email=args.email,
        attempts=args.attempts,
        delay=args.delay,
        admin_email=args.admin_email,
        admin_password=args.admin_password,
        output_file=args.output
    )


if __name__ == "__main__":
    main()
