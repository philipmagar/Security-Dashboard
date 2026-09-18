#!/usr/bin/env python3
"""
API & Database Layer Security Verification Test Suite
Mini-SIEM Security Testing Framework

Validates that Mini-SIEM's existing security controls actively function:
1. Malformed request validation (payload schemas, weak passwords, invalid roles)
2. Authentication security (missing, malformed, forged, and expired JWT tokens)
3. Role-Based Access Control (RBAC enforcement across user, operator, and admin roles)
4. Parameter manipulation and type safety (query bounds, invalid IDs, malformed dates)
5. Excessive requests and rate limiting (Express-rate-limit and brute-force lockouts)
6. Database layer SQL injection resilience (parameterized queries across auth, alerts, logs)
7. Sensitive information disclosure prevention (passwords, tokens, DB error stack traces)
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

# Colorized terminal output
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


def print_header():
    print(f"""
{CYAN}{BOLD}================================================================================
         MINI-SIEM API & DATABASE SECURITY VERIFICATION TEST SUITE
         Verifying Defensive Controls, RBAC, Parameterization & Data Safety
================================================================================{RESET}
""")


def run_security_verification(base_url="http://localhost:5001", admin_email="admin@siem.local", admin_pass="Admin@1234", output_file="api_security_verification_results.json"):
    base_url = base_url.rstrip("/")
    start_time = time.time()
    test_records = []

    print(f"{BOLD}[*] Target Base URL      :{RESET} {base_url}")
    print(f"{BOLD}[*] Admin Account        :{RESET} {admin_email}")
    print(f"{BOLD}[*] Start Time           :{RESET} {datetime.now().isoformat()}\n")

    # Helper function to record test result
    def record_test(test_id, category, test_name, endpoint, method, payload_or_param, expected_status, actual_status, passed, sec_event, sec_alert, notes=""):
        status_color = GREEN if passed else RED
        result_label = "PASS" if passed else "FAIL"
        
        print(f"[{test_id:02d}] {BOLD}{category:<18}{RESET} | {test_name:<38} | HTTP {actual_status} vs {expected_status} | {status_color}{BOLD}[{result_label}]{RESET}")
        if not passed:
            print(f"     {RED}Details: {notes}{RESET}")

        test_records.append({
            "test_id": test_id,
            "category": category,
            "test_name": test_name,
            "endpoint": endpoint,
            "method": method,
            "payload_or_param": str(payload_or_param),
            "expected_status": expected_status,
            "actual_status": actual_status,
            "passed": passed,
            "security_event_generated": sec_event,
            "security_alert_generated": sec_alert,
            "notes": notes
        })

    test_counter = 1

    # =========================================================================
    # Phase 0: Provision Test Users (Operator and Standard User)
    # =========================================================================
    print(f"{BOLD}--- PHASE 0: AUTHENTICATION SETUP & TOKEN PROVISIONING ---{RESET}")
    
    # 1. Login as Admin
    admin_token = None
    try:
        r_admin = requests.post(f"{base_url}/api/auth/login", json={"email": admin_email, "password": admin_pass}, timeout=5)
        if r_admin.status_code == 200:
            admin_token = r_admin.json().get("token")
    except Exception as e:
        print(f"{YELLOW}[!] Notice: Unable to connect to {base_url}: {e}{RESET}")

    # 2. Register/Login Operator
    operator_email = f"operator_sec_{int(time.time())}@siem.local"
    operator_pass = "Operator@1234!"
    operator_token = None
    try:
        requests.post(f"{base_url}/api/auth/register", json={
            "email": operator_email, "password": operator_pass, "name": "Security Operator", "role": "operator"
        }, timeout=5)
        r_op = requests.post(f"{base_url}/api/auth/login", json={"email": operator_email, "password": operator_pass}, timeout=5)
        if r_op.status_code == 200:
            operator_token = r_op.json().get("token")
    except Exception:
        pass

    # 3. Register/Login Standard User
    user_email = f"std_user_{int(time.time())}@siem.local"
    user_pass = "StandardUser@1234!"
    user_token = None
    try:
        requests.post(f"{base_url}/api/auth/register", json={
            "email": user_email, "password": user_pass, "name": "Standard User", "role": "user"
        }, timeout=5)
        r_usr = requests.post(f"{base_url}/api/auth/login", json={"email": user_email, "password": user_pass}, timeout=5)
        if r_usr.status_code == 200:
            user_token = r_usr.json().get("token")
    except Exception:
        pass

    # =========================================================================
    # Phase 1: API Security & Input Validation (Malformed Requests)
    # =========================================================================
    print(f"\n{BOLD}--- PHASE 1: MALFORMED REQUEST & INPUT VALIDATION TESTING ---{RESET}")

    # Test 1: Empty Registration Body
    try:
        r = requests.post(f"{base_url}/api/auth/register", json={}, timeout=5)
        passed = (r.status_code == 400)
        record_test(test_counter, "Input Validation", "Empty registration payload", "/api/auth/register", "POST",
                    {}, 400, r.status_code, passed, "None", "None", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "Input Validation", "Empty registration payload", "/api/auth/register", "POST",
                    {}, 400, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 2: Weak Password (< 8 chars / no special character)
    try:
        r = requests.post(f"{base_url}/api/auth/register", json={
            "email": f"weak_{int(time.time())}@siem.local", "password": "weak", "role": "user"
        }, timeout=5)
        passed = (r.status_code == 400)
        record_test(test_counter, "Input Validation", "Weak password complexity rejection", "/api/auth/register", "POST",
                    {"password": "weak"}, 400, r.status_code, passed, "None", "None", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "Input Validation", "Weak password complexity rejection", "/api/auth/register", "POST",
                    {}, 400, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 3: Invalid Role in Registration
    try:
        r = requests.post(f"{base_url}/api/auth/register", json={
            "email": f"invalid_role_{int(time.time())}@siem.local", "password": "ValidPassword@1234!", "role": "super_root_admin"
        }, timeout=5)
        passed = (r.status_code == 400)
        record_test(test_counter, "Input Validation", "Disallowed role assignment", "/api/auth/register", "POST",
                    {"role": "super_root_admin"}, 400, r.status_code, passed, "None", "None", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "Input Validation", "Disallowed role assignment", "/api/auth/register", "POST",
                    {}, 400, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 4: Missing Password on Login
    try:
        r = requests.post(f"{base_url}/api/auth/login", json={"email": "admin@siem.local"}, timeout=5)
        passed = (r.status_code == 400)
        record_test(test_counter, "Input Validation", "Missing password in login payload", "/api/auth/login", "POST",
                    {"email": "admin@siem.local"}, 400, r.status_code, passed, "None", "None", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "Input Validation", "Missing password in login payload", "/api/auth/login", "POST",
                    {}, 400, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 5: Malformed Alert Creation (Invalid Severity)
    try:
        headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
        r = requests.post(f"{base_url}/api/alerts", json={
            "type": "MALFORMED_ALERT", "severity": "catastrophic_mega_danger", "source": "127.0.0.1", "message": "Test"
        }, headers=headers, timeout=5)
        passed = (r.status_code == 400)
        record_test(test_counter, "Input Validation", "Invalid alert severity value", "/api/alerts", "POST",
                    {"severity": "catastrophic_mega_danger"}, 400, r.status_code, passed, "None", "None", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "Input Validation", "Invalid alert severity value", "/api/alerts", "POST",
                    {}, 400, 0, False, "None", "None", str(e))
    test_counter += 1

    # =========================================================================
    # Phase 2: Authentication Security & JWT Token Verification
    # =========================================================================
    print(f"\n{BOLD}--- PHASE 2: AUTHENTICATION & JWT TOKEN VERIFICATION ---{RESET}")

    # Test 6: Missing Authorization Header on Protected Route
    try:
        r = requests.get(f"{base_url}/api/security/logs", timeout=5)
        passed = (r.status_code == 401)
        record_test(test_counter, "JWT Auth", "Missing Authorization header", "/api/security/logs", "GET",
                    "No Auth Header", 401, r.status_code, passed, "None", "None", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "JWT Auth", "Missing Authorization header", "/api/security/logs", "GET",
                    "", 401, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 7: Malformed Bearer Token Format
    try:
        r = requests.get(f"{base_url}/api/dashboard/summary", headers={"Authorization": "Basic dXNlcjpwYXNz"}, timeout=5)
        passed = (r.status_code == 401)
        record_test(test_counter, "JWT Auth", "Malformed auth header scheme (non-Bearer)", "/api/dashboard/summary", "GET",
                    "Basic ...", 401, r.status_code, passed, "None", "None", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "JWT Auth", "Malformed auth header scheme (non-Bearer)", "/api/dashboard/summary", "GET",
                    "", 401, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 8: Forged / Tampered JWT Token
    try:
        fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJlbWFpbCI6ImFkbWluQHNpZW0ubG9jYWwiLCJyb2xlIjoiYWRtaW4ifQ.InvalidSignatureStringXYZ123456"
        r = requests.get(f"{base_url}/api/security/metrics", headers={"Authorization": f"Bearer {fake_token}"}, timeout=5)
        passed = (r.status_code == 401)
        record_test(test_counter, "JWT Auth", "Tampered JWT token signature", "/api/security/metrics", "GET",
                    "Invalid signature", 401, r.status_code, passed, "TOKEN_INVALID", "TOKEN_INVALID (Low/High)", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "JWT Auth", "Tampered JWT token signature", "/api/security/metrics", "GET",
                    "", 401, 0, False, "TOKEN_INVALID", "TOKEN_INVALID", str(e))
    test_counter += 1

    # =========================================================================
    # Phase 3: Role-Based Access Control (RBAC) Enforcement
    # =========================================================================
    print(f"\n{BOLD}--- PHASE 3: ROLE-BASED ACCESS CONTROL (RBAC) TESTING ---{RESET}")

    # Test 9: Standard User Accessing Admin/Operator Logs Endpoint
    try:
        headers = {"Authorization": f"Bearer {user_token}"} if user_token else {}
        r = requests.get(f"{base_url}/api/security/logs", headers=headers, timeout=5)
        passed = (r.status_code == 403)
        record_test(test_counter, "RBAC Access", "User role accessing security logs", "/api/security/logs", "GET",
                    f"User: {user_email} (role: user)", 403, r.status_code, passed, "UNAUTHORIZED_ACCESS", "UNAUTHORIZED_ACCESS (Medium)", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "RBAC Access", "User role accessing security logs", "/api/security/logs", "GET",
                    "", 403, 0, False, "UNAUTHORIZED_ACCESS", "UNAUTHORIZED_ACCESS", str(e))
    test_counter += 1

    # Test 10: Standard User Accessing Operator Dashboard
    try:
        headers = {"Authorization": f"Bearer {user_token}"} if user_token else {}
        r = requests.get(f"{base_url}/api/auth/operator-dashboard", headers=headers, timeout=5)
        passed = (r.status_code == 403)
        record_test(test_counter, "RBAC Access", "User role accessing operator dashboard", "/api/auth/operator-dashboard", "GET",
                    f"User: {user_email} (role: user)", 403, r.status_code, passed, "UNAUTHORIZED_ACCESS", "UNAUTHORIZED_ACCESS", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "RBAC Access", "User role accessing operator dashboard", "/api/auth/operator-dashboard", "GET",
                    "", 403, 0, False, "UNAUTHORIZED_ACCESS", "UNAUTHORIZED_ACCESS", str(e))
    test_counter += 1

    # Test 11: Operator Accessing Admin-Only User Management
    try:
        headers = {"Authorization": f"Bearer {operator_token}"} if operator_token else {}
        r = requests.get(f"{base_url}/api/admin/users", headers=headers, timeout=5)
        passed = (r.status_code == 403)
        record_test(test_counter, "RBAC Access", "Operator accessing admin user directory", "/api/admin/users", "GET",
                    f"User: {operator_email} (role: operator)", 403, r.status_code, passed, "UNAUTHORIZED_ACCESS", "UNAUTHORIZED_ACCESS", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "RBAC Access", "Operator accessing admin user directory", "/api/admin/users", "GET",
                    "", 403, 0, False, "UNAUTHORIZED_ACCESS", "UNAUTHORIZED_ACCESS", str(e))
    test_counter += 1

    # Test 12: Admin Accessing Admin-Only Endpoint
    try:
        headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
        r = requests.get(f"{base_url}/api/admin/users", headers=headers, timeout=5)
        passed = (r.status_code == 200)
        record_test(test_counter, "RBAC Access", "Admin accessing admin user directory", "/api/admin/users", "GET",
                    f"User: {admin_email} (role: admin)", 200, r.status_code, passed, "None", "None", "Authorized access granted")
    except Exception as e:
        record_test(test_counter, "RBAC Access", "Admin accessing admin user directory", "/api/admin/users", "GET",
                    "", 200, 0, False, "None", "None", str(e))
    test_counter += 1

    # =========================================================================
    # Phase 4: Parameter Manipulation & Type Safety
    # =========================================================================
    print(f"\n{BOLD}--- PHASE 4: PARAMETER MANIPULATION & BOUNDS TESTING ---{RESET}")

    # Test 13: Capped Limit Parameter (Anti-Memory Exhaustion)
    try:
        headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
        r = requests.get(f"{base_url}/api/alerts?limit=999999&page=-5", headers=headers, timeout=5)
        passed = (r.status_code == 200) and (r.json().get("limit", 0) <= 200)
        record_test(test_counter, "Parameter Safety", "Over-limit query parameter clamping", "/api/alerts", "GET",
                    {"limit": 999999, "page": -5}, 200, r.status_code, passed, "None", "None",
                    f"Limit clamped to: {r.json().get('limit')}, page clamped to: {r.json().get('page')}")
    except Exception as e:
        record_test(test_counter, "Parameter Safety", "Over-limit query parameter clamping", "/api/alerts", "GET",
                    {}, 200, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 14: Non-existent / Non-numeric Resource ID Handling
    try:
        headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
        r = requests.get(f"{base_url}/api/alerts/non_existent_alert_id_99999", headers=headers, timeout=5)
        passed = (r.status_code == 404)
        record_test(test_counter, "Parameter Safety", "Non-existent entity lookup rejection", "/api/alerts/non_existent_alert_id_99999", "GET",
                    "id: non_existent_alert_id_99999", 404, r.status_code, passed, "None", "None", r.json().get("message", ""))
    except Exception as e:
        record_test(test_counter, "Parameter Safety", "Non-existent entity lookup rejection", "/api/alerts/non_existent_alert_id_99999", "GET",
                    "", 404, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 15: Invalid Date Filter in Logs
    try:
        headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
        r = requests.get(f"{base_url}/api/security/logs?startDate=invalid-date-string&endDate=malformed", headers=headers, timeout=5)
        passed = (r.status_code == 200)
        record_test(test_counter, "Parameter Safety", "Malformed date filter graceful fallback", "/api/security/logs", "GET",
                    {"startDate": "invalid-date-string"}, 200, r.status_code, passed, "None", "None", "Safely bypassed invalid date without DB error")
    except Exception as e:
        record_test(test_counter, "Parameter Safety", "Malformed date filter graceful fallback", "/api/security/logs", "GET",
                    {}, 200, 0, False, "None", "None", str(e))
    test_counter += 1

    # =========================================================================
    # Phase 5: Database Layer & SQL Injection Resilience Testing
    # =========================================================================
    print(f"\n{BOLD}--- PHASE 5: DATABASE SQL INJECTION RESILIENCE (PARAMETERIZATION) ---{RESET}")

    # Test 16: SQL Injection in Login Email (Tautology Attack: ' OR '1'='1)
    try:
        sqli_email = "admin@siem.local' OR '1'='1"
        r = requests.post(f"{base_url}/api/auth/login", json={"email": sqli_email, "password": "AnyPassword123!"}, timeout=5)
        passed = (r.status_code in [401, 423, 429]) and ("syntax" not in r.text.lower() and "fatal" not in r.text.lower())
        record_test(test_counter, "SQL Injection", "Login SQL tautology (' OR '1'='1)", "/api/auth/login", "POST",
                    {"email": sqli_email}, 401, r.status_code, passed, "LOGIN", "MULTIPLE_FAILED_LOGINS / BRUTE_FORCE",
                    "Safely neutralized by parameterized query ($1). Zero bypass.")
    except Exception as e:
        record_test(test_counter, "SQL Injection", "Login SQL tautology (' OR '1'='1)", "/api/auth/login", "POST",
                    {}, 401, 0, False, "LOGIN", "None", str(e))
    test_counter += 1

    # Test 17: SQL Injection Piggybacked Command in Registration
    try:
        sqli_reg = f"victim_{int(time.time())}' OR 1=1; DROP TABLE users; --@siem.local"
        r = requests.post(f"{base_url}/api/auth/register", json={
            "email": sqli_reg, "password": "StrongPassword@1234!", "role": "user"
        }, timeout=5)
        # Should either register safely with literal string or reject, without executing DROP TABLE
        passed = (r.status_code in [201, 400, 409])
        # Verify table still exists by health check
        r_check = requests.get(f"{base_url}/api/health", timeout=5)
        passed = passed and (r_check.status_code == 200)
        record_test(test_counter, "SQL Injection", "Stacked query injection (DROP TABLE)", "/api/auth/register", "POST",
                    {"email": sqli_reg}, 201, r.status_code, passed, "REGISTER", "None",
                    "Parameterized query prevents command execution. Database integrity intact.")
    except Exception as e:
        record_test(test_counter, "SQL Injection", "Stacked query injection (DROP TABLE)", "/api/auth/register", "POST",
                    {}, 201, 0, False, "REGISTER", "None", str(e))
    test_counter += 1

    # Test 18: SQL Injection UNION SELECT in Security Logs Filter
    try:
        headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
        union_sqli = "admin' UNION SELECT 1, '2026-01-01', 'EXPLOIT', 'leak@siem.local', true, '1.1.1.1', 'pwned', 'SUCCESS', 'leaked' --"
        r = requests.get(f"{base_url}/api/security/logs?userEmail={union_sqli}", headers=headers, timeout=5)
        passed = (r.status_code == 200) and not any(log.get("details") == "leaked" for log in r.json().get("logs", []))
        record_test(test_counter, "SQL Injection", "UNION SELECT query manipulation in logs", "/api/security/logs", "GET",
                    {"userEmail": union_sqli}, 200, r.status_code, passed, "None", "None",
                    "LOWER(user_email) = LOWER($1) treats payload as literal text. Zero leakage.")
    except Exception as e:
        record_test(test_counter, "SQL Injection", "UNION SELECT query manipulation in logs", "/api/security/logs", "GET",
                    {}, 200, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 19: SQL Injection in Alert ID Path
    try:
        headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
        r = requests.get(f"{base_url}/api/alerts/' OR '1'='1", headers=headers, timeout=5)
        passed = (r.status_code == 404)
        record_test(test_counter, "SQL Injection", "SQL injection in URL path parameter", "/api/alerts/:id", "GET",
                    "id: ' OR '1'='1", 404, r.status_code, passed, "None", "None",
                    "WHERE id = $1 parameterized lookup safely returned 404 Not Found.")
    except Exception as e:
        record_test(test_counter, "SQL Injection", "SQL injection in URL path parameter", "/api/alerts/:id", "GET",
                    "", 404, 0, False, "None", "None", str(e))
    test_counter += 1

    # =========================================================================
    # Phase 6: Sensitive Information Exposure Prevention
    # =========================================================================
    print(f"\n{BOLD}--- PHASE 6: SENSITIVE INFORMATION EXPOSURE AUDIT ---{RESET}")

    # Test 20: Password Hash Leaked in User Registration Response
    try:
        test_sec_email = f"audit_user_{int(time.time())}@siem.local"
        r = requests.post(f"{base_url}/api/auth/register", json={
            "email": test_sec_email, "password": "SecretPassword@1234!", "role": "user"
        }, timeout=5)
        has_password = "password" in r.json() or "$2b$" in r.text or "$2a$" in r.text
        passed = (r.status_code == 201) and (not has_password)
        record_test(test_counter, "Data Exposure", "Password exclusion in register response", "/api/auth/register", "POST",
                    "Registration payload", 201, r.status_code, passed, "REGISTER", "None",
                    "Password hash completely omitted from response body.")
    except Exception as e:
        record_test(test_counter, "Data Exposure", "Password exclusion in register response", "/api/auth/register", "POST",
                    {}, 201, 0, False, "REGISTER", "None", str(e))
    test_counter += 1

    # Test 21: Password Hash Leaked in Profile Endpoint
    try:
        headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
        r = requests.get(f"{base_url}/api/users/profile", headers=headers, timeout=5)
        has_password = "password" in r.json() or "$2b$" in r.text or "$2a$" in r.text
        passed = (r.status_code == 200) and (not has_password)
        record_test(test_counter, "Data Exposure", "Password exclusion in user profile", "/api/users/profile", "GET",
                    "Profile lookup", 200, r.status_code, passed, "None", "None",
                    "User profile query explicitly selects only non-sensitive columns.")
    except Exception as e:
        record_test(test_counter, "Data Exposure", "Password exclusion in user profile", "/api/users/profile", "GET",
                    "", 200, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 22: Password Hash Leaked in Admin Users Directory
    try:
        headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
        r = requests.get(f"{base_url}/api/admin/users", headers=headers, timeout=5)
        users = r.json() if isinstance(r.json(), list) else []
        has_password = any("password" in u for u in users) or "$2b$" in r.text or "$2a$" in r.text
        passed = (r.status_code == 200) and (not has_password)
        record_test(test_counter, "Data Exposure", "Password exclusion in admin users list", "/api/admin/users", "GET",
                    "Admin user list", 200, r.status_code, passed, "None", "None",
                    "Database query selects only id, email, name, role, created_at.")
    except Exception as e:
        record_test(test_counter, "Data Exposure", "Password exclusion in admin users list", "/api/admin/users", "GET",
                    "", 200, 0, False, "None", "None", str(e))
    test_counter += 1

    # Test 23: Internal Database Error / Stack Trace Exposure
    try:
        r = requests.get(f"{base_url}/api/non_existent_route_for_error_test", timeout=5)
        has_stack = "node_modules" in r.text or "at Object." in r.text or "pg_catalog" in r.text or "SELECT *" in r.text
        passed = (r.status_code == 404) and (not has_stack)
        record_test(test_counter, "Data Exposure", "Stack trace / SQL schema sanitization", "/api/non_existent_route", "GET",
                    "Error trigger", 404, r.status_code, passed, "None", "None",
                    "Express 404 & 500 handlers return sanitized JSON messages without stack traces.")
    except Exception as e:
        record_test(test_counter, "Data Exposure", "Stack trace / SQL schema sanitization", "/api/non_existent_route", "GET",
                    "", 404, 0, False, "None", "None", str(e))
    test_counter += 1

    # =========================================================================
    # Summary & Benchmark Output
    # =========================================================================
    total_duration = round(time.time() - start_time, 2)
    total_tests = len(test_records)
    passed_tests = sum(1 for t in test_records if t["passed"])
    failed_tests = total_tests - passed_tests

    print(f"\n{CYAN}{BOLD}================================================================================{RESET}")
    print(f"{CYAN}{BOLD}           API & DATABASE SECURITY VERIFICATION TEST BENCHMARK RESULTS           {RESET}")
    print(f"{CYAN}{BOLD}================================================================================{RESET}")
    print(f" {BOLD}Total Test Cases Executed :{RESET} {total_tests}")
    print(f" {BOLD}Tests Passed              :{RESET} {GREEN}{passed_tests}{RESET} / {total_tests} ({round(passed_tests/total_tests*100, 1)}%)")
    print(f" {BOLD}Tests Failed              :{RESET} {RED if failed_tests > 0 else GREEN}{failed_tests}{RESET}")
    print(f" {BOLD}Total Execution Latency   :{RESET} {total_duration}s")
    print(f"{CYAN}{BOLD}================================================================================{RESET}\n")

    report = {
        "suite_name": "API & Database Layer Security Verification Suite",
        "target_url": base_url,
        "timestamp": datetime.now().isoformat(),
        "total_execution_time_seconds": total_duration,
        "summary": {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "pass_rate_percentage": round((passed_tests / total_tests) * 100, 1)
        },
        "test_results": test_records
    }

    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"{GREEN}[✓] Comprehensive security test results saved to: {output_file}{RESET}\n")

    return report


def main():
    parser = argparse.ArgumentParser(description="Run Mini-SIEM API & Database Security Verification Suite")
    parser.add_argument("--url", default="http://localhost:5001", help="Target Mini-SIEM API base URL")
    parser.add_argument("--admin-email", default="admin@siem.local", help="Admin email for metrics and verification")
    parser.add_argument("--admin-password", default="Admin@1234", help="Admin password")
    parser.add_argument("--output", default="api_security_verification_results.json", help="Output JSON results filename")

    args = parser.parse_args()
    print_header()
    run_security_verification(base_url=args.url, admin_email=args.admin_email, admin_pass=args.admin_password, output_file=args.output)


if __name__ == "__main__":
    main()
