# Mini-SIEM Security Testing & Attack Simulation Suite

>  **ETHICAL USE ONLY**  
> These attack simulation scripts are designed strictly for testing **your own local instance** of the Mini-SIEM application. Never run these scripts against external systems or unauthorized targets.

---

## Overview

The `security-tests` suite validates that Mini-SIEM does not just possess theoretical defensive code, but actively detects real attacks, computes dynamic risk scores, generates alerts, and enforces immediate mitigation (account lockouts and rate limiting) in real time.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ATTACK SIMULATION & DEFENSE FLOW                     │
├─────────────────┬───────────────────────────────────────────────────────┤
│ Attack Vector   │ 1. Script sends invalid login bursts (POST /login)   │
│ Ingestion Layer │ 2. Express logs events to PostgreSQL with IP & status │
│ Defense Layer 1 │ 3. Brute-force middleware locks account at attempt #5 │
│ Defense Layer 2 │ 4. Express-rate-limit blocks burst with HTTP 429     │
│ Analytics Engine│ 5. Python Detection Engine flags multi-IP spraying   │
│ Scoring Engine  │ 6. Threat level jumps LOW ➔ CRITICAL (Score > 30)    │
│ SIEM Dashboard  │ 7. Real-time alert triage & visual metric updates    │
└─────────────────┴───────────────────────────────────────────────────────┘
```

---

## Test Cases

| Script | Attack Scenario | Endpoint | Detection Mechanism | Mitigation Action |
|---|---|---|---|---|
| `brute_force_test.py` | Credential Brute-Force | `POST /api/auth/login` | Node.js middleware + Python Engine | HTTP 423 Account Lockout (30 min) |
| `rate_limit_test.py` | Rapid API Flood / DoS | `POST /api/auth/login` | `loginLimiter` (Express Rate Limit) | HTTP 429 Too Many Requests |
| `password_spray_test.py`| Distributed Password Spray | `POST /api/auth/login` | Python Detection Engine rule | Cross-IP correlation alert (CRITICAL)|
| `run_all_tests.py` | Full Security Benchmark | All endpoints | All multi-tier rules | Unified validation matrix |

---

## Installation & Setup

1. **Install Python dependencies:**
   ```bash
   cd security-tests
   pip install -r requirements.txt
   ```

2. **Ensure Mini-SIEM backend is running:**
   ```bash
   cd ../backend
   npm run dev
   ```

3. *(Optional)* **Ensure Python Detection Engine is running:**
   ```bash
   cd ../security_python
   python detector.py
   ```

---

## Running the Tests

### 1. Run the Credential Brute-Force Test
```bash
# Default: 10 attempts against admin@siem.local on http://localhost:5001
python brute_force_test.py

# Custom target and burst size
python brute_force_test.py --url http://localhost:5001 --email victim@siem.local --attempts 12 --delay 0.05
```

### 2. Run the Rate Limiting Flood Test
```bash
python rate_limit_test.py --url http://localhost:5001 --burst 20
```

### 3. Run the Distributed Password Spraying Test
```bash
python password_spray_test.py --url http://localhost:5001 --ips 8
```

### 4. Run the Full Security Test Suite
```bash
python run_all_tests.py --url http://localhost:5001
```

---

## Output Metrics & Artifacts

Each test outputs:
- **Terminal Execution Stream:** Per-request HTTP status codes, latencies (ms), and detection triggers.
- **Measurable Summary Matrix:** Attack detection status, time-to-detection (TTD), mitigation outcome, and risk score.
- **JSON Test Reports:** `brute_force_results.json`, `rate_limit_results.json`, `password_spray_results.json`, and `full_security_test_report.json`.
