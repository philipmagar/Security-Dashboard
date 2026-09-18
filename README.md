# Mini-SIEM — Security Information and Event Management

A lightweight, full-stack SIEM platform that monitors API security events, blocks attacks in real-time, and visualizes threats on a modern dashboard.

---

## How It Works

```text
[ User / Attacker ] ──► [ Express API ] ──► [ PostgreSQL ] ◄── [ Python Detection Engine ]
                              │
                              ▼
                    [ React Dashboard UI ]
```

1. **Express Backend:** Handles authentication (JWT), enforces user roles (RBAC), applies rate limiting, locks accounts on brute-force attempts, and logs all security events to the database.
2. **PostgreSQL Database:** Stores users, immutable audit logs, and security alerts.
3. **Python Detection Engine:** Runs in the background to detect complex attack patterns (like password spraying across multiple IPs) and generates threat alerts.
4. **React Frontend:** Displays live security metrics, interactive risk score charts, searchable audit logs, and an alert triage system.

---

## Key Features

* **Brute-Force & Rate Limit Defense:** Automatically locks accounts after 5 failed attempts (HTTP 423) and throttles request bursts (HTTP 429).
* **Role-Based Access Control (RBAC):** Tiered access for `user`, `operator`, and `admin` roles.
* **SQL Injection Prevention:** Uses parameterized queries to safely handle all user inputs.
* **Real-Time Alerting:** Auto-generates alerts for suspicious activity, failed logins, and unauthorized access attempts.
* **Interactive Dashboard:** Dark-mode UI with live event feeds, threat level scoring, and one-click alert management.

---

## Quickstart

### Run with Docker (Recommended)

Start the entire application with one command:

```bash
docker-compose up -d --build
```

* **Frontend Dashboard:** [http://localhost:5173](http://localhost:5173)
* **Backend API:** [http://localhost:5000](http://localhost:5000)

---

### Run Locally (Without Docker)

1. **Start PostgreSQL Database:**
   ```bash
   docker-compose up -d db
   ```

2. **Start Backend API:**
   ```bash
   cd backend
   npm install
   npm run dev
   ```

3. **Start Python Detection Engine:**
   ```bash
   cd security_python
   pip install -r requirements.txt
   python detector.py
   ```

4. **Start Frontend:**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

---

## Default Login Credentials

Use the **"Login as Demo Admin"** button on the login screen, or enter:

* **Email:** `admin@siem.local`
* **Password:** `Admin@1234`

---

## Security Verification & Tests

To test and verify the security controls against live simulated attacks:

```bash
cd security-tests
pip install -r requirements.txt

# Run the full automated test suite
python run_all_tests.py --url http://localhost:5001
```

### Verified Protections:
- **Input Validation & JWT Authentication:** Malformed bodies and invalid/forged tokens are rejected.
- **RBAC Enforcement:** Standard users cannot access operator or admin routes.
- **SQL Injection:** Neutralized via parameterized queries.
- **Brute-Force Lockout:** Account is locked for 30 minutes after 5 failed logins.
- **API Flood Protection:** Exceeding rate limits returns HTTP 429.

---

## Tech Stack

* **Frontend:** React 19, Vite, Tailwind CSS v4, Recharts
* **Backend:** Node.js, Express, PostgreSQL (`pg`), JWT, bcrypt
* **Detection:** Python 3, psycopg2
* **Database:** PostgreSQL 15

---

_Developed by Philip Magar_
