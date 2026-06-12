# Mini-SIEM — Security Information and Event Management

A lightweight SIEM (Security Information and Event Management) platform built with a Node.js/Express backend and a modern React frontend. This project demonstrates core security engineering concepts: API rate limiting, brute force detection, role-based access control, real-time security alerting, and dynamic dashboard analytics.

---

##  Repository Structure

This is a monorepo containing both the backend API and the frontend web application.

```text
Security-Dashboard/
├── backend/       # Node.js & Express API, security logging, and alerting engine
└── frontend/      # React & Vite SPA, dynamic UI and metrics dashboard
```

---

## Features

### Backend Security Engine
- **API Rate Limiting:** Tiered limiters using `express-rate-limit` for global endpoints, logins, and alerts.
- **Brute Force Defense:** Two-layer chain protecting authentication endpoints with temporary account lockouts.
- **Role-Based Access Control (RBAC):** `user`, `operator`, and `admin` roles with progressive access levels.
- **Security Alert System:** Auto-generated alerts for suspicious activity, multiple failed logins, unauthorized access, and invalid tokens.
- **Risk Scoring & Threat Levels:** Computed risk scores per IP based on their behavioral history.

### Frontend Operations Dashboard
- **Real-Time Metrics:** Dynamic tracking of total events, login success rates, and active threats.
- **High Risk Entities:** Detailed breakdown of suspicious IPs and their computed risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Recent Alerts:** Timeline panel showcasing the latest security anomalies.
- **Modern UI/UX:** Responsive, dark-themed "glassmorphic" developer aesthetic.

---

## Getting Started

### 1. Start the Backend Server

Navigate to the `backend` directory, install dependencies, and start the development server.

```bash
cd backend
npm install

# Create a .env file with PORT=5001 and JWT_SECRET=your-secret-key
# (Or use the defaults provided in the project)

npm run dev
```
The backend API will be running on `http://localhost:5001`.

### 2. Start the Frontend Application

Open a new terminal window, navigate to the `frontend` directory, install dependencies, and start the Vite dev server.

```bash
cd frontend
npm install
npm run dev
```
Vite will provide a local URL (typically `http://localhost:5173`) where you can view the dashboard.

---

##  API Reference Overview

The backend exposes several critical endpoints for security monitoring:

- `GET /api/dashboard/summary` - Full overview of events, alerts, and brute force metrics.
- `GET /api/security/risk-scores` - Dynamically computed risk scores for tracked IPs.
- `GET /api/alerts` - List of generated security alerts.
- `GET /api/security/logs` - Filterable, paginated audit log of system events.

*(For detailed API routing and configurations, see the internal codebase in the `/backend` directory).*

---

_Developed by Philip Magar_
