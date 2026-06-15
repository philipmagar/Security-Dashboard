# Mini-SIEM — Security Information and Event Management

A lightweight SIEM (Security Information and Event Management) platform built with a Node.js/Express backend and a modern React frontend. This project demonstrates core security engineering concepts: API rate limiting, brute force detection, role-based access control, real-time security alerting, alert triage workflows, and dynamic dashboard analytics.

---

## Repository Structure

```text
mini-siem/
├── backend/     # Node.js & Express API — security engine, alerting, RBAC
└── frontend/    # React & Vite SPA — dashboard, logs explorer, alert management
```

---

## Features

### Backend Security Engine
- **API Rate Limiting:** Tiered limiters using `express-rate-limit` for global endpoints, logins, and alerts.
- **Brute Force Defense:** Two-layer protection on authentication endpoints with automatic account lockouts.
- **Role-Based Access Control (RBAC):** `user`, `operator`, and `admin` roles with progressive access levels enforced on every route.
- **Alert Engine:** Auto-generated alerts for brute force, rate limit violations, unauthorized access, invalid tokens, and role escalation attempts.
- **Risk Scoring & Threat Levels:** Computed risk scores per IP based on behavioral history (`LOW` → `CRITICAL`).
- **Security Logs:** Filterable, paginated audit trail of all system events.

### Frontend Operations Dashboard

#### Dashboard
- Real-time metrics: total events, login success rate, active brute force threats, unacknowledged alerts.
- High-risk entity table with IP addresses, risk levels, and computed scores.
- Recent alerts timeline panel with severity colour-coding.
- Auto-refreshes every 30 seconds.

#### Logs Explorer
- Searchable and filterable view of all security events.
- Responsive data table with pagination.

#### Alert Management 
- **Stats Bar:** Live counts for Total, Unacknowledged, Last-24h, and per-severity (Critical / High / Medium / Low / Info) alerts.
- **Filter & Search:** Filter alerts by severity, type, and acknowledgement status simultaneously.
- **Paginated Table:** Colour-coded severity rows with type, message, source IP, relative timestamp, and open/acknowledged status.
- **Acknowledge:** One-click triage per alert, or bulk-acknowledge all matching the active filters.
- **Delete:** Permanently remove an alert with a confirmation modal (admin only).
- **Create Manual Alert:** Form modal to fire a manual alert with type, severity, source, message, and optional JSON details.
- **Toast Notifications:** Real-time feedback for every action (acknowledge, delete, create).
- **Auto-refresh:** Syncs every 30 seconds in the background.

---

## Getting Started

### 1. Start the Backend Server

```bash
cd backend
npm install
# Ensure a .env file exists with PORT=5001 and JWT_SECRET=your-secret-key
npm run dev
```

The backend API will be available at `http://localhost:5001`.

### 2. Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

Vite will serve the app at `http://localhost:5173`.

---

## API Reference

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard/summary` | Full overview of events, alerts, and brute-force metrics |
| `GET` | `/api/security/risk-scores` | Dynamically computed IP risk scores |
| `GET` | `/api/security/logs` | Filterable, paginated audit log |

### Alert Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/alerts` | List alerts (filterable by `severity`, `type`, `acknowledged`) |
| `GET` | `/api/alerts/stats` | Counts by severity, type, and 24h window |
| `GET` | `/api/alerts/types` | Enumeration of all valid alert types |
| `GET` | `/api/alerts/:id` | Single alert by ID |
| `POST` | `/api/alerts` | Create a manual alert |
| `PATCH` | `/api/alerts/:id/acknowledge` | Acknowledge a single alert |
| `PATCH` | `/api/alerts/acknowledge-all` | Bulk-acknowledge with optional severity/type filter |
| `DELETE` | `/api/alerts/:id` | Delete an alert (admin only) |

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Register a new user |
| `POST` | `/api/auth/login` | Login and receive a JWT |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js, Express 5, express-rate-limit, jsonwebtoken, bcrypt |
| Frontend | React 18, Vite, React Router v6 |
| Styling | Vanilla CSS (dark theme, glassmorphism) |

---

_Developed by Philip Magar_
