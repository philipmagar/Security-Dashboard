# Mini-SIEM (Security Information and Event Management)

**A personal learning project exploring backend security and API design.**

---

## Project Overview

Welcome to **Mini-SIEM**, a lightweight Security Information and Event Management backend.

In today's digital landscape, monitoring security events is critical. However, enterprise-grade tools are often resource-heavy and complex. I built this project to demonstrate how core security logging, real-time alert processing, and secure user authentication can be achieved efficiently using modern, lightweight web technologies.

This project serves as a showcase of my ability to design, build, and secure a backend API from the ground up.

## Key Technical Skills Demonstrated

- **API Design:** Built a scalable, low-latency RESTful API using **Node.js** and **Express.js**.
- **Information Security:** Implemented robust user authentication flows using **bcrypt** for password hashing and stateless **JSON Web Tokens (JWT)** for session management.
- **Role-Based Access Control (RBAC):** Integrated strict middleware authorization distinguishing between `admin`, `operator`, and standard `user` roles.
- **Software Architecture:** Structured the codebase using the **Model-View-Controller (MVC)** pattern, ensuring a clean separation between routing, business logic, and data access.
- **Security Logging & Metrics:** Engineered an event auditing system that continuously monitors and logs access violations, failed login attempts, and system anomalies, complete with metrics aggregation.

## Technology Stack

- **Backend:** Node.js, Express.js
- **Authentication:** JWT, bcrypt
- **Data Storage:** In-Memory Data Store (Optimized for prototyping and rapid testing)
- **Environment Management:** dotenv, Nodemon

---

## How to Run the Project

Want to see it in action? Follow these simple steps to run the API locally.

### 1. Clone the Repository

```bash
git clone https://github.com/philipmagar/Security-Dashboard.git
cd Security-Dashboard/backend-node
```

### 2. Set Up Environment Variables

Create a `.env` file in the root directory and add the following:

```env
PORT=5001(port 5000 was occupied by Docker Container)
JWT_SECRET=your-secure-academic-secret-key
```

### 3. Install & Start

```bash
npm install
npm run dev
```

The server will start at `http://localhost:5001`.

### Core API Endpoints

**Health & Status:**
- `GET /api/health` — Verifies the server is running.

**Authentication:**
- `POST /api/auth/register` — Registers a new user with a securely hashed password.
- `POST /api/auth/login` — Authenticates the user and returns a JWT token.

**User Operations:**
- `GET /api/users/profile` — Retrieves the authenticated user's profile (Requires JWT).

**Admin & Security Operations (RBAC Protected):**
- `GET /api/admin/users` — Lists all registered users (Requires `admin` role).
- `GET /api/security/metrics` — Aggregates security events like failed/successful logins (Requires `admin` or `operator` role).
- `GET /api/security/logs` — Retrieves recent system audit logs (Requires `admin` or `operator` role).

---

_This project was developed by Philip Magar as a personal learning initiative._
