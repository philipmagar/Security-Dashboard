# Security Dashboard API (Mini-SIEM)

A robust, scalable Node.js backend built to support the Security Dashboard (Mini-SIEM) application. This API handles log aggregation, real-time alert processing, and secure user management.

## 🚀 Technologies Used

- **Runtime Environment:** Node.js
- **Web Framework:** Express.js
- **ORM:** Prisma
- **Database:** PostgreSQL (Containerized with Docker)
- **Authentication:** JSON Web Tokens (JWT) & bcrypt for secure password hashing
- **Development Tooling:** Nodemon, dotenv, cors

## 🏗️ Architecture & Features

- **Secure User Management:** Role-based access control with hashed passwords and secure JWT authentication.
- **Log Ingestion:** Highly efficient data models for aggregating security logs across multiple sources.
- **Alerting System:** Built-in alert status tracking and severity management for incident response.
- **Containerized Database:** Simple and reproducible local development environment utilizing Docker Compose.

## 🛠️ Getting Started

### Prerequisites

Ensure you have the following installed on your local machine:
- [Node.js](https://nodejs.org/en/) (v16+ recommended)
- [Docker](https://www.docker.com/products/docker-desktop) and Docker Compose
- [Git](https://git-scm.com/)

### 1. Clone the Repository

```bash
git clone https://github.com/philipmagar/Security-Dashboard.git
cd Security-Dashboard/backend-node
```

### 2. Environment Configuration

Create a `.env` file in the root of your project:

```env
# Server Port Configuration
PORT=5001

# PostgreSQL Database Connection
# Adjust the port if necessary (e.g., 5433 if 5432 is in use)
DATABASE_URL="postgresql://postgres:postgres@localhost:5433/minisiem?schema=public"
```

### 3. Start the Database

Launch the containerized PostgreSQL instance in the background:

```bash
docker compose up -d
```

### 4. Install Dependencies & Setup Prisma

Install project packages and sync the database schema:

```bash
npm install
npx prisma db push
npx prisma generate
```

### 5. Run the Server

Start the development server with hot-reloading enabled:

```bash
npm run dev
```

The server will be available at `http://localhost:5001`. A basic health-check endpoint is exposed at `/api/health`.

## 🗄️ Database Schema Overview

The database relies on three core entities:
- **User**: Represents dashboard administrators and operators (`email`, `password`, `role`).
- **Log**: Records incoming system logs and metadata (`source`, `level`, `message`).
- **Alert**: Tracks active incidents and anomalies (`title`, `severity`, `status`).

## 🛡️ Security Measures

- Comprehensive `.gitignore` preventing accidental commits of sensitive configuration files (`.env`).
- Separation of concerns between the Express server and the ORM logic.
- Environment variables utilized for all sensitive routing and connection strings.
