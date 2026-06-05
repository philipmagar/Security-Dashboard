# Security Dashboard - Backend Node

This is the Node.js backend for the Security Dashboard project, utilizing Express and Prisma ORM with a PostgreSQL database.

## What was done today

* **Project Setup**: Initialized the Node.js backend with `express`, `cors`, `dotenv`, `jsonwebtoken`, and `bcrypt`.
* **Database & Prisma**: 
  * Configured Prisma and created the initial schema (`User`, `Log`, and `Alert` models).
  * Set up PostgreSQL inside a Docker container using `docker-compose`.
  * Synchronized the Prisma schema with the database (`npx prisma db push`) and generated the Prisma client.
* **Server Setup**: Created the Express server entry point (`index.js`) with a `/api/health` check endpoint.
* **Security & Git**: Configured `.env` for database credentials and added a comprehensive `.gitignore` to prevent sensitive information from being pushed to GitHub.

## Getting Started

1. Start the PostgreSQL database:
   ```bash
   docker compose up -d
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev
   ```

The server will be running on `http://localhost:5001`.
