const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

// ── Route imports ───────────────────────────────────────────────────────────
const authRoutes      = require('./src/routes/auth.routes');
const adminRoutes     = require('./src/routes/admin.routes');
const userRoutes      = require('./src/routes/user.routes');
const securityRoutes  = require('./src/routes/security.routes');
const alertRoutes     = require('./src/routes/alert.routes');
const dashboardRoutes = require('./src/routes/dashboard.routes');

// ── Middleware imports ──────────────────────────────────────────────────────
const { globalLimiter } = require('./src/middleware/rateLimiter.middleware');

dotenv.config();

const app = express();

// ── Core middleware ─────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Global rate limiter (applied to ALL /api/* routes) ─────────────────────
app.use('/api', globalLimiter);

// ── Routes ─────────────────────────────────────────────────────────────────
app.use('/api/auth',      authRoutes);
app.use('/api/admin',     adminRoutes);
app.use('/api/users',     userRoutes);
app.use('/api/security',  securityRoutes);
app.use('/api/alerts',    alertRoutes);
app.use('/api/dashboard', dashboardRoutes);

app.get('/api/health', (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Mini-SIEM API is running',
        timestamp: new Date().toISOString(),
        version: '2.0.0',
    });
});
app.use((req, res) => {
    res.status(404).json({ status: 'error', message: `Route ${req.method} ${req.originalUrl} not found` });
});
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.stack || err.message);
    res.status(err.status || 500).json({
        status: 'error',
        message: err.message || 'Internal server error',
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`\nMini-SIEM API running on http://localhost:${PORT}`);
    console.log(`Health:    GET /api/health`);
    console.log(`Auth:      POST /api/auth/login | POST /api/auth/register`);
    console.log(`Alerts:    GET /api/alerts`);
    console.log(`Dashboard:  GET /api/dashboard/summary`);
    console.log(`Security:   GET /api/security/metrics\n`);
});
