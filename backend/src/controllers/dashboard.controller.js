const db = require('../utils/db');
const { getAlertStats, getAlerts } = require('../services/alert.service');
const { getBruteForceStats } = require('../middleware/bruteForce.middleware');
const os = require('os');

const pad = n => String(n).padStart(2, '0');

const formatUptime = (seconds) => {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${d}d ${h}h ${m}m ${s}s`;
};

// GET /api/dashboard/summary
const getSummary = async (req, res) => {
    try {
        const [
            totalEventsRes,
            failedLoginsRes,
            successfulLoginsRes,
            recentLogsRes,
            alertStatsRes,
            recentAlertsRes,
            usersRes,
        ] = await Promise.all([
            db.query('SELECT COUNT(*) FROM logs'),
            db.query("SELECT COUNT(*) FROM logs WHERE event = 'LOGIN' AND success = false"),
            db.query("SELECT COUNT(*) FROM logs WHERE event = 'LOGIN' AND success = true"),
            db.query('SELECT timestamp, event, user_email, success, ip, details FROM logs ORDER BY timestamp DESC LIMIT 10'),
            getAlertStats(),
            getAlerts({ limit: 5 }),
            db.query('SELECT role, COUNT(*) FROM users GROUP BY role'),
        ]);

        const totalEvents    = parseInt(totalEventsRes.rows[0].count, 10) || 0;
        const failedLogins   = parseInt(failedLoginsRes.rows[0].count, 10) || 0;
        const successfulLogins = parseInt(successfulLoginsRes.rows[0].count, 10) || 0;
        const totalLogins    = failedLogins + successfulLogins;
        const loginSuccessRate = totalLogins > 0
            ? `${Math.round((successfulLogins / totalLogins) * 100)}%`
            : '100%';

        const byRole = {};
        let totalUsers = 0;
        usersRes.rows.forEach(r => {
            const count = parseInt(r.count, 10);
            byRole[r.role] = count;
            totalUsers += count;
        });

        const bruteForce = getBruteForceStats();

        res.status(200).json({
            generatedAt: new Date().toISOString(),
            security: {
                totalEvents,
                failedLogins,
                successfulLogins,
                loginSuccessRate,
                recentActivity: recentLogsRes.rows.map(log => ({
                    timestamp: log.timestamp,
                    event: log.event,
                    user: log.user_email,
                    success: log.success,
                    ip: log.ip,
                    details: log.details,
                })),
            },
            alerts: {
                ...alertStatsRes,
                recent: recentAlertsRes.data,
            },
            bruteForce: {
                totalTracked: bruteForce.totalTrackedIPs,
                currentlyLocked: bruteForce.currentlyLocked,
            },
            users: {
                total: totalUsers,
                byRole,
            },
            system: {
                uptimeFormatted: formatUptime(process.uptime()),
                platform: os.platform(),
                memoryUsageMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                nodeVersion: process.version,
            },
        });
    } catch (err) {
        console.error('[DASHBOARD SUMMARY ERROR]', err);
        res.status(500).json({ status: 'error', message: err.message || 'Failed to load dashboard summary' });
    }
};

// GET /api/dashboard/timeline?hours=24
const getTimeline = async (req, res) => {
    try {
        const hours = Math.min(parseInt(req.query.hours, 10) || 24, 168);
        const now = Date.now();

        const buckets = {};
        for (let h = hours; h >= 0; h--) {
            const ts = new Date(now - h * 60 * 60 * 1000);
            const key = `${ts.getUTCFullYear()}-${pad(ts.getUTCMonth() + 1)}-${pad(ts.getUTCDate())}T${pad(ts.getUTCHours())}:00Z`;
            buckets[key] = { timestamp: key, total: 0, failed: 0, success: 0 };
        }

        const logsRes = await db.query(
            "SELECT timestamp, success FROM logs WHERE timestamp >= NOW() - ($1 || ' hours')::INTERVAL",
            [hours]
        );

        logsRes.rows.forEach(log => {
            const d = new Date(log.timestamp);
            const key = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:00Z`;
            if (buckets[key]) {
                buckets[key].total++;
                if (log.success) buckets[key].success++;
                else buckets[key].failed++;
            }
        });

        res.status(200).json({ hours, buckets: Object.values(buckets) });
    } catch (err) {
        console.error('[TIMELINE ERROR]', err);
        res.status(500).json({ status: 'error', message: 'Failed to fetch timeline' });
    }
};

// GET /api/dashboard/threat-level
const getThreatLevel = async (req, res) => {
    try {
        const [alertStats, recentFailedRes] = await Promise.all([
            getAlertStats(),
            db.query("SELECT COUNT(*) FROM logs WHERE success = false AND timestamp > NOW() - INTERVAL '1 hour'"),
        ]);

        const bruteForce = getBruteForceStats();
        const recentFailed = parseInt(recentFailedRes.rows[0].count, 10) || 0;

        let score = 0;
        score += (alertStats.bySeverity?.critical || 0) * 10;
        score += (alertStats.bySeverity?.high || 0) * 5;
        score += (alertStats.bySeverity?.medium || 0) * 2;
        score += bruteForce.currentlyLocked * 8;
        score += recentFailed * 1;

        const level = score >= 30 ? 'CRITICAL' : score >= 15 ? 'HIGH' : score >= 5 ? 'MEDIUM' : 'LOW';

        res.status(200).json({
            level,
            score,
            factors: {
                criticalAlerts: alertStats.bySeverity?.critical || 0,
                highAlerts:     alertStats.bySeverity?.high     || 0,
                mediumAlerts:   alertStats.bySeverity?.medium   || 0,
                lockedAccounts: bruteForce.currentlyLocked,
                recentFailedEventsLastHour: recentFailed,
            },
        });
    } catch (err) {
        console.error('[THREAT LEVEL ERROR]', err);
        res.status(500).json({ status: 'error', message: err.message || 'Failed to fetch threat level' });
    }
};

module.exports = { getSummary, getTimeline, getThreatLevel };
