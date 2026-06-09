const { securityLogs, getSecurityMetrics } = require('../utils/logger');
const { getAlertStats } = require('../services/alert.service');
const { getBruteForceStats } = require('../middleware/bruteForce.middleware');
const { users } = require('../models/user.model');
const os = require('os');


const getSummary = (req, res) => {
    const metrics = getSecurityMetrics();
    const alertStats = getAlertStats();
    const bruteForce = getBruteForceStats();
    const uptimeSeconds = process.uptime();

    const recentActivity = securityLogs.slice(-20).reverse().map(log => ({
        timestamp: log.timestamp,
        event: log.event,
        user: log.userEmail,
        success: log.success,
        details: log.details,
    }));
    const totalLogins = metrics.failedLogins + metrics.successfulLogins;
    const loginSuccessRate = totalLogins > 0
        ? Math.round((metrics.successfulLogins / totalLogins) * 100)
        : 100;

    
    const topThreats = bruteForce.entries
        .filter(e => e.attempts > 0)
        .sort((a, b) => b.attempts - a.attempts)
        .slice(0, 5);

    res.status(200).json({
        generatedAt: new Date().toISOString(),
        system: {
            uptimeSeconds: Math.round(uptimeSeconds),
            uptimeFormatted: formatUptime(uptimeSeconds),
            nodeVersion: process.version,
            platform: os.platform(),
            memoryUsageMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        },
        users: {
            total: users.length,
            byRole: users.reduce((acc, u) => {
                acc[u.role] = (acc[u.role] || 0) + 1;
                return acc;
            }, {}),
        },
        security: {
            totalEvents: metrics.totalEvents,
            failedLogins: metrics.failedLogins,
            successfulLogins: metrics.successfulLogins,
            loginSuccessRate: `${loginSuccessRate}%`,
            recentActivity,
        },
        alerts: alertStats,
        bruteForce: {
            totalTracked: bruteForce.totalTrackedIPs,
            currentlyLocked: bruteForce.currentlyLocked,
            topThreats,
        },
    });
};


const getTimeline = (req, res) => {
    const hours = Math.min(parseInt(req.query.hours, 10) || 24, 168);
    const now = Date.now();
    const windowStart = now - hours * 60 * 60 * 1000;

    const relevant = securityLogs.filter(
        log => new Date(log.timestamp).getTime() >= windowStart
    );

    // Bucket by hour
    const buckets = {};
    for (let h = hours; h >= 0; h--) {
        const ts = new Date(now - h * 60 * 60 * 1000);
        const key = `${ts.getUTCFullYear()}-${pad(ts.getUTCMonth() + 1)}-${pad(ts.getUTCDate())}T${pad(ts.getUTCHours())}:00Z`;
        buckets[key] = { timestamp: key, total: 0, failed: 0, success: 0 };
    }

    relevant.forEach(log => {
        const d = new Date(log.timestamp);
        const key = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:00Z`;
        if (buckets[key]) {
            buckets[key].total++;
            if (log.success) buckets[key].success++;
            else buckets[key].failed++;
        }
    });

    res.status(200).json({
        hours,
        buckets: Object.values(buckets),
    });
};


const getThreatLevel = (req, res) => {
    const alertStats = getAlertStats();
    const bruteForce = getBruteForceStats();
    const recentFailed = securityLogs
        .filter(l => !l.success && new Date(l.timestamp).getTime() > Date.now() - 60 * 60 * 1000)
        .length;

    let score = 0;
    score += alertStats.bySeverity.critical * 10;
    score += alertStats.bySeverity.high * 5;
    score += alertStats.bySeverity.medium * 2;
    score += bruteForce.currentlyLocked * 8;
    score += recentFailed * 1;

    let level;
    if (score >= 30) level = 'CRITICAL';
    else if (score >= 15) level = 'HIGH';
    else if (score >= 5)  level = 'MEDIUM';
    else                  level = 'LOW';

    res.status(200).json({
        level,
        score,
        factors: {
            criticalAlerts: alertStats.bySeverity.critical,
            highAlerts: alertStats.bySeverity.high,
            mediumAlerts: alertStats.bySeverity.medium,
            lockedAccounts: bruteForce.currentlyLocked,
            recentFailedEventsLastHour: recentFailed,
        },
    });
};

const pad = n => String(n).padStart(2, '0');

const formatUptime = (seconds) => {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${d}d ${h}h ${m}m ${s}s`;
};

module.exports = { getSummary, getTimeline, getThreatLevel };
