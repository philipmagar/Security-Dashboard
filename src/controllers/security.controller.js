const { getSecurityMetrics, securityLogs } = require('../utils/logger');
const { getBruteForceStats } = require('../middleware/bruteForce.middleware');
const { getAlertStats } = require('../services/alert.service');


const getMetrics = (req, res) => {
    const metrics = getSecurityMetrics();
    const bruteForce = getBruteForceStats();
    const alertStats = getAlertStats();

    res.status(200).json({
        generatedAt: new Date().toISOString(),
        events: {
            total: metrics.totalEvents,
            failedLogins: metrics.failedLogins,
            successfulLogins: metrics.successfulLogins,
            registrations: metrics.registrations,
            unauthorizedAttempts: metrics.unauthorizedAttempts,
            eventsLast24h: metrics.eventsLast24h,
        },
        bruteForce,
        alerts: alertStats,
        recentLogs: metrics.recentLogs,
    });
};


const getLogs = (req, res) => {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const event = req.query.event;
    const success = req.query.success;

    let logs = [...securityLogs].reverse(); // newest first

    if (event) {
        logs = logs.filter(l => l.event === event.toUpperCase());
    }
    if (success !== undefined) {
        const successBool = success === 'true';
        logs = logs.filter(l => l.success === successBool);
    }

    res.status(200).json({
        total: logs.length,
        returned: Math.min(logs.length, limit),
        logs: logs.slice(0, limit),
    });
};

const getBruteForce = (req, res) => {
    res.status(200).json(getBruteForceStats());
};

module.exports = { getMetrics, getLogs, getBruteForce };
