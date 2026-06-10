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
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const { event, success, userEmail, ip, startDate, endDate } = req.query;

    let logs = [...securityLogs].reverse(); // newest first

    if (event) {
        logs = logs.filter(l => l.event === event.toUpperCase());
    }
    if (success !== undefined) {
        const successBool = success === 'true';
        logs = logs.filter(l => l.success === successBool);
    }
    if (userEmail) {
        logs = logs.filter(l => l.userEmail.toLowerCase() === userEmail.toLowerCase());
    }
    if (ip) {
        logs = logs.filter(l => l.ip === ip);
    }
    if (startDate) {
        const startTime = new Date(startDate).getTime();
        if (!isNaN(startTime)) logs = logs.filter(l => new Date(l.timestamp).getTime() >= startTime);
    }
    if (endDate) {
        const endTime = new Date(endDate).getTime();
        if (!isNaN(endTime)) logs = logs.filter(l => new Date(l.timestamp).getTime() <= endTime);
    }

    const total = logs.length;
    const totalPages = Math.ceil(total / limit);
    const offset = (page - 1) * limit;

    res.status(200).json({
        total,
        page,
        limit,
        totalPages,
        returned: Math.max(0, Math.min(total - offset, limit)),
        logs: logs.slice(offset, offset + limit),
    });
};

const getLogById = (req, res) => {
    const { id } = req.params;
    const log = securityLogs.find(l => l.id === id);
    if (!log) {
        return res.status(404).json({ message: 'Log not found' });
    }
    res.status(200).json(log);
};

const getBruteForce = (req, res) => {
    res.status(200).json(getBruteForceStats());
};

const getSuspiciousIPs = (req, res) => {
    const bruteForce = getBruteForceStats();
    
    // Group brute force entries by IP
    const ipMap = {};
    for (const entry of bruteForce.entries) {
        if (!ipMap[entry.ip]) {
            ipMap[entry.ip] = {
                ip: entry.ip,
                totalAttempts: 0,
                targets: [],
                isLocked: false,
                lockedUntil: null
            };
        }
        ipMap[entry.ip].totalAttempts += entry.attempts;
        ipMap[entry.ip].targets.push({ email: entry.email, attempts: entry.attempts });
        if (entry.isLocked) {
            ipMap[entry.ip].isLocked = true;
            if (!ipMap[entry.ip].lockedUntil || new Date(entry.lockedUntil) > new Date(ipMap[entry.ip].lockedUntil)) {
                ipMap[entry.ip].lockedUntil = entry.lockedUntil;
            }
        }
    }
    
    const topThreats = Object.values(ipMap)
        .filter(ipData => ipData.totalAttempts > 0)
        .sort((a, b) => b.totalAttempts - a.totalAttempts);

    res.status(200).json({
        totalSuspiciousIPs: topThreats.length,
        topThreats
    });
};

module.exports = { getMetrics, getLogs, getLogById, getBruteForce, getSuspiciousIPs };
