const { getSecurityMetrics } = require('../utils/logger');
const db = require('../utils/db');
const { getBruteForceStats } = require('../middleware/bruteForce.middleware');
const { getAlertStats } = require('../services/alert.service');


const getMetrics = async (req, res) => {
    try {
        const metrics = await getSecurityMetrics();
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
    } catch (err) {
        res.status(500).json({ message: 'Error retrieving metrics' });
    }
};


const getLogs = async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);
        const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
        const { event, success, userEmail, ip, startDate, endDate } = req.query;

        let query = 'SELECT * FROM logs WHERE 1=1';
        let countQuery = 'SELECT COUNT(*) FROM logs WHERE 1=1';
        const params = [];
        let paramIndex = 1;

        if (event) {
            query += ` AND event = $${paramIndex}`;
            countQuery += ` AND event = $${paramIndex}`;
            params.push(event.toUpperCase());
            paramIndex++;
        }
        if (success !== undefined) {
            const successBool = success === 'true';
            query += ` AND success = $${paramIndex}`;
            countQuery += ` AND success = $${paramIndex}`;
            params.push(successBool);
            paramIndex++;
        }
        if (userEmail) {
            query += ` AND LOWER(user_email) = LOWER($${paramIndex})`;
            countQuery += ` AND LOWER(user_email) = LOWER($${paramIndex})`;
            params.push(userEmail);
            paramIndex++;
        }
        if (ip) {
            query += ` AND ip = $${paramIndex}`;
            countQuery += ` AND ip = $${paramIndex}`;
            params.push(ip);
            paramIndex++;
        }
        if (startDate && !isNaN(new Date(startDate).getTime())) {
            query += ` AND timestamp >= $${paramIndex}`;
            countQuery += ` AND timestamp >= $${paramIndex}`;
            params.push(new Date(startDate));
            paramIndex++;
        }
        if (endDate && !isNaN(new Date(endDate).getTime())) {
            query += ` AND timestamp <= $${paramIndex}`;
            countQuery += ` AND timestamp <= $${paramIndex}`;
            params.push(new Date(endDate));
            paramIndex++;
        }

        query += ` ORDER BY timestamp DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        
        const countRes = await db.query(countQuery, params);
        const total = parseInt(countRes.rows[0].count, 10);
        const totalPages = Math.ceil(total / limit);
        const offset = (page - 1) * limit;
        
        params.push(limit, offset);
        const logsRes = await db.query(query, params);

        res.status(200).json({
            total,
            page,
            limit,
            totalPages,
            returned: logsRes.rows.length,
            logs: logsRes.rows.map(r => ({
                id: r.id, timestamp: r.timestamp, event: r.event,
                userEmail: r.user_email, success: r.success, ip: r.ip, details: r.details
            })),
        });
    } catch (err) {
        console.error('Error fetching logs:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
};

const getLogById = async (req, res) => {
    try {
        const { id } = req.params;
        const result = await db.query('SELECT * FROM logs WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Log not found' });
        }
        const r = result.rows[0];
        res.status(200).json({
            id: r.id, timestamp: r.timestamp, event: r.event,
            userEmail: r.user_email, success: r.success, ip: r.ip, details: r.details
        });
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
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

const getRiskScores = async (req, res) => {
    try {
        const ipScores = {};
        
        const logsRes = await db.query('SELECT ip, event, success FROM logs');
        logsRes.rows.forEach(log => {
            if (!log.ip || log.ip === 'unknown') return;
            if (!ipScores[log.ip]) ipScores[log.ip] = 0;
            
            if (log.event === 'LOGIN' && !log.success) ipScores[log.ip] += 1;
            if (log.event === 'UNAUTHORIZED_ACCESS') ipScores[log.ip] += 5;
            if (log.event === 'TOKEN_INVALID') ipScores[log.ip] += 5;
            if (log.event === 'ROLE_ESCALATION_ATTEMPT') ipScores[log.ip] += 20;
        });

        const bruteForce = getBruteForceStats();
        bruteForce.entries.forEach(entry => {
            if (!ipScores[entry.ip]) ipScores[entry.ip] = 0;
            if (entry.isLocked) ipScores[entry.ip] += 15;
        });

        const scores = Object.keys(ipScores).map(ip => ({
            ip,
            score: ipScores[ip],
            level: ipScores[ip] > 50 ? 'CRITICAL' : ipScores[ip] > 20 ? 'HIGH' : ipScores[ip] > 5 ? 'MEDIUM' : 'LOW'
        })).sort((a, b) => b.score - a.score);

        res.status(200).json(scores);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

module.exports = { getMetrics, getLogs, getLogById, getBruteForce, getSuspiciousIPs, getRiskScores };
