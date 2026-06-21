const { createAlert } = require('../services/alert.service');
const db = require('./db');

/**
 * Logs a security event to PostgreSQL and auto-generates an alert for suspicious patterns.
 */
const logSecurityEvent = async (event, userEmail, success, details, ip = 'unknown') => {
    try {
        await db.query(
            'INSERT INTO logs (event, user_email, success, ip, details) VALUES ($1, $2, $3, $4, $5)',
            [event, userEmail, success, ip, details]
        );

        console.log(
            `[SECURITY LOG] Event: ${event} | User: ${userEmail} | ` +
            `Success: ${success} | IP: ${ip} | Details: ${details}`
        );

        // ── Auto-alert rules ────────────────────────────────────────────────────
        
        // Multiple failed logins: trigger alert after 3+ failures from same email
        if (event === 'LOGIN' && !success) {
            const res = await db.query(
                `SELECT COUNT(*) FROM logs 
                 WHERE event = 'LOGIN' AND success = false 
                 AND user_email = $1 
                 AND timestamp > NOW() - INTERVAL '10 minutes'`,
                [userEmail]
            );
            const recentFailures = parseInt(res.rows[0].count, 10);
            
            if (recentFailures === 3) {
                createAlert({
                    type: 'MULTIPLE_FAILED_LOGINS',
                    severity: 'high',
                    source: ip,
                    message: `3 consecutive failed login attempts for ${userEmail}`,
                    details: { userEmail, recentFailures, ip },
                });
            }
        }

        // Unauthorized access attempt (403 equivalent events)
        if (event === 'UNAUTHORIZED_ACCESS') {
            const res = await db.query(
                `SELECT COUNT(*) FROM logs 
                 WHERE event = 'UNAUTHORIZED_ACCESS' 
                 AND ip = $1 
                 AND timestamp > NOW() - INTERVAL '5 minutes'`,
                [ip]
            );
            const recentAccessDenied = parseInt(res.rows[0].count, 10);

            if (recentAccessDenied === 5) {
                createAlert({
                    type: 'ACCESS_DENIED_SPIKE',
                    severity: 'high',
                    source: ip,
                    message: `Spike in unauthorized access attempts from IP ${ip}`,
                    details: { ip, recentAccessDenied },
                });
            }

            createAlert({
                type: 'UNAUTHORIZED_ACCESS',
                severity: 'medium',
                source: ip,
                message: `Unauthorized access attempt by ${userEmail}`,
                details: { userEmail, details, ip },
            });
        }

        // Token-related failures
        if (event === 'TOKEN_INVALID') {
            const res = await db.query(
                `SELECT COUNT(*) FROM logs 
                 WHERE event = 'TOKEN_INVALID' 
                 AND ip = $1 
                 AND timestamp > NOW() - INTERVAL '5 minutes'`,
                [ip]
            );
            const recentInvalidTokens = parseInt(res.rows[0].count, 10);

            if (recentInvalidTokens === 5) {
                createAlert({
                    type: 'INVALID_TOKEN_SPIKE',
                    severity: 'high',
                    source: ip,
                    message: `Spike in invalid token attempts from IP ${ip}`,
                    details: { ip, recentInvalidTokens },
                });
            }

            createAlert({
                type: 'TOKEN_INVALID',
                severity: 'low',
                source: ip,
                message: `Invalid or expired token used by ${userEmail}`,
                details: { userEmail, ip },
            });
        }

        // Role escalation attempt
        if (event === 'ROLE_ESCALATION_ATTEMPT') {
            createAlert({
                type: 'ROLE_ESCALATION_ATTEMPT',
                severity: 'critical',
                source: ip,
                message: `Role escalation attempt detected for ${userEmail}`,
                details: { userEmail, details, ip },
            });
        }
    } catch (err) {
        console.error('Error logging security event:', err);
    }
};

/**
 * Returns aggregate metrics from the PostgreSQL security log.
 */
const getSecurityMetrics = async () => {
    try {
        const totalEventsRes = await db.query('SELECT COUNT(*) FROM logs');
        const failedLoginsRes = await db.query("SELECT COUNT(*) FROM logs WHERE event = 'LOGIN' AND success = false");
        const successfulLoginsRes = await db.query("SELECT COUNT(*) FROM logs WHERE event = 'LOGIN' AND success = true");
        const registrationsRes = await db.query("SELECT COUNT(*) FROM logs WHERE event = 'REGISTER'");
        const unauthorizedRes = await db.query("SELECT COUNT(*) FROM logs WHERE event = 'UNAUTHORIZED_ACCESS'");
        const last24hRes = await db.query("SELECT COUNT(*) FROM logs WHERE timestamp > NOW() - INTERVAL '24 hours'");
        
        const recentLogsRes = await db.query('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10');

        return {
            totalEvents: parseInt(totalEventsRes.rows[0].count, 10),
            failedLogins: parseInt(failedLoginsRes.rows[0].count, 10),
            successfulLogins: parseInt(successfulLoginsRes.rows[0].count, 10),
            registrations: parseInt(registrationsRes.rows[0].count, 10),
            unauthorizedAttempts: parseInt(unauthorizedRes.rows[0].count, 10),
            eventsLast24h: parseInt(last24hRes.rows[0].count, 10),
            recentLogs: recentLogsRes.rows,
        };
    } catch (err) {
        console.error('Error getting security metrics:', err);
        return {
            totalEvents: 0, failedLogins: 0, successfulLogins: 0, 
            registrations: 0, unauthorizedAttempts: 0, eventsLast24h: 0, recentLogs: []
        };
    }
};

module.exports = { logSecurityEvent, getSecurityMetrics };
