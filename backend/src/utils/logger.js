const { alerts } = require('../models/alert.model');
const { createAlert } = require('../services/alert.service');

const securityLogs = [];

/**
 * Logs a security event and auto-generates an alert for suspicious patterns.
 * @param {string} event      - Event name (LOGIN, REGISTER, BRUTE_FORCE_DETECTED, etc.)
 * @param {string} userEmail  - Target user email or identifier
 * @param {boolean} success   - Whether the event was successful
 * @param {string} details    - Human-readable detail string
 * @param {string} [ip]       - Source IP address (optional)
 */
const logSecurityEvent = (event, userEmail, success, details, ip = 'unknown') => {
    const timestamp = new Date().toISOString();
    const id = `log_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const logEntry = { id, timestamp, event, userEmail, success, details, ip };
    securityLogs.push(logEntry);

    // Prevent memory leaks by limiting the array size
    if (securityLogs.length > 10000) {
        securityLogs.splice(0, securityLogs.length - 10000);
    }

    console.log(
        `[SECURITY LOG] ${timestamp} | Event: ${event} | User: ${userEmail} | ` +
        `Success: ${success} | IP: ${ip} | Details: ${details}`
    );

    // ── Auto-alert rules ────────────────────────────────────────────────────

    // Multiple failed logins: trigger alert after 3+ failures from same email
    if (event === 'LOGIN' && !success) {
        const recentWindow = Date.now() - 10 * 60 * 1000; // last 10 minutes
        const recentFailures = securityLogs.filter(
            l => l.event === 'LOGIN' &&
                 !l.success &&
                 l.userEmail === userEmail &&
                 new Date(l.timestamp).getTime() > recentWindow
        ).length;

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
        const recentWindow = Date.now() - 5 * 60 * 1000; // last 5 minutes
        const recentAccessDenied = securityLogs.filter(
            l => l.event === 'UNAUTHORIZED_ACCESS' &&
                 l.ip === ip &&
                 new Date(l.timestamp).getTime() > recentWindow
        ).length;

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
        const recentWindow = Date.now() - 5 * 60 * 1000; // last 5 minutes
        const recentInvalidTokens = securityLogs.filter(
            l => l.event === 'TOKEN_INVALID' &&
                 l.ip === ip &&
                 new Date(l.timestamp).getTime() > recentWindow
        ).length;

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
};

/**
 * Returns aggregate metrics from the security log.
 */
const getSecurityMetrics = () => {
    const totalEvents = securityLogs.length;
    const failedLogins = securityLogs.filter(l => l.event === 'LOGIN' && !l.success).length;
    const successfulLogins = securityLogs.filter(l => l.event === 'LOGIN' && l.success).length;
    const registrations = securityLogs.filter(l => l.event === 'REGISTER').length;
    const unauthorizedAttempts = securityLogs.filter(l => l.event === 'UNAUTHORIZED_ACCESS').length;

    const last24h = Date.now() - 24 * 60 * 60 * 1000;
    const eventsLast24h = securityLogs.filter(
        l => new Date(l.timestamp).getTime() > last24h
    ).length;

    return {
        totalEvents,
        failedLogins,
        successfulLogins,
        registrations,
        unauthorizedAttempts,
        eventsLast24h,
        recentLogs: securityLogs.slice(-10).reverse(), // Last 10 events, newest first
    };
};

module.exports = { logSecurityEvent, getSecurityMetrics, securityLogs };
