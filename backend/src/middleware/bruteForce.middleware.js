const { logSecurityEvent } = require('../utils/logger');
const { createAlert } = require('../services/alert.service');


const bruteForceStore = new Map();

const MAX_ATTEMPTS = 5;               
const WINDOW_MS = 15 * 60 * 1000;    
const LOCK_DURATION_MS = 30 * 60 * 1000; 


const cleanup = () => {
    const now = Date.now();
    for (const [key, record] of bruteForceStore.entries()) {
        if (record.lockedUntil && now > record.lockedUntil + LOCK_DURATION_MS) {
            bruteForceStore.delete(key);
        } else if (!record.lockedUntil && now - record.firstAttempt > WINDOW_MS) {
            bruteForceStore.delete(key);
        }
    }
};
setInterval(cleanup, 5 * 60 * 1000); 


const getKey = (req) => {
    const ip = req.ip || req.connection.remoteAddress;
    const email = (req.body?.email || '').toLowerCase().trim();
    return `${ip}::${email}`;
};


const bruteForceCheck = (req, res, next) => {
    const key = getKey(req);
    const ip = req.ip || req.connection.remoteAddress;
    const email = req.body?.email || 'unknown';
    const now = Date.now();
    const record = bruteForceStore.get(key);

    if (record?.lockedUntil) {
        if (now < record.lockedUntil) {
            const remaining = Math.ceil((record.lockedUntil - now) / 1000);

            logSecurityEvent('BRUTE_FORCE_BLOCKED', email, false,
                `Account blocked — ${record.attempts} failed attempts from IP ${ip}`);

            return res.status(423).json({
                status: 'error',
                message: 'Account temporarily locked due to multiple failed login attempts.',
                retryAfter: remaining,
                lockedUntil: new Date(record.lockedUntil).toISOString(),
            });
        } else {
            
            bruteForceStore.delete(key);
        }
    }

    next();
};


const recordFailedAttempt = (req) => {
    const key = getKey(req);
    const ip = req.ip || req.connection.remoteAddress;
    const email = req.body?.email || 'unknown';
    const now = Date.now();

    let record = bruteForceStore.get(key);

    if (!record || (now - record.firstAttempt > WINDOW_MS && !record.lockedUntil)) {
        
        record = { attempts: 0, firstAttempt: now, lockedUntil: null };
    }

    record.attempts += 1;
    bruteForceStore.set(key, record);

    if (record.attempts >= MAX_ATTEMPTS) {
        record.lockedUntil = now + LOCK_DURATION_MS;
        bruteForceStore.set(key, record);

        logSecurityEvent('BRUTE_FORCE_DETECTED', email, false,
            `Brute force detected: ${record.attempts} failed attempts from IP ${ip}. Account locked for 30 minutes.`);

        createAlert({
            type: 'BRUTE_FORCE_DETECTED',
            severity: 'critical',
            source: ip,
            message: `Brute force attack detected for account: ${email}`,
            details: {
                ip,
                email,
                attempts: record.attempts,
                lockDurationMinutes: LOCK_DURATION_MS / 60000,
                lockedUntil: new Date(record.lockedUntil).toISOString(),
            },
        });
    }

    return record.attempts;
};


const clearFailedAttempts = (req) => {
    const key = getKey(req);
    bruteForceStore.delete(key);
};


const getBruteForceStats = () => {
    const now = Date.now();
    const entries = [];
    for (const [key, record] of bruteForceStore.entries()) {
        const [ip, email] = key.split('::');
        entries.push({
            ip,
            email,
            attempts: record.attempts,
            isLocked: record.lockedUntil ? now < record.lockedUntil : false,
            lockedUntil: record.lockedUntil ? new Date(record.lockedUntil).toISOString() : null,
        });
    }
    return {
        totalTrackedIPs: bruteForceStore.size,
        currentlyLocked: entries.filter(e => e.isLocked).length,
        entries,
    };
};

module.exports = {
    bruteForceCheck,
    recordFailedAttempt,
    clearFailedAttempts,
    getBruteForceStats,
};
