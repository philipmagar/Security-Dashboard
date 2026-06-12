const rateLimit = require('express-rate-limit');
const { createAlert } = require('../services/alert.service');


const rateLimitHandler = (req, res, _next, options) => {
    const ip = req.ip || req.connection.remoteAddress;
    const path = req.originalUrl;

    createAlert({
        type: 'RATE_LIMIT_EXCEEDED',
        severity: 'medium',
        source: ip,
        message: `Rate limit exceeded on ${path}`,
        details: {
            ip,
            path,
            method: req.method,
            limit: options.max,
            windowMs: options.windowMs,
        },
    });

    res.status(429).json({
        status: 'error',
        message: 'Too many requests. Please slow down.',
        retryAfter: Math.ceil(options.windowMs / 1000),
    });
};


const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    handler: rateLimitHandler,
    message: 'Too many requests from this IP, please try again later.',
});


const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // only count failed/non-2xx responses
    handler: (req, res, next, options) => {
        const ip = req.ip || req.connection.remoteAddress;

        createAlert({
            type: 'LOGIN_RATE_LIMIT',
            severity: 'high',
            source: ip,
            message: `Login rate limit exceeded from IP ${ip}`,
            details: {
                ip,
                email: req.body?.email || 'unknown',
                limit: options.max,
                windowMs: options.windowMs,
            },
        });

        res.status(429).json({
            status: 'error',
            message: 'Too many login attempts. Account temporarily locked for 15 minutes.',
            retryAfter: Math.ceil(options.windowMs / 1000),
        });
    },
});


const alertLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    handler: rateLimitHandler,
});

module.exports = { globalLimiter, loginLimiter, alertLimiter };
