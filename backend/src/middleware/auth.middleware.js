const jwt = require('jsonwebtoken');
const { logSecurityEvent } = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key';


const authenticateUser = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Authentication failed. Token missing or invalid format.' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        logSecurityEvent({
            eventType: 'TOKEN_INVALID',
            username: 'unknown',
            sourceIp: req.ip || req.connection?.remoteAddress,
            endpoint: req.originalUrl || req.url || '/api',
            result: 'DENIED',
            details: 'Invalid or expired token',
        });
        return res.status(401).json({ message: 'Authentication failed. Invalid or expired token.' });
    }
};

const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !req.user.role) {
            return res.status(403).json({ message: 'Access denied. Role not found.' });
        }

        if (!allowedRoles.includes(req.user.role)) {
            logSecurityEvent({
                eventType: 'UNAUTHORIZED_ACCESS',
                username: req.user.email,
                sourceIp: req.ip || req.connection?.remoteAddress,
                endpoint: req.originalUrl || req.url || '/api',
                result: 'DENIED',
                details: `Role not authorized. Required: ${allowedRoles.join(', ')}`,
            });
            return res.status(403).json({ 
                message: `Access denied. Requires one of the following roles: ${allowedRoles.join(', ')}` 
            });
        }
        next();
    };
};

module.exports = {
    authenticateUser,
    authorizeRoles
};
