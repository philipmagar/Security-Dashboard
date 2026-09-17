const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { logSecurityEvent } = require('../utils/logger');
const { getUserByEmail, createUser } = require('../models/user.model');
const { recordFailedAttempt, clearFailedAttempts } = require('../middleware/bruteForce.middleware');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key';
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS || '10', 10);

const validatePassword = (password) => {
    if (!password || password.length < 8) return 'Password must be at least 8 characters long';
    if (!/[A-Z]/.test(password)) return 'Password must contain an uppercase letter';
    if (!/[a-z]/.test(password)) return 'Password must contain a lowercase letter';
    if (!/\d/.test(password)) return 'Password must contain a number';
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return 'Password must contain a special character';
    return null;
};

const register = async (req, res) => {
    let { email, password, name, role } = req.body;
    const ip = req.ip || req.connection.remoteAddress;

    if (!email || !password || !role) {
        return res.status(400).json({ message: 'Email, password and role are required' });
    }

    // Sanitize inputs
    email = email.trim().toLowerCase();
    name = name ? name.trim() : '';

    const passwordError = validatePassword(password);
    if (passwordError) {
        return res.status(400).json({ message: passwordError });
    }

    const validRoles = ['admin', 'operator', 'user'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({
            message: `Invalid role. Must be one of: ${validRoles.join(', ')}`,
        });
    }

    const existingUser = await getUserByEmail(email);
    if (existingUser) {
        logSecurityEvent({
            eventType: 'REGISTER',
            username: email,
            sourceIp: ip,
            endpoint: '/api/auth/register',
            result: 'FAILURE',
            details: 'User already exists',
        });
        return res.status(409).json({ message: 'User already exists' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const newUser = {
            id: Date.now().toString(),
            email,
            password: hashedPassword,
            name: name || '',
            role,
        };
        await createUser(newUser);
        logSecurityEvent({
            eventType: 'REGISTER',
            username: email,
            sourceIp: ip,
            endpoint: '/api/auth/register',
            result: 'SUCCESS',
            details: 'User registered successfully',
        });

        const { password: _, ...userWithoutPassword } = newUser;
        res.status(201).json(userWithoutPassword);
    } catch (error) {
        logSecurityEvent({
            eventType: 'REGISTER',
            username: email,
            sourceIp: ip,
            endpoint: '/api/auth/register',
            result: 'ERROR',
            details: error.message,
        });
        res.status(500).json({ message: 'Internal server error' });
    }
};


const login = async (req, res) => {
    let { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    // Sanitize input
    email = email.trim().toLowerCase();

    const user = await getUserByEmail(email);
    if (!user) {
        recordFailedAttempt(req);
        logSecurityEvent({
            eventType: 'LOGIN',
            username: email,
            sourceIp: ip,
            endpoint: '/api/auth/login',
            result: 'FAILURE',
            details: 'Invalid credentials - User not found',
        });
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    try {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            const attempts = recordFailedAttempt(req);
            logSecurityEvent({
                eventType: 'LOGIN',
                username: email,
                sourceIp: ip,
                endpoint: '/api/auth/login',
                result: 'FAILURE',
                details: `Invalid credentials - Password mismatch (attempt #${attempts})`,
            });
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        clearFailedAttempts(req); 

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        logSecurityEvent({
            eventType: 'LOGIN',
            username: email,
            sourceIp: ip,
            endpoint: '/api/auth/login',
            result: 'SUCCESS',
            details: 'User logged in successfully',
        });
        res.status(200).json({
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
            },
        });
    } catch (error) {
        logSecurityEvent({
            eventType: 'LOGIN',
            username: email,
            sourceIp: ip,
            endpoint: '/api/auth/login',
            result: 'ERROR',
            details: error.message,
        });
        res.status(500).json({ message: 'Internal server error' });
    }
};

module.exports = { register, login };
