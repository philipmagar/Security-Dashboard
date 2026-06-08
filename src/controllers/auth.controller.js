const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { logSecurityEvent } = require('../utils/logger');
const { users } = require('../models/user.model');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key';

const register = async (req, res) => {
    const { email, password, name, role } = req.body;
    if (!email || !password || !role) {
        return res.status(400).json({ message: 'Email, password and role are required' });
    }
    if (users.find(u => u.email === email)) {
        logSecurityEvent('REGISTER', email, false, 'User already exists');
        return res.status(409).json({ message: 'User already exists' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: Date.now().toString(),
            email,
            password: hashedPassword,
            name,
            role // E.g., 'admin', 'operator', 'user'
        };
        users.push(newUser);
        logSecurityEvent('REGISTER', email, true, 'User registered successfully');
        const { password: _, ...userWithoutPassword } = newUser;
        res.status(201).json(userWithoutPassword);
    } catch (error) {
        logSecurityEvent('REGISTER', email, false, error.message);
        res.status(500).json({ message: 'Internal server error' });
    }
};

const login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = users.find(u => u.email === email);
    if (!user) {
        logSecurityEvent('LOGIN', email, false, 'Invalid credentials - User not found');
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    try {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            logSecurityEvent('LOGIN', email, false, 'Invalid credentials - Password mismatch');
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        logSecurityEvent('LOGIN', email, true, 'User logged in successfully');
        res.status(200).json({ token });
    } catch (error) {
        logSecurityEvent('LOGIN', email, false, error.message);
        res.status(500).json({ message: 'Internal server error' });
    }
};

module.exports = {
    register,
    login
};
