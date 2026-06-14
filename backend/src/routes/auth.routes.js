const express = require('express');
const { authenticateUser, authorizeRoles } = require('../middleware/auth.middleware');
const { loginLimiter } = require('../middleware/rateLimiter.middleware');
const { bruteForceCheck } = require('../middleware/bruteForce.middleware');
const { register, login } = require('../controllers/auth.controller');

const router = express.Router();

router.post('/register', register);

router.post('/login', loginLimiter, bruteForceCheck, login);

router.get('/profile', authenticateUser, (req, res) => {
    res.json({ message: 'Welcome to your profile', user: req.user });
});

router.get('/admin-dashboard', authenticateUser, authorizeRoles('admin'), (req, res) => {
    res.json({ message: 'Welcome to the Admin Dashboard.' });
});

router.get('/operator-dashboard', authenticateUser, authorizeRoles('admin', 'operator'), (req, res) => {
    res.json({ message: 'Welcome to the Operator Dashboard.' });
});

module.exports = router;