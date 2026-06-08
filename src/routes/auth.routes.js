const express = require('express');
const { authenticateUser, authorizeRoles } = require('../middleware/auth.middleware');
const { register, login } = require('../controllers/auth.controller');

const router = express.Router();

router.post('/register', register);

router.post('/login', login);

// ==========================================
// Examples of Role-Based Protected Routes
// ==========================================

// Route accessible by ANY authenticated user
router.get('/profile', authenticateUser, (req, res) => {
    res.json({ message: 'Welcome to your profile', user: req.user });
});

// Route accessible ONLY by 'admin' role
router.get('/admin-dashboard', authenticateUser, authorizeRoles('admin'), (req, res) => {
    res.json({ message: 'Welcome to the Admin Dashboard. Here is the highly sensitive data.' });
});

// Route accessible by 'admin' or 'operator' roles
router.get('/operator-dashboard', authenticateUser, authorizeRoles('admin', 'operator'), (req, res) => {
    res.json({ message: 'Welcome to the Operator Dashboard. You can view alerts here.' });
});

module.exports = router;