const express = require('express');
const { authenticateUser, authorizeRoles } = require('../middleware/auth.middleware');
const { getAllUsers } = require('../controllers/admin.controller');

const router = express.Router();

// Admin only route
router.get('/users', authenticateUser, authorizeRoles('admin'), getAllUsers);

module.exports = router;
