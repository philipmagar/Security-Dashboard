const express = require('express');
const { authenticateUser, authorizeRoles } = require('../middleware/auth.middleware');
const { getMetrics, getLogs } = require('../controllers/security.controller');

const router = express.Router();

// Security logs and metrics only accessible to admin and operator
router.get('/metrics', authenticateUser, authorizeRoles('admin', 'operator'), getMetrics);
router.get('/logs', authenticateUser, authorizeRoles('admin', 'operator'), getLogs);

module.exports = router;
