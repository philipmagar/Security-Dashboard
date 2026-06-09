const express = require('express');
const { authenticateUser, authorizeRoles } = require('../middleware/auth.middleware');
const { getMetrics, getLogs, getBruteForce } = require('../controllers/security.controller');

const router = express.Router();

// Security logs, metrics, and brute-force state — admin + operator only
router.get('/metrics',     authenticateUser, authorizeRoles('admin', 'operator'), getMetrics);
router.get('/logs',        authenticateUser, authorizeRoles('admin', 'operator'), getLogs);
router.get('/brute-force', authenticateUser, authorizeRoles('admin', 'operator'), getBruteForce);

module.exports = router;
