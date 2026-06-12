const express = require('express');
const { authenticateUser, authorizeRoles } = require('../middleware/auth.middleware');
const { getMetrics, getLogs, getLogById, getBruteForce, getSuspiciousIPs, getRiskScores } = require('../controllers/security.controller');

const router = express.Router();

router.use(authenticateUser, authorizeRoles('admin', 'operator'));

// Security logs, metrics, and brute-force state — admin + operator only
router.get('/metrics', getMetrics);
router.get('/logs', getLogs);
router.get('/logs/:id', getLogById);
router.get('/suspicious-ips', getSuspiciousIPs);
router.get('/brute-force', getBruteForce);
router.get('/risk-scores', getRiskScores);

module.exports = router;
