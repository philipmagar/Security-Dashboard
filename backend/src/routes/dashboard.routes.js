const express = require('express');
const { authenticateUser, authorizeRoles } = require('../middleware/auth.middleware');
const { getSummary, getTimeline, getThreatLevel } = require('../controllers/dashboard.controller');

const router = express.Router();

router.use(authenticateUser, authorizeRoles('admin', 'operator'));


router.get('/summary', getSummary);


router.get('/timeline', getTimeline);


router.get('/threat-level', getThreatLevel);

module.exports = router;
