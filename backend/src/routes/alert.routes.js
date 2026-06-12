const express = require('express');
const { authenticateUser, authorizeRoles } = require('../middleware/auth.middleware');
const { alertLimiter } = require('../middleware/rateLimiter.middleware');
const {
    listAlerts,
    getStats,
    getTypes,
    getAlert,
    createManualAlert,
    ackAlert,
    ackAllAlerts,
    removeAlert,
} = require('../controllers/alert.controller');

const router = express.Router();
router.use(authenticateUser);

router.get('/', alertLimiter, authorizeRoles('admin', 'operator'), listAlerts);
router.get('/stats', alertLimiter, authorizeRoles('admin', 'operator'), getStats);
router.get('/types', alertLimiter, authorizeRoles('admin', 'operator'), getTypes);
router.get('/:id', alertLimiter, authorizeRoles('admin', 'operator'), getAlert);

router.post('/',authorizeRoles('admin', 'operator'), createManualAlert);


router.patch('/acknowledge-all',authorizeRoles('admin', 'operator'), ackAllAlerts);
router.patch('/:id/acknowledge',authorizeRoles('admin', 'operator'), ackAlert);

router.delete('/:id',authorizeRoles('admin'),removeAlert);

module.exports = router;
