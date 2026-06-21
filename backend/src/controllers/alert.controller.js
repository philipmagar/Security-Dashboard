const {
    createAlert,
    getAlerts,
    getAlertById,
    acknowledgeAlert,
    acknowledgeAllAlerts,
    deleteAlert,
    getAlertStats,
    ALERT_TYPES,
} = require('../services/alert.service');


const listAlerts = async (req, res) => {
    try {
        const { severity, type, acknowledged, limit = 50, page = 1 } = req.query;

        const parsedLimit = Math.min(parseInt(limit, 10) || 50, 200); // cap at 200
        const parsedPage = Math.max(parseInt(page, 10) || 1, 1);

        const result = await getAlerts({ severity, type, acknowledged, limit: parsedLimit, page: parsedPage });
        res.status(200).json(result);
    } catch (err) {
        res.status(500).json({ message: 'Error retrieving alerts' });
    }
};

const getStats = async (req, res) => {
    try {
        const stats = await getAlertStats();
        res.status(200).json(stats);
    } catch (err) {
        res.status(500).json({ message: 'Error retrieving alert stats' });
    }
};

const getTypes = (req, res) => {
    res.status(200).json({ types: ALERT_TYPES });
};

const getAlert = async (req, res) => {
    try {
        const alert = await getAlertById(req.params.id);
        if (!alert) {
            return res.status(404).json({ message: 'Alert not found' });
        }
        res.status(200).json(alert);
    } catch (err) {
        res.status(500).json({ message: 'Error retrieving alert' });
    }
};


const createManualAlert = async (req, res) => {
    try {
        const { type, severity, source, message, details } = req.body;

        if (!type || !severity || !source || !message) {
            return res.status(400).json({
                message: 'Fields required: type, severity, source, message',
            });
        }

        const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
        if (!validSeverities.includes(severity)) {
            return res.status(400).json({
                message: `Invalid severity. Must be one of: ${validSeverities.join(', ')}`,
            });
        }

        const alert = await createAlert({ type, severity, source, message, details: details || {} });
        res.status(201).json(alert);
    } catch (err) {
        res.status(500).json({ message: 'Error creating alert' });
    }
};

const ackAlert = async (req, res) => {
    try {
        const alert = await acknowledgeAlert(req.params.id);
        if (!alert) {
            return res.status(404).json({ message: 'Alert not found' });
        }
        res.status(200).json({ message: 'Alert acknowledged', alert });
    } catch (err) {
        res.status(500).json({ message: 'Error acknowledging alert' });
    }
};

const ackAllAlerts = async (req, res) => {
    try {
        const { severity, type } = req.body || {};
        const result = await acknowledgeAllAlerts({ severity, type });
        res.status(200).json({ message: `${result.acknowledged} alert(s) acknowledged`, ...result });
    } catch (err) {
        res.status(500).json({ message: 'Error acknowledging alerts' });
    }
};

const removeAlert = async (req, res) => {
    try {
        const removed = await deleteAlert(req.params.id);
        if (!removed) {
            return res.status(404).json({ message: 'Alert not found' });
        }
        res.status(200).json({ message: 'Alert deleted', alert: removed });
    } catch (err) {
        res.status(500).json({ message: 'Error deleting alert' });
    }
};

module.exports = {
    listAlerts,
    getStats,
    getTypes,
    getAlert,
    createManualAlert,
    ackAlert,
    ackAllAlerts,
    removeAlert,
};
