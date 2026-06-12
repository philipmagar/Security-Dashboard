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


const listAlerts = (req, res) => {
    const { severity, type, acknowledged, limit = 50, page = 1 } = req.query;

    const parsedLimit = Math.min(parseInt(limit, 10) || 50, 200); // cap at 200
    const parsedPage = Math.max(parseInt(page, 10) || 1, 1);

    const result = getAlerts({ severity, type, acknowledged, limit: parsedLimit, page: parsedPage });
    res.status(200).json(result);
};


const getStats = (req, res) => {
    res.status(200).json(getAlertStats());
};

const getTypes = (req, res) => {
    res.status(200).json({ types: ALERT_TYPES });
};

const getAlert = (req, res) => {
    const alert = getAlertById(req.params.id);
    if (!alert) {
        return res.status(404).json({ message: 'Alert not found' });
    }
    res.status(200).json(alert);
};


const createManualAlert = (req, res) => {
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

    const alert = createAlert({ type, severity, source, message, details: details || {} });
    res.status(201).json(alert);
};


const ackAlert = (req, res) => {
    const alert = acknowledgeAlert(req.params.id);
    if (!alert) {
        return res.status(404).json({ message: 'Alert not found' });
    }
    res.status(200).json({ message: 'Alert acknowledged', alert });
};

const ackAllAlerts = (req, res) => {
    const { severity, type } = req.body || {};
    const result = acknowledgeAllAlerts({ severity, type });
    res.status(200).json({ message: `${result.acknowledged} alert(s) acknowledged`, ...result });
};


const removeAlert = (req, res) => {
    const removed = deleteAlert(req.params.id);
    if (!removed) {
        return res.status(404).json({ message: 'Alert not found' });
    }
    res.status(200).json({ message: 'Alert deleted', alert: removed });
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
