const { getSecurityMetrics, securityLogs } = require('../utils/logger');

const getMetrics = (req, res) => {
    const metrics = getSecurityMetrics();
    res.status(200).json(metrics);
};

const getLogs = (req, res) => {
    res.status(200).json(securityLogs);
};

module.exports = { getMetrics, getLogs };
