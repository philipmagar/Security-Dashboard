const securityLogs = [];

const logSecurityEvent = (event, userEmail, success, details) => {
    const timestamp = new Date().toISOString();
    const logEntry = { timestamp, event, userEmail, success, details };
    securityLogs.push(logEntry);
    console.log(`[SECURITY LOG] ${timestamp} | Event: ${event} | User: ${userEmail} | Success: ${success} | Details: ${details}`);
};

const getSecurityMetrics = () => {
    const totalEvents = securityLogs.length;
    const failedLogins = securityLogs.filter(log => log.event === 'LOGIN' && !log.success).length;
    const successfulLogins = securityLogs.filter(log => log.event === 'LOGIN' && log.success).length;
    
    return {
        totalEvents,
        failedLogins,
        successfulLogins,
        recentLogs: securityLogs.slice(-10).reverse() // Return last 10 events
    };
};

module.exports = { logSecurityEvent, getSecurityMetrics, securityLogs };
