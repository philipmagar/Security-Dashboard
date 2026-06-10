const { alerts } = require("../models/alert.model");

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const ALERT_TYPES = [
  "BRUTE_FORCE_DETECTED",
  "LOGIN_RATE_LIMIT",
  "RATE_LIMIT_EXCEEDED",
  "UNAUTHORIZED_ACCESS",
  "SUSPICIOUS_ACTIVITY",
  "MULTIPLE_FAILED_LOGINS",
  "TOKEN_INVALID",
  "ROLE_ESCALATION_ATTEMPT",
];

const createAlert = ({
  type,
  severity = "medium",
  source,
  message,
  details = {},
}) => {
  const alert = {
    id: `alert_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    type,
    severity,
    source,
    message,
    details,
    acknowledged: false,
    timestamp: new Date().toISOString(),
  };

  alerts.push(alert);

  if (alerts.length > 1000) {
    alerts.splice(0, alerts.length - 1000);
  }

  console.log(
    `[ALERT] [${severity.toUpperCase()}] ${type} | ${source} | ${message}`,
  );

  return alert;
};



const getAlerts = ({
  severity,
  type,
  acknowledged,
  limit = 50,
  page = 1,
} = {}) => {
  let filtered = [...alerts];

  if (severity) {
    filtered = filtered.filter((a) => a.severity === severity);
  }
  if (type) {
    filtered = filtered.filter((a) => a.type === type);
  }
  if (acknowledged !== undefined) {
    const ack = acknowledged === "true" || acknowledged === true;
    filtered = filtered.filter((a) => a.acknowledged === ack);
  }

  // Sort newest first, then by severity descending
  filtered.sort((a, b) => {
    const timeDiff = new Date(b.timestamp) - new Date(a.timestamp);
    if (timeDiff !== 0) return timeDiff;
    return (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
  });

  const total = filtered.length;
  const totalPages = Math.ceil(total / limit);
  const offset = (page - 1) * limit;
  const data = filtered.slice(offset, offset + limit);

  return { data, total, page: Number(page), limit: Number(limit), totalPages };
};

const getAlertById = (id) => alerts.find((a) => a.id === id) || null;
const acknowledgeAlert = (id) => {
  const alert = alerts.find((a) => a.id === id);
  if (!alert) return null;
  alert.acknowledged = true;
  alert.acknowledgedAt = new Date().toISOString();
  return alert;
};

const acknowledgeAllAlerts = ({ severity, type } = {}) => {
  let targets = alerts.filter((a) => !a.acknowledged);
  if (severity) targets = targets.filter((a) => a.severity === severity);
  if (type) targets = targets.filter((a) => a.type === type);

  const now = new Date().toISOString();
  targets.forEach((a) => {
    a.acknowledged = true;
    a.acknowledgedAt = now;
  });

  return { acknowledged: targets.length };
};

const deleteAlert = (id) => {
  const idx = alerts.findIndex((a) => a.id === id);
  if (idx === -1) return null;
  const [removed] = alerts.splice(idx, 1);
  return removed;
};

const getAlertStats = () => {
  const total = alerts.length;
  const unacknowledged = alerts.filter((a) => !a.acknowledged).length;
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byType = {};
  const last24h = Date.now() - 24 * 60 * 60 * 1000;
  let recent24h = 0;

  alerts.forEach((a) => {
    if (bySeverity[a.severity] !== undefined) bySeverity[a.severity]++;
    byType[a.type] = (byType[a.type] || 0) + 1;
    if (new Date(a.timestamp).getTime() > last24h) recent24h++;
  });

  return {
    total,
    unacknowledged,
    acknowledged: total - unacknowledged,
    recent24h,
    bySeverity,
    byType,
  };
};

module.exports = {
  createAlert,
  getAlerts,
  getAlertById,
  acknowledgeAlert,
  acknowledgeAllAlerts,
  deleteAlert,
  getAlertStats,
  ALERT_TYPES,
};
