const db = require('../utils/db');

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const ALERT_TYPES = [
  "BRUTE_FORCE_DETECTED",
  "LOGIN_RATE_LIMIT",
  "RATE_LIMIT_EXCEEDED",
  "UNAUTHORIZED_ACCESS",
  "ACCESS_DENIED_SPIKE",
  "SUSPICIOUS_ACTIVITY",
  "MULTIPLE_FAILED_LOGINS",
  "TOKEN_INVALID",
  "INVALID_TOKEN_SPIKE",
  "ROLE_ESCALATION_ATTEMPT",
];

const createAlert = async ({
  type,
  severity = "medium",
  source,
  message,
  details = {},
}) => {
  const id = `alert_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const timestamp = new Date().toISOString();

  await db.query(
    'INSERT INTO alerts (id, timestamp, type, severity, source, message, details, acknowledged) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
    [id, timestamp, type, severity, source, message, JSON.stringify(details), false]
  );

  console.log(`[ALERT] [${severity.toUpperCase()}] ${type} | ${source} | ${message}`);
  
  return { id, timestamp, type, severity, source, message, details, acknowledged: false };
};

const getAlerts = async ({
  severity,
  type,
  acknowledged,
  limit = 50,
  page = 1,
} = {}) => {
  let query = 'SELECT * FROM alerts WHERE 1=1';
  let countQuery = 'SELECT COUNT(*) FROM alerts WHERE 1=1';
  const params = [];
  let paramIndex = 1;

  if (severity) {
    query += ` AND severity = $${paramIndex}`;
    countQuery += ` AND severity = $${paramIndex}`;
    params.push(severity);
    paramIndex++;
  }
  if (type) {
    query += ` AND type = $${paramIndex}`;
    countQuery += ` AND type = $${paramIndex}`;
    params.push(type);
    paramIndex++;
  }
  if (acknowledged !== undefined) {
    const ack = acknowledged === "true" || acknowledged === true;
    query += ` AND acknowledged = $${paramIndex}`;
    countQuery += ` AND acknowledged = $${paramIndex}`;
    params.push(ack);
    paramIndex++;
  }

  // Sort newest first
  query += ` ORDER BY timestamp DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
  
  const countRes = await db.query(countQuery, params);
  const total = parseInt(countRes.rows[0].count, 10);
  const totalPages = Math.ceil(total / limit);
  const offset = (page - 1) * limit;

  params.push(limit, offset);
  const dataRes = await db.query(query, params);

  const data = dataRes.rows.map(r => ({
    ...r,
    details: typeof r.details === 'string' ? JSON.parse(r.details) : r.details
  }));

  return { data, total, page: Number(page), limit: Number(limit), totalPages };
};

const getAlertById = async (id) => {
  const res = await db.query('SELECT * FROM alerts WHERE id = $1', [id]);
  if (res.rows.length === 0) return null;
  const a = res.rows[0];
  return { ...a, details: typeof a.details === 'string' ? JSON.parse(a.details) : a.details };
};

const acknowledgeAlert = async (id) => {
  const res = await db.query(
    'UPDATE alerts SET acknowledged = true WHERE id = $1 RETURNING *',
    [id]
  );
  if (res.rows.length === 0) return null;
  const a = res.rows[0];
  return { ...a, details: typeof a.details === 'string' ? JSON.parse(a.details) : a.details };
};

const acknowledgeAllAlerts = async ({ severity, type } = {}) => {
  let query = 'UPDATE alerts SET acknowledged = true WHERE acknowledged = false';
  const params = [];
  let paramIndex = 1;

  if (severity) {
    query += ` AND severity = $${paramIndex}`;
    params.push(severity);
    paramIndex++;
  }
  if (type) {
    query += ` AND type = $${paramIndex}`;
    params.push(type);
    paramIndex++;
  }

  const res = await db.query(query, params);
  return { acknowledged: res.rowCount };
};

const deleteAlert = async (id) => {
  const res = await db.query('DELETE FROM alerts WHERE id = $1 RETURNING *', [id]);
  if (res.rows.length === 0) return null;
  const a = res.rows[0];
  return { ...a, details: typeof a.details === 'string' ? JSON.parse(a.details) : a.details };
};

const getAlertStats = async () => {
  const totalRes = await db.query('SELECT COUNT(*) FROM alerts');
  const unackRes = await db.query('SELECT COUNT(*) FROM alerts WHERE acknowledged = false');
  const last24hRes = await db.query("SELECT COUNT(*) FROM alerts WHERE timestamp > NOW() - INTERVAL '24 hours'");
  
  const sevRes = await db.query('SELECT severity, COUNT(*) FROM alerts GROUP BY severity');
  const typeRes = await db.query('SELECT type, COUNT(*) FROM alerts GROUP BY type');

  const total = parseInt(totalRes.rows[0].count, 10);
  const unacknowledged = parseInt(unackRes.rows[0].count, 10);
  const recent24h = parseInt(last24hRes.rows[0].count, 10);

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  sevRes.rows.forEach(r => { bySeverity[r.severity] = parseInt(r.count, 10); });

  const byType = {};
  typeRes.rows.forEach(r => { byType[r.type] = parseInt(r.count, 10); });

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
