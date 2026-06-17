const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001/api';

const getToken = () => localStorage.getItem('siem_token');
const setToken = (t) => localStorage.setItem('siem_token', t);

// Explicit login function for the Login page
export const loginUser = async (email, password) => {
  const res = await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Login failed');
  setToken(data.token);
  return data;
};

// Logout utility
export const logoutUser = () => {
  localStorage.removeItem('siem_token');
  window.location.reload();
};

// Wrapper: attaches token, redirects to login on 401
const authFetch = async (url, options = {}) => {
  const token = getToken();
  
  const headers = { ...options.headers };
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(url, { ...options, headers });

  if (response.status === 401) {
    // Token expired or invalid
    logoutUser();
  }

  return response;
};

// ── Dashboard ─────────────────────────────────────────────────────────────────

export const fetchDashboardSummary = async () => {
  const response = await authFetch(`${API_BASE_URL}/dashboard/summary`);
  if (!response.ok) throw new Error('Failed to fetch summary');
  return response.json();
};

export const fetchRiskScores = async () => {
  const response = await authFetch(`${API_BASE_URL}/security/risk-scores`);
  if (!response.ok) throw new Error('Failed to fetch risk scores');
  return response.json();
};

// ── Security Logs ─────────────────────────────────────────────────────────────

export const fetchLogs = async () => {
  const response = await authFetch(`${API_BASE_URL}/security/logs`);
  if (!response.ok) throw new Error('Failed to fetch logs');
  return response.json();
};

export const fetchSecurityLogs = async ({ event = '', success = '', ip = '', page = 1, limit = 25 } = {}) => {
  const params = new URLSearchParams();
  if (event) params.append('event', event);
  if (success !== '') params.append('success', success);
  if (ip) params.append('ip', ip);
  params.append('page', page);
  params.append('limit', limit);

  const response = await authFetch(`${API_BASE_URL}/security/logs?${params}`);
  if (!response.ok) throw new Error('Failed to fetch security logs');
  return response.json();
};

export const fetchLoginTrend = async (hours = 24) => {
  const response = await authFetch(`${API_BASE_URL}/dashboard/timeline?hours=${hours}`);
  if (!response.ok) throw new Error('Failed to fetch login trend');
  return response.json();
};

// ── Alert Management ──────────────────────────────────────────────────────────

export const fetchAlerts = async ({ severity = '', type = '', acknowledged = '', page = 1, limit = 20 } = {}) => {
  const params = new URLSearchParams();
  if (severity) params.append('severity', severity);
  if (type) params.append('type', type);
  if (acknowledged !== '') params.append('acknowledged', acknowledged);
  params.append('page', page);
  params.append('limit', limit);

  const response = await authFetch(`${API_BASE_URL}/alerts?${params}`);
  if (!response.ok) throw new Error('Failed to fetch alerts');
  return response.json();
};

export const fetchAlertStats = async () => {
  const response = await authFetch(`${API_BASE_URL}/alerts/stats`);
  if (!response.ok) throw new Error('Failed to fetch alert stats');
  return response.json();
};

export const fetchAlertTypes = async () => {
  const response = await authFetch(`${API_BASE_URL}/alerts/types`);
  if (!response.ok) throw new Error('Failed to fetch alert types');
  return response.json();
};

export const createAlert = async (body) => {
  const response = await authFetch(`${API_BASE_URL}/alerts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.message || 'Failed to create alert');
  }
  return response.json();
};

export const acknowledgeAlert = async (id) => {
  const response = await authFetch(`${API_BASE_URL}/alerts/${id}/acknowledge`, {
    method: 'PATCH',
  });
  if (!response.ok) throw new Error('Failed to acknowledge alert');
  return response.json();
};

export const acknowledgeAllAlerts = async (severity = '', type = '') => {
  const response = await authFetch(`${API_BASE_URL}/alerts/acknowledge-all`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...(severity && { severity }), ...(type && { type }) }),
  });
  if (!response.ok) throw new Error('Failed to acknowledge all alerts');
  return response.json();
};

export const deleteAlert = async (id) => {
  const response = await authFetch(`${API_BASE_URL}/alerts/${id}`, {
    method: 'DELETE',
  });
  if (!response.ok) throw new Error('Failed to delete alert');
  return response.json();
};
