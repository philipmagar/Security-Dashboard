const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001/api'; 
const getToken = () => localStorage.getItem('token') || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzgxMjY1NzQzfQ.Mswvt2OU7KR0fAVGBA5aZbVmMPiNel1anL-9iNOqUbQ'; 

export const fetchDashboardSummary = async () => {
  const response = await fetch(`${API_BASE_URL}/dashboard/summary`, {
    headers: {
      Authorization: `Bearer ${getToken()}`,
    },
  });
  if (!response.ok) throw new Error('Failed to fetch summary');
  return response.json();
};

export const fetchRiskScores = async () => {
  const response = await fetch(`${API_BASE_URL}/security/risk-scores`, {
    headers: {
      Authorization: `Bearer ${getToken()}`,
    },
  });
  if (!response.ok) throw new Error('Failed to fetch risk scores');
  return response.json();
};

export const fetchLogs = async () => {
  const response = await fetch(`${API_BASE_URL}/security/logs`, {
    headers: {
      Authorization: `Bearer ${getToken()}`,
    },
  });
  if (!response.ok) throw new Error('Failed to fetch logs');
  return response.json();
};

// ── Alert Management ─────────────────────────────────────────────────────────

export const fetchAlerts = async ({ severity = '', type = '', acknowledged = '', page = 1, limit = 20 } = {}) => {
  const params = new URLSearchParams();
  if (severity) params.append('severity', severity);
  if (type) params.append('type', type);
  if (acknowledged !== '') params.append('acknowledged', acknowledged);
  params.append('page', page);
  params.append('limit', limit);

  const response = await fetch(`${API_BASE_URL}/alerts?${params}`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!response.ok) throw new Error('Failed to fetch alerts');
  return response.json();
};

export const fetchAlertStats = async () => {
  const response = await fetch(`${API_BASE_URL}/alerts/stats`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!response.ok) throw new Error('Failed to fetch alert stats');
  return response.json();
};

export const fetchAlertTypes = async () => {
  const response = await fetch(`${API_BASE_URL}/alerts/types`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!response.ok) throw new Error('Failed to fetch alert types');
  return response.json();
};

export const createAlert = async (body) => {
  const response = await fetch(`${API_BASE_URL}/alerts`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${getToken()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.message || 'Failed to create alert');
  }
  return response.json();
};

export const acknowledgeAlert = async (id) => {
  const response = await fetch(`${API_BASE_URL}/alerts/${id}/acknowledge`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!response.ok) throw new Error('Failed to acknowledge alert');
  return response.json();
};

export const acknowledgeAllAlerts = async (severity = '', type = '') => {
  const response = await fetch(`${API_BASE_URL}/alerts/acknowledge-all`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${getToken()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ ...(severity && { severity }), ...(type && { type }) }),
  });
  if (!response.ok) throw new Error('Failed to acknowledge all alerts');
  return response.json();
};

export const deleteAlert = async (id) => {
  const response = await fetch(`${API_BASE_URL}/alerts/${id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!response.ok) throw new Error('Failed to delete alert');
  return response.json();
};
