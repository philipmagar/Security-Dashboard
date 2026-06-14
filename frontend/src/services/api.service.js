const API_BASE_URL = 'http://localhost:5001/api'; 
const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzgxMjY1NzQzfQ.Mswvt2OU7KR0fAVGBA5aZbVmMPiNel1anL-9iNOqUbQ'; 

export const fetchDashboardSummary = async () => {
  const response = await fetch(`${API_BASE_URL}/dashboard/summary`, {
    headers: {
      Authorization: `Bearer ${TOKEN}`,
    },
  });
  if (!response.ok) throw new Error('Failed to fetch summary');
  return response.json();
};

export const fetchRiskScores = async () => {
  const response = await fetch(`${API_BASE_URL}/security/risk-scores`, {
    headers: {
      Authorization: `Bearer ${TOKEN}`,
    },
  });
  if (!response.ok) throw new Error('Failed to fetch risk scores');
  return response.json();
};

export const fetchLogs = async () => {
  const response = await fetch(`${API_BASE_URL}/security/logs`, {
    headers: {
      Authorization: `Bearer ${TOKEN}`,
    },
  });
  if (!response.ok) throw new Error('Failed to fetch logs');
  return response.json();
};
