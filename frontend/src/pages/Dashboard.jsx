import { useEffect, useState } from 'react';
import { fetchDashboardSummary, fetchRiskScores } from '../services/api.service';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts';
import { ShieldAlert, Activity, Lock, Bell, AlertTriangle } from 'lucide-react';
import './Dashboard.css';

const Dashboard = () => {
  const [summary, setSummary] = useState(null);
  const [riskScores, setRiskScores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const loadData = async () => {
      try {
        const [summaryData, riskData] = await Promise.all([
          fetchDashboardSummary(),
          fetchRiskScores()
        ]);
        setSummary(summaryData);
        setRiskScores(riskData);
      } catch (err) {
        setError('Error loading dashboard data. Make sure backend is running and you have a valid token.');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    loadData();
    const interval = setInterval(loadData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  if (loading && !summary) {
    return <div className="loading">Initializing Security Dashboard...</div>;
  }

  if (error) {
    return <div className="error"><AlertTriangle className="icon" /> {error}</div>;
  }

  // Ensure riskScores is an array and limit to top 10 for the chart
  const chartData = (Array.isArray(riskScores) ? riskScores : []).slice(0, 10);

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h1>Security Operations Center</h1>
        <div className="status-badge pulse">
          <span className="dot"></span>
          System Online
        </div>
      </header>

      <main className="dashboard-main">
        <section className="metrics-grid">
          <div className="card metric-card">
            <div className="metric-header">
              <h3>Total Events</h3>
              <Activity className="metric-icon" size={20} />
            </div>
            <div className="value">{summary?.security?.totalEvents?.toLocaleString() || 0}</div>
            <div className="subtitle">Security events tracked</div>
          </div>
          <div className="card metric-card">
            <div className="metric-header">
              <h3>Login Success Rate</h3>
              <ShieldAlert className="metric-icon success-icon" size={20} />
            </div>
            <div className="value success">{summary?.security?.loginSuccessRate || '0%'}</div>
            <div className="subtitle">Overall success rate</div>
          </div>
          <div className="card metric-card">
            <div className="metric-header">
              <h3>Active Threats</h3>
              <Lock className="metric-icon danger-icon" size={20} />
            </div>
            <div className="value danger">{summary?.bruteForce?.currentlyLocked || 0}</div>
            <div className="subtitle">Accounts currently locked</div>
          </div>
          <div className="card metric-card">
            <div className="metric-header">
              <h3>Unacknowledged</h3>
              <Bell className="metric-icon warning-icon" size={20} />
            </div>
            <div className="value warning">{summary?.alerts?.unacknowledged || 0}</div>
            <div className="subtitle">Alerts require attention</div>
          </div>
        </section>

        <section className="card chart-section">
          <h2>Risk Score Analysis</h2>
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartData} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" vertical={false} />
                  <XAxis dataKey="ip" stroke="#a3a3a3" tick={{fill: '#a3a3a3', fontSize: 12}} />
                  <YAxis stroke="#a3a3a3" tick={{fill: '#a3a3a3', fontSize: 12}} />
                  <Tooltip 
                    cursor={{fill: 'rgba(255,255,255,0.05)'}} 
                    contentStyle={{ backgroundColor: '#141414', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
                  />
                  <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.level === 'CRITICAL' ? '#f85149' : entry.level === 'HIGH' ? '#d29922' : '#3b82f6'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
          ) : (
            <div className="empty-state">No significant risk entities detected.</div>
          )}
        </section>

        <div className="two-col mt-2">
          <section className="card panel risk-scores">
            <h2>High Risk Entities</h2>
            {riskScores.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Risk Level</th>
                    <th>Score</th>
                  </tr>
                </thead>
                <tbody>
                  {riskScores.slice(0, 5).map((score, idx) => (
                    <tr key={idx}>
                      <td>{score.ip}</td>
                      <td>
                        <span className={`badge risk-${score.level.toLowerCase()}`}>
                          {score.level}
                        </span>
                      </td>
                      <td className="score-val">{score.score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state">No significant risk entities detected.</div>
            )}
          </section>

          <section className="card panel recent-alerts">
            <h2>Recent Alerts</h2>
            {summary?.alerts?.recent && summary.alerts.recent.length > 0 ? (
              <div className="alert-list">
                {summary.alerts.recent.map(alert => (
                  <div key={alert.id} className={`alert-item severity-${alert.severity}`}>
                    <div className="alert-header">
                      <span className="alert-type">{alert.type.replace(/_/g, ' ')}</span>
                      <span className="alert-time">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div className="alert-message">{alert.message}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">No recent alerts.</div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
