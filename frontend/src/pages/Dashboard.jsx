import { useEffect, useState } from 'react';
import { fetchDashboardSummary, fetchRiskScores } from '../services/api.service';
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
    return <div className="error">{error}</div>;
  }

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
          <div className="metric-card">
            <h3>Total Events</h3>
            <div className="value">{summary.security.totalEvents.toLocaleString()}</div>
            <div className="subtitle">Security events tracked</div>
          </div>
          <div className="metric-card">
            <h3>Login Success Rate</h3>
            <div className="value success">{summary.security.loginSuccessRate}</div>
            <div className="subtitle">Overall success rate</div>
          </div>
          <div className="metric-card">
            <h3>Active Brute Force Threats</h3>
            <div className="value danger">{summary.bruteForce.currentlyLocked}</div>
            <div className="subtitle">Accounts currently locked</div>
          </div>
          <div className="metric-card">
            <h3>Unacknowledged Alerts</h3>
            <div className="value warning">{summary.alerts.unacknowledged}</div>
            <div className="subtitle">Requires immediate attention</div>
          </div>
        </section>

        <div className="two-col">
          <section className="panel risk-scores">
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

          <section className="panel recent-alerts">
            <h2>Recent Alerts</h2>
            {summary.alerts.recent && summary.alerts.recent.length > 0 ? (
              <div className="alert-list">
                {summary.alerts.recent.map(alert => (
                  <div key={alert.id} className={`alert-item severity-${alert.severity}`}>
                    <div className="alert-header">
                      <span className="alert-type">{alert.type}</span>
                      <span className="alert-time">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div className="alert-message">{alert.message}</div>
                    <div className="alert-source">Source: {alert.source}</div>
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
