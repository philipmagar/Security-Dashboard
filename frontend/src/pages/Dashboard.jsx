import { useEffect, useState } from 'react';
import { fetchDashboardSummary, fetchRiskScores } from '../services/api.service';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts';
import { ShieldAlert, Activity, Lock, Bell, AlertTriangle } from 'lucide-react';

const SEVERITY_BORDER = {
  critical: 'border-l-red-500',
  high: 'border-l-amber-500',
  medium: 'border-l-blue-500',
  low: 'border-l-green-500',
};

const RISK_BADGE = {
  CRITICAL: 'bg-red-100 text-red-700',
  HIGH: 'bg-amber-100 text-amber-700',
  MEDIUM: 'bg-blue-100 text-blue-700',
  LOW: 'bg-green-100 text-green-700',
};

const MetricCard = ({ title, value, subtitle, icon: Icon, valueClass = 'text-slate-900' }) => (
  <div className="bg-white border border-slate-200 rounded-lg p-6 shadow-sm">
    <div className="flex justify-between items-center mb-3">
      <h3 className="m-0 text-xs font-semibold text-slate-500 uppercase tracking-wider">{title}</h3>
      <Icon size={18} className="text-slate-400" />
    </div>
    <div className={`text-3xl font-bold mb-1 ${valueClass}`}>{value}</div>
    <div className="text-sm text-slate-500">{subtitle}</div>
  </div>
);

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
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500">
        Initializing Security Dashboard...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 bg-red-50 text-red-700 border border-red-200 rounded-lg p-4">
        <AlertTriangle size={18} /> {error}
      </div>
    );
  }

  const chartData = (Array.isArray(riskScores) ? riskScores : []).slice(0, 10);

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <header className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-slate-900 m-0">Security Operations Center</h1>
        <div className="flex items-center gap-2 bg-green-50 text-green-700 text-sm font-medium px-3 py-1.5 rounded-full border border-green-200">
          <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
          System Online
        </div>
      </header>

      {/* Metric Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
        <MetricCard
          title="Total Events"
          value={summary?.security?.totalEvents?.toLocaleString() || 0}
          subtitle="Security events tracked"
          icon={Activity}
        />
        <MetricCard
          title="Login Success Rate"
          value={summary?.security?.loginSuccessRate || '0%'}
          subtitle="Overall success rate"
          icon={ShieldAlert}
          valueClass="text-green-600"
        />
        <MetricCard
          title="Active Threats"
          value={summary?.bruteForce?.currentlyLocked || 0}
          subtitle="Accounts currently locked"
          icon={Lock}
          valueClass="text-red-600"
        />
        <MetricCard
          title="Unacknowledged"
          value={summary?.alerts?.unacknowledged || 0}
          subtitle="Alerts require attention"
          icon={Bell}
          valueClass="text-amber-600"
        />
      </section>

      {/* Chart */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 shadow-sm">
        <h2 className="text-base font-semibold text-slate-900 mb-4 m-0">Risk Score Analysis</h2>
        {chartData.length > 0 ? (
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={chartData} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
              <XAxis dataKey="ip" stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} />
              <YAxis stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} />
              <Tooltip
                cursor={{ fill: 'rgba(0,0,0,0.04)' }}
                contentStyle={{ backgroundColor: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}
              />
              <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                {chartData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.level === 'CRITICAL' ? '#ef4444' : entry.level === 'HIGH' ? '#f59e0b' : '#3b82f6'}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-40 text-slate-400 text-sm">
            No significant risk entities detected.
          </div>
        )}
      </section>

      {/* Two Column Bottom */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* High Risk Entities */}
        <section className="bg-white border border-slate-200 rounded-lg p-6 shadow-sm">
          <h2 className="text-base font-semibold text-slate-900 mb-4 m-0">High Risk Entities</h2>
          {riskScores.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b-2 border-slate-100">
                  <th className="text-left py-2 px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">IP Address</th>
                  <th className="text-left py-2 px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">Risk Level</th>
                  <th className="text-left py-2 px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">Score</th>
                </tr>
              </thead>
              <tbody>
                {riskScores.slice(0, 5).map((score, idx) => (
                  <tr key={idx} className="border-b border-slate-50 hover:bg-slate-50 transition-colors">
                    <td className="py-3 px-3 font-mono text-slate-700">{score.ip}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-semibold ${RISK_BADGE[score.level] || 'bg-slate-100 text-slate-700'}`}>
                        {score.level}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-semibold text-slate-900">{score.score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="flex items-center justify-center h-32 text-slate-400 text-sm">
              No significant risk entities detected.
            </div>
          )}
        </section>

        {/* Recent Alerts */}
        <section className="bg-white border border-slate-200 rounded-lg p-6 shadow-sm">
          <h2 className="text-base font-semibold text-slate-900 mb-4 m-0">Recent Alerts</h2>
          {summary?.alerts?.recent && summary.alerts.recent.length > 0 ? (
            <div className="flex flex-col gap-2">
              {summary.alerts.recent.map(alert => (
                <div
                  key={alert.id}
                  className={`bg-slate-50 border-l-4 rounded-r-md p-3 ${SEVERITY_BORDER[alert.severity] || 'border-l-slate-300'}`}
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-sm font-semibold text-slate-800 capitalize">
                      {alert.type.replace(/_/g, ' ')}
                    </span>
                    <span className="text-xs text-slate-400">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div className="text-sm text-slate-600">{alert.message}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-32 text-slate-400 text-sm">
              No recent alerts.
            </div>
          )}
        </section>
      </div>
    </div>
  );
};

export default Dashboard;
