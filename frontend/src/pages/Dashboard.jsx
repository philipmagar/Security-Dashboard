import { useEffect, useState } from 'react';
import { fetchDashboardSummary, fetchRiskScores } from '../services/api.service';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts';
import { ShieldAlert, Activity, Lock, Bell, AlertTriangle, ShieldCheck } from 'lucide-react';

const SEVERITY_BORDER = {
  critical: 'border-l-4 border-l-red-500 bg-red-500/10 text-red-200',
  high: 'border-l-4 border-l-amber-500 bg-amber-500/10 text-amber-200',
  medium: 'border-l-4 border-l-blue-500 bg-blue-500/10 text-blue-200',
  low: 'border-l-4 border-l-emerald-500 bg-emerald-500/10 text-emerald-200',
};

const RISK_BADGE = {
  CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500/30',
  HIGH: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
  MEDIUM: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
  LOW: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
};

const MetricCard = ({ title, value, subtitle, icon: Icon, valueClass = 'text-white' }) => (
  <div className="relative overflow-hidden bg-slate-900/50 backdrop-blur-xl border border-white/10 rounded-2xl p-6 shadow-2xl transition-all duration-300 hover:scale-[1.02] hover:border-white/20 group">
    <div className="absolute -right-6 -top-6 opacity-5 group-hover:opacity-10 transition-opacity duration-500">
      <Icon size={120} />
    </div>
    <div className="flex justify-between items-center mb-4 relative z-10">
      <h3 className="m-0 text-sm font-medium text-slate-400 uppercase tracking-wider">{title}</h3>
      <div className="p-2 bg-white/5 rounded-lg border border-white/5">
        <Icon size={20} className="text-slate-300" />
      </div>
    </div>
    <div className={`text-4xl font-bold mb-2 tracking-tight relative z-10 ${valueClass}`}>{value}</div>
    <div className="text-sm text-slate-500 relative z-10">{subtitle}</div>
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
      <div className="flex flex-col items-center justify-center h-[70vh] text-slate-400">
        <div className="w-12 h-12 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mb-4"></div>
        <p className="animate-pulse">Initializing Security Protocol...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-3 bg-red-950/50 backdrop-blur-md text-red-400 border border-red-500/30 rounded-xl p-5 shadow-2xl">
        <AlertTriangle size={24} className="animate-bounce" /> {error}
      </div>
    );
  }

  const chartData = (Array.isArray(riskScores) ? riskScores : []).slice(0, 10);

  return (
    <div className="flex flex-col gap-8 text-slate-200">
      {/* Header */}
      <header className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400 m-0">
            Security Operations Center
          </h1>
          <p className="text-slate-400 text-sm mt-1">Real-time threat monitoring and intelligence</p>
        </div>
        <div className="flex items-center gap-2 bg-emerald-950/30 text-emerald-400 text-sm font-medium px-4 py-2 rounded-full border border-emerald-500/30 backdrop-blur-sm shadow-lg shadow-emerald-900/20">
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
          </span>
          System Online
        </div>
      </header>

      {/* Metric Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-6">
        <MetricCard
          title="Total Events"
          value={summary?.security?.totalEvents?.toLocaleString() || 0}
          subtitle="Security events analyzed"
          icon={Activity}
          valueClass="text-blue-400"
        />
        <MetricCard
          title="Success Rate"
          value={summary?.security?.loginSuccessRate || '0%'}
          subtitle="Authentication pass rate"
          icon={ShieldCheck}
          valueClass="text-emerald-400"
        />
        <MetricCard
          title="Active Threats"
          value={summary?.bruteForce?.currentlyLocked || 0}
          subtitle="Accounts currently locked"
          icon={Lock}
          valueClass="text-red-400"
        />
        <MetricCard
          title="Unacknowledged"
          value={summary?.alerts?.unacknowledged || 0}
          subtitle="Alerts pending review"
          icon={Bell}
          valueClass="text-amber-400"
        />
      </section>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        
        {/* Chart Section */}
        <section className="xl:col-span-2 bg-slate-900/50 backdrop-blur-xl border border-white/10 rounded-2xl p-6 shadow-2xl">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold text-white m-0 flex items-center gap-2">
              <Activity size={20} className="text-blue-400" /> Risk Score Analysis
            </h2>
          </div>
          {chartData.length > 0 ? (
            <div className="h-[300px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 10, right: 20, left: -20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} opacity={0.5} />
                  <XAxis dataKey="ip" stroke="#64748b" tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis stroke="#64748b" tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                    contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', backdropFilter: 'blur(8px)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#fff' }}
                    itemStyle={{ color: '#e2e8f0' }}
                  />
                  <Bar dataKey="score" radius={[6, 6, 0, 0]} maxBarSize={50}>
                    {chartData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={entry.level === 'CRITICAL' ? '#ef4444' : entry.level === 'HIGH' ? '#f59e0b' : '#3b82f6'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="flex items-center justify-center h-[300px] text-slate-500 text-sm">
              No significant risk entities detected.
            </div>
          )}
        </section>

        {/* High Risk Entities */}
        <section className="bg-slate-900/50 backdrop-blur-xl border border-white/10 rounded-2xl p-6 shadow-2xl flex flex-col">
          <h2 className="text-lg font-semibold text-white mb-6 m-0 flex items-center gap-2">
            <ShieldAlert size={20} className="text-red-400" /> Critical Entities
          </h2>
          <div className="flex-1 overflow-auto">
            {riskScores.length > 0 ? (
              <div className="flex flex-col gap-3">
                {riskScores.slice(0, 5).map((score, idx) => (
                  <div key={idx} className="flex items-center justify-between p-4 rounded-xl bg-white/5 border border-white/5 hover:bg-white/10 transition-colors">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-full bg-slate-800">
                        <Lock size={16} className="text-slate-400" />
                      </div>
                      <span className="font-mono text-slate-300 text-sm">{score.ip}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold tracking-wider ${RISK_BADGE[score.level] || 'bg-slate-800 text-slate-400'}`}>
                        {score.level}
                      </span>
                      <span className="font-bold text-white min-w-[3ch] text-right">{score.score}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-500 text-sm">
                System clear. No high-risk entities.
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Recent Alerts Full Width */}
      <section className="bg-slate-900/50 backdrop-blur-xl border border-white/10 rounded-2xl p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-white m-0 flex items-center gap-2">
            <Bell size={20} className="text-amber-400" /> Recent Alerts
          </h2>
          <button className="text-sm text-blue-400 hover:text-blue-300 transition-colors">View All</button>
        </div>
        
        {summary?.alerts?.recent && summary.alerts.recent.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {summary.alerts.recent.map(alert => (
              <div
                key={alert.id}
                className={`relative overflow-hidden rounded-xl p-4 border border-white/5 ${SEVERITY_BORDER[alert.severity] || 'bg-slate-800 border-l-4 border-l-slate-500'} transition-transform hover:-translate-y-1`}
              >
                <div className="flex justify-between items-start mb-2">
                  <span className="text-sm font-bold text-white capitalize tracking-wide">
                    {alert.type.replace(/_/g, ' ')}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="text-sm opacity-90">{alert.message}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center justify-center h-32 text-slate-500 text-sm">
            No recent alerts in the queue.
          </div>
        )}
      </section>
    </div>
  );
};

export default Dashboard;
