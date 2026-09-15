import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchDashboardSummary, fetchRiskScores } from '../services/api.service';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell,
} from 'recharts';
import {
  Activity, ShieldCheck, Lock, Bell, AlertTriangle, ShieldAlert, RefreshCw,
} from 'lucide-react';

const SEV_COLORS = {
  critical: { bg: 'bg-red-50', border: 'border-red-400', text: 'text-red-700', badge: 'bg-red-100 text-red-700' },
  high:     { bg: 'bg-amber-50', border: 'border-amber-400', text: 'text-amber-700', badge: 'bg-amber-100 text-amber-700' },
  medium:   { bg: 'bg-blue-50', border: 'border-blue-400', text: 'text-blue-700', badge: 'bg-blue-100 text-blue-700' },
  low:      { bg: 'bg-green-50', border: 'border-green-400', text: 'text-green-700', badge: 'bg-green-100 text-green-700' },
};

const RISK_BAR_COLOR = { CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#3b82f6', LOW: '#10b981' };

const StatCard = ({ title, value, sub, icon: Icon, color }) => (
  <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm">
    <div className="flex items-center justify-between mb-3">
      <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">{title}</span>
      <div className={`p-2 rounded-md ${color.iconBg}`}>
        <Icon size={16} className={color.iconText} />
      </div>
    </div>
    <div className={`text-3xl font-bold tracking-tight ${color.value}`}>{value}</div>
    {sub && <div className="text-xs text-slate-400 mt-1">{sub}</div>}
  </div>
);

const Dashboard = () => {
  const [summary, setSummary]       = useState(null);
  const [riskScores, setRiskScores] = useState([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState('');
  const [lastUpdated, setLastUpdated] = useState(null);
  const navigate = useNavigate();

  const load = async () => {
    try {
      const [s, r] = await Promise.all([fetchDashboardSummary(), fetchRiskScores()]);
      setSummary(s);
      setRiskScores(Array.isArray(r) ? r : []);
      setError('');
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message || 'Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3 text-slate-500">
        <div className="w-8 h-8 border-2 border-slate-200 border-t-blue-600 rounded-full animate-spin" />
        <p className="text-sm">Loading dashboard...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-3 bg-red-50 border border-red-200 text-red-700 rounded-lg p-4 text-sm">
        <AlertTriangle size={18} className="shrink-0" />
        <span>{error}</span>
        <button
          onClick={() => { setLoading(true); load(); }}
          className="ml-auto text-xs font-semibold underline hover:no-underline"
        >
          Retry
        </button>
      </div>
    );
  }

  const chartData = riskScores.slice(0, 10);

  return (
    <div className="flex flex-col gap-6">

      {/* ── Header ── */}
      <header className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 m-0">Security Dashboard</h1>
          <p className="text-slate-500 text-sm mt-0.5 mb-0">
            Real-time threat monitoring
            {lastUpdated && (
              <span className="ml-2 text-slate-400">
                · Updated {lastUpdated.toLocaleTimeString()}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 bg-emerald-50 text-emerald-700 text-xs font-medium px-3 py-1.5 rounded-full border border-emerald-200">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
            Live
          </div>
          <button
            onClick={() => { setLoading(true); load(); }}
            className="flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 border border-slate-200 rounded-md px-3 py-1.5 bg-white hover:bg-slate-50 transition-colors"
          >
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>
      </header>

      {/* ── Stat Cards ── */}
      <section className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          title="Total Events"
          value={(summary?.security?.totalEvents ?? 0).toLocaleString()}
          sub="Security events logged"
          icon={Activity}
          color={{ iconBg: 'bg-blue-100', iconText: 'text-blue-600', value: 'text-blue-700' }}
        />
        <StatCard
          title="Login Success"
          value={summary?.security?.loginSuccessRate ?? '–'}
          sub="Auth success rate"
          icon={ShieldCheck}
          color={{ iconBg: 'bg-emerald-100', iconText: 'text-emerald-600', value: 'text-emerald-700' }}
        />
        <StatCard
          title="Locked Accounts"
          value={summary?.bruteForce?.currentlyLocked ?? 0}
          sub="Currently blocked IPs"
          icon={Lock}
          color={{ iconBg: 'bg-red-100', iconText: 'text-red-600', value: 'text-red-700' }}
        />
        <StatCard
          title="Open Alerts"
          value={summary?.alerts?.unacknowledged ?? 0}
          sub="Pending review"
          icon={Bell}
          color={{ iconBg: 'bg-amber-100', iconText: 'text-amber-600', value: 'text-amber-700' }}
        />
      </section>

      {/* ── Risk Chart + Critical IPs ── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">

        {/* Chart */}
        <section className="xl:col-span-2 bg-white border border-slate-200 rounded-lg p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-800 mb-4 flex items-center gap-2">
            <Activity size={15} className="text-blue-600" /> IP Risk Scores
          </h2>
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis dataKey="ip" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={{ stroke: '#e2e8f0' }} tickLine={false} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={{ stroke: '#e2e8f0' }} tickLine={false} />
                <Tooltip
                  cursor={{ fill: '#f8fafc' }}
                  contentStyle={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '6px', fontSize: '12px' }}
                />
                <Bar dataKey="score" radius={[4, 4, 0, 0]} maxBarSize={40}>
                  {chartData.map((entry, i) => (
                    <Cell key={i} fill={RISK_BAR_COLOR[entry.level] || '#94a3b8'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[260px] text-slate-400 text-sm">
              No risk data available yet.
            </div>
          )}
        </section>

        {/* Top Risk IPs */}
        <section className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm flex flex-col">
          <h2 className="text-sm font-semibold text-slate-800 mb-4 flex items-center gap-2">
            <ShieldAlert size={15} className="text-red-600" /> Top Risk IPs
          </h2>
          {riskScores.length > 0 ? (
            <div className="flex flex-col gap-2">
              {riskScores.slice(0, 6).map((s, i) => (
                <div key={i} className="flex items-center justify-between p-2.5 rounded-md bg-slate-50 border border-slate-100">
                  <span className="font-mono text-xs text-slate-700">{s.ip}</span>
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${SEV_COLORS[s.level?.toLowerCase()]?.badge || 'bg-slate-100 text-slate-600'}`}>
                      {s.level}
                    </span>
                    <span className="text-xs font-bold text-slate-700">{s.score}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-1 items-center justify-center text-slate-400 text-sm">
              No high-risk IPs detected.
            </div>
          )}
        </section>
      </div>

      {/* ── Alert Severity Summary ── */}
      {summary?.alerts?.bySeverity && (
        <section className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-800 mb-4 flex items-center gap-2">
            <Bell size={15} className="text-amber-600" /> Alerts by Severity
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
              const count = summary.alerts.bySeverity[sev] ?? 0;
              const c = SEV_COLORS[sev] || { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-600' };
              return (
                <div key={sev} className={`rounded-lg p-4 border-l-4 ${c.bg} ${c.border} text-center`}>
                  <div className={`text-2xl font-bold ${c.text}`}>{count}</div>
                  <div className="text-xs text-slate-500 font-medium capitalize mt-0.5">{sev}</div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* ── Recent Alerts ── */}
      <section className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-800 flex items-center gap-2">
            <Bell size={15} className="text-amber-600" /> Recent Alerts
          </h2>
          <button
            onClick={() => navigate('/alerts')}
            className="text-xs font-semibold text-blue-600 hover:text-blue-700"
          >
            View all →
          </button>
        </div>
        {summary?.alerts?.recent?.length > 0 ? (
          <div className="flex flex-col gap-2">
            {summary.alerts.recent.map(alert => {
              const c = SEV_COLORS[alert.severity] || { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-700' };
              return (
                <div
                  key={alert.id}
                  className={`flex items-start gap-3 p-3 rounded-md border-l-4 ${c.bg} ${c.border}`}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2 mb-0.5">
                      <span className={`text-xs font-bold capitalize ${c.text}`}>
                        {alert.type?.replace(/_/g, ' ')}
                      </span>
                      <span className="text-[11px] text-slate-400 shrink-0 font-mono">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 m-0 leading-relaxed">{alert.message}</p>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="flex items-center justify-center h-20 text-slate-400 text-sm">
            No recent alerts.
          </div>
        )}
      </section>

    </div>
  );
};

export default Dashboard;
