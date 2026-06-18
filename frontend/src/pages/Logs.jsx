import { useState, useEffect, useCallback } from 'react';
import { fetchSecurityLogs, fetchLoginTrend } from '../services/api.service';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts';
import {
  Search, RefreshCw, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight,
  ShieldOff, CheckCircle2, XCircle, Clock, Activity, TrendingDown, Filter
} from 'lucide-react';

const EVENT_TYPES = ['LOGIN', 'LOGOUT', 'REGISTER', 'UNAUTHORIZED_ACCESS', 'TOKEN_INVALID', 'ROLE_ESCALATION_ATTEMPT'];

const BADGE_CLASSES = {
  success: 'bg-green-100 text-green-800',
  danger: 'bg-red-100 text-red-800',
  info: 'bg-blue-100 text-blue-800',
  critical: 'bg-orange-100 text-orange-800',
  warning: 'bg-yellow-100 text-yellow-800',
  neutral: 'bg-slate-100 text-slate-700',
};

const EventBadge = ({ event, success }) => {
  let type = 'neutral';
  if (event === 'LOGIN' && success) type = 'success';
  else if (event === 'LOGIN' && !success) type = 'danger';
  else if (event === 'REGISTER') type = 'info';
  else if (event === 'UNAUTHORIZED_ACCESS' || event === 'ROLE_ESCALATION_ATTEMPT') type = 'critical';
  else if (event === 'TOKEN_INVALID') type = 'warning';

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${BADGE_CLASSES[type]}`}>
      {event?.replace(/_/g, ' ')}
    </span>
  );
};

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white border border-slate-200 rounded-lg shadow-md p-3 text-sm">
      <p className="font-semibold text-slate-700 mb-1">{label}</p>
      {payload.map(p => (
        <p key={p.dataKey} style={{ color: p.color }} className="m-0">
          {p.name}: <strong>{p.value}</strong>
        </p>
      ))}
    </div>
  );
};

const Logs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [filters, setFilters] = useState({ event: '', success: '', ip: '' });
  const [ipInput, setIpInput] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [trendData, setTrendData] = useState([]);
  const [trendHours, setTrendHours] = useState(24);
  const [trendLoading, setTrendLoading] = useState(true);

  const loadLogs = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    setError('');
    try {
      const res = await fetchSecurityLogs({ ...filters, page, limit: 25 });
      setLogs(res.logs || []);
      setTotalPages(res.totalPages || 1);
      setTotal(res.total || 0);
    } catch (err) {
      setError('Failed to load logs. Make sure the backend is running.');
      console.error(err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [filters, page]);

  const loadTrend = useCallback(async () => {
    setTrendLoading(true);
    try {
      const res = await fetchLoginTrend(trendHours);
      const buckets = (res.buckets || []).map(b => ({
        time: new Date(b.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        failed: b.failed,
        success: b.success,
        total: b.total,
      }));
      setTrendData(buckets);
    } catch (err) {
      console.error('Trend fetch failed', err);
    } finally {
      setTrendLoading(false);
    }
  }, [trendHours]);

  useEffect(() => { (async () => { await loadLogs(); })(); }, [loadLogs]);
  useEffect(() => { (async () => { await loadTrend(); })(); }, [loadTrend]);
  useEffect(() => {
    const t = setInterval(() => { loadLogs(true); loadTrend(); }, 30000);
    return () => clearInterval(t);
  }, [loadLogs, loadTrend]);

  const handleFilterChange = (name, value) => {
    setFilters(f => ({ ...f, [name]: value }));
    setPage(1);
  };

  const applyIpFilter = () => handleFilterChange('ip', ipInput.trim());
  const clearFilters = () => { setFilters({ event: '', success: '', ip: '' }); setIpInput(''); setPage(1); };

  const totalFailed = trendData.reduce((a, b) => a + b.failed, 0);
  const totalSuccess = trendData.reduce((a, b) => a + b.success, 0);
  const hasFilters = filters.event || filters.success !== '' || filters.ip;

  const selectBase = "px-3 py-2 border border-slate-300 rounded-md text-sm bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-500";
  const btnBase = "flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-md border transition-colors cursor-pointer";

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <header className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 m-0">Security Logs</h1>
          <p className="text-sm text-slate-500 mt-1 mb-0">Real-time event stream and failed login analysis</p>
        </div>
        <button
          className={`${btnBase} bg-white border-slate-300 text-slate-700 hover:bg-slate-50`}
          onClick={() => { loadLogs(true); loadTrend(); }}
        >
          <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
          {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      </header>

      {/* Trend Chart */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 shadow-sm">
        <div className="flex justify-between items-center mb-4">
          <div className="flex items-center gap-2">
            <TrendingDown size={16} className="text-slate-500" />
            <h2 className="text-base font-semibold text-slate-900 m-0">Failed Login Trend</h2>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5 text-sm">
              <XCircle size={13} className="text-red-500" />
              <span className="font-semibold text-red-600">{totalFailed}</span>
              <span className="text-slate-500">Failed</span>
            </div>
            <div className="flex items-center gap-1.5 text-sm">
              <CheckCircle2 size={13} className="text-green-500" />
              <span className="font-semibold text-green-600">{totalSuccess}</span>
              <span className="text-slate-500">Success</span>
            </div>
            <select className={`${selectBase} py-1`} value={trendHours} onChange={e => setTrendHours(Number(e.target.value))}>
              <option value={6}>Last 6h</option>
              <option value={24}>Last 24h</option>
              <option value={48}>Last 48h</option>
              <option value={168}>Last 7d</option>
            </select>
          </div>
        </div>
        {trendLoading ? (
          <div className="flex items-center justify-center h-40 gap-2 text-slate-400 text-sm">
            <Activity size={20} className="animate-spin" /> Loading chart…
          </div>
        ) : trendData.every(d => d.total === 0) ? (
          <div className="flex items-center justify-center h-40 gap-2 text-slate-400 text-sm">
            <ShieldOff size={20} /> No login events in this window
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="failedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="successGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.15} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
              <XAxis dataKey="time" tick={{ fill: '#94a3b8', fontSize: 11 }} stroke="transparent" interval="preserveStartEnd" />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} stroke="transparent" allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="failed" name="Failed" stroke="#ef4444" strokeWidth={2} fill="url(#failedGrad)" dot={false} />
              <Area type="monotone" dataKey="success" name="Success" stroke="#10b981" strokeWidth={2} fill="url(#successGrad)" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </section>

      {/* Filters Bar */}
      <div className="flex justify-between items-center bg-white border border-slate-200 rounded-lg px-4 py-3 shadow-sm gap-3 flex-wrap">
        <div className="flex items-center gap-3 flex-wrap">
          <Filter size={14} className="text-slate-400" />
          <select className={selectBase} value={filters.event} onChange={e => handleFilterChange('event', e.target.value)}>
            <option value="">All Events</option>
            {EVENT_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
          <select className={selectBase} value={filters.success} onChange={e => handleFilterChange('success', e.target.value)}>
            <option value="">All Outcomes</option>
            <option value="true">Success</option>
            <option value="false">Failed</option>
          </select>
          <div className="relative flex items-center">
            <Search size={13} className="absolute left-3 text-slate-400 pointer-events-none" />
            <input
              className={`${selectBase} pl-8 w-44`}
              type="text"
              placeholder="Filter by IP…"
              value={ipInput}
              onChange={e => setIpInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && applyIpFilter()}
            />
            {ipInput && (
              <button className="absolute right-2 text-slate-400 hover:text-slate-700" onClick={() => { setIpInput(''); handleFilterChange('ip', ''); }}>✕</button>
            )}
          </div>
          <button className={`${btnBase} bg-blue-600 text-white border-blue-600 hover:bg-blue-700`} onClick={applyIpFilter}>Apply</button>
          {hasFilters && (
            <button className={`${btnBase} bg-white border-slate-300 text-slate-600 hover:bg-slate-50`} onClick={clearFilters}>✕ Clear</button>
          )}
        </div>
        <div className="flex items-center gap-1.5 text-sm text-slate-500">
          <Clock size={13} />
          {total.toLocaleString()} event{total !== 1 ? 's' : ''}
        </div>
      </div>

      {/* Table */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 h-40 text-slate-400 text-sm">
            <span className="w-4 h-4 border-2 border-slate-300 border-t-blue-500 rounded-full animate-spin" />
            Loading logs…
          </div>
        ) : error ? (
          <div className="flex items-center gap-2 m-4 p-3 bg-red-50 text-red-700 rounded-md text-sm">
            <XCircle size={15} /> {error}
          </div>
        ) : logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 h-40 text-slate-400">
            <ShieldOff size={36} />
            <p className="text-sm m-0">No logs match the current filters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50">
                <tr>
                  {['Timestamp', 'Event Type', 'User / Email', 'IP Address', 'Status', 'Details'].map(h => (
                    <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-slate-500 uppercase tracking-wider border-b-2 border-slate-100">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr
                    key={log.id}
                    className={`border-b border-slate-50 hover:bg-slate-50 transition-colors ${!log.success && log.event === 'LOGIN' ? 'bg-red-50/40' : ''}`}
                  >
                    <td className="py-3 px-4">
                      <span className="block text-xs text-slate-400">{new Date(log.timestamp).toLocaleDateString()}</span>
                      <span className="font-mono text-slate-700">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    </td>
                    <td className="py-3 px-4"><EventBadge event={log.event} success={log.success} /></td>
                    <td className="py-3 px-4 text-slate-700">{log.userEmail || log.userId || <span className="text-slate-300">—</span>}</td>
                    <td className="py-3 px-4">
                      <span className="font-mono text-xs bg-slate-100 text-slate-700 px-2 py-0.5 rounded">{log.ip || log.ipAddress || '—'}</span>
                    </td>
                    <td className="py-3 px-4">
                      {log.success
                        ? <span className="flex items-center gap-1 text-green-600 text-xs font-semibold"><CheckCircle2 size={12} /> OK</span>
                        : <span className="flex items-center gap-1 text-red-600 text-xs font-semibold"><XCircle size={12} /> Fail</span>
                      }
                    </td>
                    <td className="py-3 px-4 max-w-xs">
                      <span className="text-slate-500 text-xs truncate block" title={log.details ? JSON.stringify(log.details) : ''}>
                        {log.details
                          ? (typeof log.details === 'string' ? log.details : JSON.stringify(log.details))
                          : <span className="text-slate-300">—</span>
                        }
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center items-center gap-2">
          <button className={`${btnBase} border-slate-200 text-slate-500 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed`} disabled={page === 1} onClick={() => setPage(1)}><ChevronsLeft size={15} /></button>
          <button className={`${btnBase} border-slate-200 text-slate-500 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed`} disabled={page === 1} onClick={() => setPage(p => p - 1)}><ChevronLeft size={15} /></button>
          <span className="text-sm text-slate-600 px-2">Page <strong>{page}</strong> of <strong>{totalPages}</strong></span>
          <button className={`${btnBase} border-slate-200 text-slate-500 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed`} disabled={page === totalPages} onClick={() => setPage(p => p + 1)}><ChevronRight size={15} /></button>
          <button className={`${btnBase} border-slate-200 text-slate-500 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed`} disabled={page === totalPages} onClick={() => setPage(totalPages)}><ChevronsRight size={15} /></button>
        </div>
      )}
    </div>
  );
};

export default Logs;
