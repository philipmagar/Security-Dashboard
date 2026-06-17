import { useState, useEffect, useCallback } from 'react';
import { fetchSecurityLogs, fetchLoginTrend } from '../services/api.service';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts';
import {
  Search, RefreshCw, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight,
  ShieldOff, CheckCircle2, XCircle, Clock, Activity, TrendingDown, Filter
} from 'lucide-react';
import './Logs.css';

const EVENT_TYPES = ['LOGIN', 'LOGOUT', 'REGISTER', 'UNAUTHORIZED_ACCESS', 'TOKEN_INVALID', 'ROLE_ESCALATION_ATTEMPT'];

const EventBadge = ({ event, success }) => {
  let cls = 'lg-badge';
  if (event === 'LOGIN' && success) cls += ' lg-badge--success';
  else if (event === 'LOGIN' && !success) cls += ' lg-badge--danger';
  else if (event === 'REGISTER') cls += ' lg-badge--info';
  else if (event === 'UNAUTHORIZED_ACCESS' || event === 'ROLE_ESCALATION_ATTEMPT') cls += ' lg-badge--critical';
  else if (event === 'TOKEN_INVALID') cls += ' lg-badge--warning';
  else cls += ' lg-badge--neutral';
  return <span className={cls}>{event?.replace(/_/g, ' ')}</span>;
};

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="lg-chart-tooltip">
      <p className="lg-tooltip-label">{label}</p>
      {payload.map(p => (
        <p key={p.dataKey} style={{ color: p.color, margin: '2px 0', fontSize: '0.82rem' }}>
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

  // Filters
  const [filters, setFilters] = useState({ event: '', success: '', ip: '' });
  const [ipInput, setIpInput] = useState('');

  // Pagination
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);

  // Trend chart
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

  // Auto-refresh every 30s
  useEffect(() => {
    const t = setInterval(() => { loadLogs(true); loadTrend(); }, 30000);
    return () => clearInterval(t);
  }, [loadLogs, loadTrend]);

  const handleFilterChange = (name, value) => {
    setFilters(f => ({ ...f, [name]: value }));
    setPage(1);
  };

  const applyIpFilter = () => {
    handleFilterChange('ip', ipInput.trim());
  };

  const clearFilters = () => {
    setFilters({ event: '', success: '', ip: '' });
    setIpInput('');
    setPage(1);
  };

  const totalFailed = trendData.reduce((a, b) => a + b.failed, 0);
  const totalSuccess = trendData.reduce((a, b) => a + b.success, 0);
  const hasFilters = filters.event || filters.success !== '' || filters.ip;

  return (
    <div className="lg-container">
      {/* ── Header ────────────────────────────────────────────────── */}
      <header className="lg-header">
        <div>
          <h1 className="lg-title">Security Logs</h1>
          <p className="lg-subtitle">Real-time event stream and failed login analysis</p>
        </div>
        <div className="lg-header-actions">
          <button
            className={`lg-refresh-btn ${refreshing ? 'lg-refresh-btn--spinning' : ''}`}
            onClick={() => { loadLogs(true); loadTrend(); }}
            title="Refresh"
          >
            <RefreshCw size={16} />
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </header>

      {/* ── Failed Login Trend Chart ─────────────────────────────── */}
      <section className="lg-card lg-trend-section">
        <div className="lg-trend-header">
          <div className="lg-trend-title-row">
            <TrendingDown size={18} className="lg-trend-icon" />
            <h2>Failed Login Trend</h2>
          </div>
          <div className="lg-trend-meta">
            <div className="lg-trend-stat">
              <XCircle size={14} style={{ color: '#f85149' }} />
              <span className="lg-trend-stat-val" style={{ color: '#f85149' }}>{totalFailed}</span>
              <span className="lg-trend-stat-label">Failed</span>
            </div>
            <div className="lg-trend-stat">
              <CheckCircle2 size={14} style={{ color: '#3fb950' }} />
              <span className="lg-trend-stat-val" style={{ color: '#3fb950' }}>{totalSuccess}</span>
              <span className="lg-trend-stat-label">Success</span>
            </div>
            <select
              className="lg-select-sm"
              value={trendHours}
              onChange={e => setTrendHours(Number(e.target.value))}
            >
              <option value={6}>Last 6h</option>
              <option value={24}>Last 24h</option>
              <option value={48}>Last 48h</option>
              <option value={168}>Last 7d</option>
            </select>
          </div>
        </div>
        {trendLoading ? (
          <div className="lg-chart-placeholder"><Activity size={24} className="lg-spin-icon" /><span>Loading chart…</span></div>
        ) : trendData.every(d => d.total === 0) ? (
          <div className="lg-chart-placeholder"><ShieldOff size={24} /><span>No login events in this window</span></div>
        ) : (
          <div className="lg-chart-wrap">
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="failedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f85149" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f85149" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="successGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3fb950" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#3fb950" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" tick={{ fill: '#8b949e', fontSize: 11 }} stroke="transparent" interval="preserveStartEnd" />
                <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} stroke="transparent" allowDecimals={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="failed" name="Failed" stroke="#f85149" strokeWidth={2} fill="url(#failedGrad)" dot={false} />
                <Area type="monotone" dataKey="success" name="Success" stroke="#3fb950" strokeWidth={2} fill="url(#successGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </section>

      {/* ── Filters ──────────────────────────────────────────────── */}
      <div className="lg-filters-bar">
        <div className="lg-filters-left">
          <Filter size={15} className="lg-filter-icon" />
          <select
            className="lg-select"
            value={filters.event}
            onChange={e => handleFilterChange('event', e.target.value)}
          >
            <option value="">All Events</option>
            {EVENT_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>

          <select
            className="lg-select"
            value={filters.success}
            onChange={e => handleFilterChange('success', e.target.value)}
          >
            <option value="">All Outcomes</option>
            <option value="true">Success</option>
            <option value="false">Failed</option>
          </select>

          <div className="lg-ip-search">
            <Search size={14} className="lg-ip-icon" />
            <input
              className="lg-ip-input"
              type="text"
              placeholder="Filter by IP…"
              value={ipInput}
              onChange={e => setIpInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && applyIpFilter()}
            />
            {ipInput && (
              <button className="lg-ip-clear" onClick={() => { setIpInput(''); handleFilterChange('ip', ''); }}>✕</button>
            )}
          </div>
          <button className="lg-apply-btn" onClick={applyIpFilter}>Apply</button>

          {hasFilters && (
            <button className="lg-clear-btn" onClick={clearFilters}>✕ Clear</button>
          )}
        </div>
        <span className="lg-total-count">
          <Clock size={13} /> {total.toLocaleString()} event{total !== 1 ? 's' : ''}
        </span>
      </div>

      {/* ── Table ────────────────────────────────────────────────── */}
      <div className="lg-card lg-table-card">
        {loading ? (
          <div className="lg-loading"><span className="lg-spinner" />Loading logs…</div>
        ) : error ? (
          <div className="lg-error"><XCircle size={16} /> {error}</div>
        ) : logs.length === 0 ? (
          <div className="lg-empty">
            <ShieldOff size={40} />
            <p>No logs match the current filters</p>
          </div>
        ) : (
          <div className="lg-table-wrap">
            <table className="lg-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>User / Email</th>
                  <th>IP Address</th>
                  <th>Status</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id} className={`lg-row ${!log.success && log.event === 'LOGIN' ? 'lg-row--fail' : ''}`}>
                    <td className="lg-col-ts">
                      <span className="lg-ts-date">{new Date(log.timestamp).toLocaleDateString()}</span>
                      <span className="lg-ts-time">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    </td>
                    <td>
                      <EventBadge event={log.event} success={log.success} />
                    </td>
                    <td className="lg-col-user">
                      {log.userEmail || log.userId || <span className="lg-muted">—</span>}
                    </td>
                    <td className="lg-col-ip">
                      <span className="lg-ip-chip">{log.ip || log.ipAddress || '—'}</span>
                    </td>
                    <td>
                      {log.success
                        ? <span className="lg-status lg-status--ok"><CheckCircle2 size={13} /> OK</span>
                        : <span className="lg-status lg-status--fail"><XCircle size={13} /> Fail</span>
                      }
                    </td>
                    <td className="lg-col-details">
                      <span className="lg-details-text" title={log.details ? JSON.stringify(log.details) : ''}>
                        {log.details
                          ? (typeof log.details === 'string'
                            ? log.details
                            : JSON.stringify(log.details))
                          : <span className="lg-muted">—</span>
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

      {/* ── Pagination ───────────────────────────────────────────── */}
      {totalPages > 1 && (
        <div className="lg-pagination">
          <button className="lg-page-btn" disabled={page === 1} onClick={() => setPage(1)}><ChevronsLeft size={15} /></button>
          <button className="lg-page-btn" disabled={page === 1} onClick={() => setPage(p => p - 1)}><ChevronLeft size={15} /></button>
          <span className="lg-page-info">Page <strong>{page}</strong> of <strong>{totalPages}</strong></span>
          <button className="lg-page-btn" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}><ChevronRight size={15} /></button>
          <button className="lg-page-btn" disabled={page === totalPages} onClick={() => setPage(totalPages)}><ChevronsRight size={15} /></button>
        </div>
      )}
    </div>
  );
};

export default Logs;
