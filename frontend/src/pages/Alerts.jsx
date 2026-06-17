import { useEffect, useState, useCallback } from 'react';
import {
  fetchAlerts,
  fetchAlertStats,
  fetchAlertTypes,
  createAlert,
  acknowledgeAlert,
  acknowledgeAllAlerts,
  deleteAlert,
} from '../services/api.service';
import './Alerts.css';
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import {
  ShieldAlert, AlertCircle, AlertTriangle, Info, Shield, Trash2,
  CheckCheck, BarChart2
} from 'lucide-react';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const SEV_COLORS = {
  critical: '#f85149',
  high:     '#d29922',
  medium:   '#58a6ff',
  low:      '#3fb950',
  info:     '#8b949e',
};

const SeverityIcon = ({ s }) => {
  const props = { size: 14, style: { display: 'inline-block', verticalAlign: 'middle', marginRight: '4px' } };
  switch(s) {
    case 'critical': return <ShieldAlert {...props} color={SEV_COLORS.critical} />;
    case 'high':     return <AlertTriangle {...props} color={SEV_COLORS.high} />;
    case 'medium':   return <AlertTriangle {...props} color={SEV_COLORS.medium} />;
    case 'low':      return <AlertCircle {...props} color={SEV_COLORS.low} />;
    case 'info':     return <Info {...props} color={SEV_COLORS.info} />;
    default:         return <AlertCircle {...props} color="#8b949e" />;
  }
};

const timeAgo = (iso) => {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const formatDate = (iso) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const EMPTY_FORM = { type: '', severity: 'medium', source: '', message: '', details: '' };

// Custom Donut tooltip
const SevTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="al-chart-tooltip">
      <span style={{ color: payload[0].payload.fill }}>{payload[0].name}</span>: <strong>{payload[0].value}</strong>
    </div>
  );
};

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [alertTypes, setAlertTypes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [toast, setToast] = useState(null);

  // Filters & pagination
  const [filters, setFilters] = useState({ severity: '', type: '', acknowledged: '' });
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);

  // Modals
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [formError, setFormError] = useState('');
  const [creating, setCreating] = useState(false);

  // Confirm delete
  const [deleteTarget, setDeleteTarget] = useState(null);

  // Selected alerts for bulk ops
  const [selected, setSelected] = useState(new Set());

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const load = useCallback(async () => {
    try {
      const [alertsRes, statsRes] = await Promise.all([
        fetchAlerts({ ...filters, page, limit: 20 }),
        fetchAlertStats(),
      ]);
      setAlerts(alertsRes.data);
      setTotalPages(alertsRes.totalPages);
      setTotal(alertsRes.total);
      setStats(statsRes);
      setSelected(new Set());
    } catch (err) {
      setError('Failed to load alerts. Check that the backend is running.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  useEffect(() => {
    const loadTypes = async () => {
      try {
        const res = await fetchAlertTypes();
        setAlertTypes(res.types || []);
      } catch (err) {
        console.error('Failed to load alert types', err);
      }
    };
    loadTypes();
  }, []);

  useEffect(() => {
    (async () => { await load(); })();
    const interval = setInterval(() => { load(); }, 30000);
    return () => clearInterval(interval);
  }, [load]);

  // ── Handlers ──────────────────────────────────────────────────────────────
  const handleFilterChange = (e) => {
    setFilters((f) => ({ ...f, [e.target.name]: e.target.value }));
    setPage(1);
  };

  const handleResolve = async (id) => {
    try {
      await acknowledgeAlert(id);
      showToast('Alert resolved');
      load();
    } catch { showToast('Failed to resolve', 'error'); }
  };

  const handleResolveAll = async () => {
    try {
      const res = await acknowledgeAllAlerts(filters.severity, filters.type);
      showToast(`${res.acknowledged} alert(s) resolved`);
      load();
    } catch { showToast('Failed to resolve all', 'error'); }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await deleteAlert(deleteTarget);
      showToast('Alert deleted');
      setDeleteTarget(null);
      load();
    } catch { showToast('Failed to delete', 'error'); }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    setFormError('');
    if (!form.type || !form.severity || !form.source || !form.message) {
      setFormError('All fields except Details are required.');
      return;
    }
    setCreating(true);
    try {
      let details = {};
      if (form.details.trim()) {
        try { details = JSON.parse(form.details); }
        catch { setFormError('Details must be valid JSON.'); setCreating(false); return; }
      }
      await createAlert({ ...form, details });
      setShowCreate(false);
      setForm(EMPTY_FORM);
      showToast('Alert created successfully');
      load();
    } catch { showToast('Failed to create alert', 'error'); }
    setCreating(false);
  };

  const toggleSelect = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (selected.size === alerts.length) setSelected(new Set());
    else setSelected(new Set(alerts.map((a) => a.id)));
  };

  // Build pie chart data from stats
  const pieData = stats
    ? SEVERITY_ORDER
        .map(s => ({ name: s.charAt(0).toUpperCase() + s.slice(1), value: stats.bySeverity?.[s] ?? 0, fill: SEV_COLORS[s] }))
        .filter(d => d.value > 0)
    : [];

  // ── Render ────────────────────────────────────────────────────────────────
  if (loading && !stats)
    return <div className="al-loading"><span className="al-spinner" />Loading Alerts…</div>;

  if (error)
    return <div className="al-error"><AlertTriangle size={16} style={{display: 'inline-block', verticalAlign: 'middle'}}/> {error}</div>;

  const unacknowledged = stats?.unacknowledged ?? 0;

  return (
    <div className="al-container">
      {/* Toast */}
      {toast && <div className={`al-toast al-toast--${toast.type}`}>{toast.msg}</div>}

      {/* Header */}
      <header className="al-header">
        <div>
          <h1>Alert Management</h1>
          <p className="al-subtitle">Monitor, triage and respond to security alerts</p>
        </div>
        <button className="al-btn al-btn--primary" id="create-alert-btn" onClick={() => setShowCreate(true)}>
          <span>＋</span> New Alert
        </button>
      </header>

      {/* ── Stats bar + Severity Chart ─────────────────────────────────── */}
      {stats && (
        <div className="al-overview">
          {/* Stat cards */}
          <section className="al-stats-bar">
            <div className="al-stat-card al-stat--total">
              <span className="al-stat-num">{stats.total}</span>
              <span className="al-stat-label">Total</span>
            </div>
            <div className="al-stat-card al-stat--unack">
              <span className="al-stat-num">{stats.unacknowledged}</span>
              <span className="al-stat-label">Open</span>
            </div>
            <div className="al-stat-card al-stat--24h">
              <span className="al-stat-num">{stats.recent24h}</span>
              <span className="al-stat-label">Last 24h</span>
            </div>
            {SEVERITY_ORDER.map((sev) => (
              <div key={sev} className={`al-stat-card al-stat--${sev}`}>
                <span className="al-stat-num">{stats.bySeverity?.[sev] ?? 0}</span>
                <span className="al-stat-label">{sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
              </div>
            ))}
          </section>

          {/* Severity Donut Chart */}
          <section className="al-chart-section">
            <div className="al-chart-title-row">
              <BarChart2 size={16} className="al-chart-icon" />
              <h3>Severity Breakdown</h3>
            </div>
            {pieData.length === 0 ? (
              <div className="al-chart-empty"><Shield size={32} /><p>No alerts yet</p></div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip content={<SevTooltip />} />
                  <Legend
                    iconType="circle"
                    iconSize={8}
                    formatter={(value) => <span style={{ color: '#c9d1d9', fontSize: '0.78rem' }}>{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </section>
        </div>
      )}

      {/* Toolbar */}
      <div className="al-toolbar">
        <div className="al-filters">
          <select name="severity" value={filters.severity} onChange={handleFilterChange} id="filter-severity" className="al-select">
            <option value="">All Severities</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>

          <select name="type" value={filters.type} onChange={handleFilterChange} id="filter-type" className="al-select">
            <option value="">All Types</option>
            {alertTypes.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>

          <select name="acknowledged" value={filters.acknowledged} onChange={handleFilterChange} id="filter-ack" className="al-select">
            <option value="">All Status</option>
            <option value="false">Open</option>
            <option value="true">Resolved</option>
          </select>

          {(filters.severity || filters.type || filters.acknowledged) && (
            <button className="al-btn al-btn--ghost" onClick={() => { setFilters({ severity: '', type: '', acknowledged: '' }); setPage(1); }}>
              ✕ Clear
            </button>
          )}
        </div>

        <div className="al-toolbar-actions">
          <span className="al-count">{total} alert{total !== 1 ? 's' : ''}</span>
          {unacknowledged > 0 && (
            <button className="al-btn al-btn--outline" id="resolve-all-btn" onClick={handleResolveAll}>
              <CheckCheck size={15} /> Resolve All{filters.severity || filters.type ? ' Filtered' : ''}
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="al-table-wrap">
        {alerts.length === 0 ? (
          <div className="al-empty">
            <div className="al-empty-icon"><Shield size={48} /></div>
            <p>No alerts match your filters</p>
          </div>
        ) : (
          <table className="al-table">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    checked={selected.size === alerts.length && alerts.length > 0}
                    onChange={selectAll}
                    id="select-all-chk"
                  />
                </th>
                <th>Severity</th>
                <th>Type</th>
                <th>Message</th>
                <th>IP / Source</th>
                <th>Created At</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr
                  key={alert.id}
                  className={`al-row al-row--${alert.severity} ${alert.acknowledged ? 'al-row--acked' : ''} ${selected.has(alert.id) ? 'al-row--selected' : ''}`}
                >
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.has(alert.id)}
                      onChange={() => toggleSelect(alert.id)}
                    />
                  </td>
                  <td>
                    <span className={`al-badge al-sev--${alert.severity}`}>
                      <SeverityIcon s={alert.severity} /> {alert.severity}
                    </span>
                  </td>
                  <td>
                    <span className="al-type">{alert.type.replace(/_/g, ' ')}</span>
                  </td>
                  <td className="al-message" title={alert.message}>{alert.message}</td>
                  <td className="al-source">
                    <span className="al-ip-chip">{alert.source || '—'}</span>
                  </td>
                  <td className="al-created-at">
                    <span className="al-date-main">{formatDate(alert.timestamp || alert.createdAt)}</span>
                    <span className="al-date-ago">{timeAgo(alert.timestamp || alert.createdAt)}</span>
                  </td>
                  <td>
                    {alert.acknowledged ? (
                      <span className="al-status al-status--acked">✓ Resolved</span>
                    ) : (
                      <span className="al-status al-status--open">● Open</span>
                    )}
                  </td>
                  <td className="al-actions">
                    {!alert.acknowledged && (
                      <button
                        className="al-icon-btn al-icon-btn--resolve"
                        title="Resolve"
                        onClick={() => handleResolve(alert.id)}
                        id={`resolve-${alert.id}`}
                      >
                        <CheckCheck size={14} />
                      </button>
                    )}
                    <button
                      className="al-icon-btn al-icon-btn--del"
                      title="Delete"
                      onClick={() => setDeleteTarget(alert.id)}
                      id={`del-${alert.id}`}
                    ><Trash2 size={14} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="al-pagination">
          <button className="al-btn al-btn--ghost" disabled={page === 1} onClick={() => setPage(1)}>«</button>
          <button className="al-btn al-btn--ghost" disabled={page === 1} onClick={() => setPage((p) => p - 1)}>‹</button>
          <span className="al-page-info">Page {page} of {totalPages}</span>
          <button className="al-btn al-btn--ghost" disabled={page === totalPages} onClick={() => setPage((p) => p + 1)}>›</button>
          <button className="al-btn al-btn--ghost" disabled={page === totalPages} onClick={() => setPage(totalPages)}>»</button>
        </div>
      )}

      {/* ── Create Alert Modal ─────────────────────────────────────────── */}
      {showCreate && (
        <div className="al-modal-overlay" onClick={(e) => e.target === e.currentTarget && setShowCreate(false)}>
          <div className="al-modal" role="dialog" aria-modal="true" aria-label="Create Alert">
            <div className="al-modal-header">
              <h2>Create Manual Alert</h2>
              <button className="al-modal-close" onClick={() => setShowCreate(false)}>✕</button>
            </div>
            <form className="al-form" onSubmit={handleCreate} noValidate>
              {formError && <div className="al-form-error"><AlertTriangle size={16} style={{display: 'inline-block', verticalAlign: 'middle'}}/> {formError}</div>}

              <label className="al-label">
                Alert Type <span className="al-req">*</span>
                <select className="al-input" value={form.type} onChange={(e) => setForm((f) => ({ ...f, type: e.target.value }))} required id="form-type">
                  <option value="">Select type…</option>
                  {alertTypes.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
                </select>
              </label>

              <label className="al-label">
                Severity <span className="al-req">*</span>
                <select className="al-input" value={form.severity} onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value }))} id="form-severity">
                  {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                </select>
              </label>

              <label className="al-label">
                Source IP / Host <span className="al-req">*</span>
                <input className="al-input" type="text" value={form.source} onChange={(e) => setForm((f) => ({ ...f, source: e.target.value }))} placeholder="e.g. 192.168.1.1" id="form-source" />
              </label>

              <label className="al-label">
                Message <span className="al-req">*</span>
                <textarea className="al-input al-textarea" value={form.message} onChange={(e) => setForm((f) => ({ ...f, message: e.target.value }))} placeholder="Describe the alert…" rows={3} id="form-message" />
              </label>

              <label className="al-label">
                Details (JSON, optional)
                <textarea className="al-input al-textarea al-mono" value={form.details} onChange={(e) => setForm((f) => ({ ...f, details: e.target.value }))} placeholder='{"key": "value"}' rows={3} id="form-details" />
              </label>

              <div className="al-form-actions">
                <button type="button" className="al-btn al-btn--ghost" onClick={() => setShowCreate(false)}>Cancel</button>
                <button type="submit" className="al-btn al-btn--primary" disabled={creating} id="submit-alert-btn">
                  {creating ? 'Creating…' : 'Create Alert'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Delete Confirm Modal ───────────────────────────────────────── */}
      {deleteTarget && (
        <div className="al-modal-overlay" onClick={(e) => e.target === e.currentTarget && setDeleteTarget(null)}>
          <div className="al-modal al-modal--sm" role="dialog" aria-modal="true">
            <div className="al-modal-header">
              <h2>Delete Alert?</h2>
              <button className="al-modal-close" onClick={() => setDeleteTarget(null)}>✕</button>
            </div>
            <p className="al-confirm-text">This action cannot be undone. The alert will be permanently removed.</p>
            <div className="al-form-actions">
              <button className="al-btn al-btn--ghost" onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button className="al-btn al-btn--danger" id="confirm-delete-btn" onClick={handleDelete}>Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
