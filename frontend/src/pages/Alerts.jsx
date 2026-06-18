import { useEffect, useState, useCallback } from 'react';
import {
  fetchAlerts, fetchAlertStats, fetchAlertTypes, createAlert,
  acknowledgeAlert, acknowledgeAllAlerts, deleteAlert,
} from '../services/api.service';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { ShieldAlert, AlertCircle, AlertTriangle, Info, Shield, Trash2, CheckCheck, BarChart2 } from 'lucide-react';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const SEV_COLORS = {
  critical: '#ef4444',
  high:     '#f59e0b',
  medium:   '#3b82f6',
  low:      '#10b981',
  info:     '#94a3b8',
};

const SEV_BADGE = {
  critical: 'bg-red-100 text-red-800',
  high:     'bg-amber-100 text-amber-800',
  medium:   'bg-blue-100 text-blue-800',
  low:      'bg-green-100 text-green-800',
  info:     'bg-slate-100 text-slate-600',
};

const SEV_ROW_BG = {
  critical: 'bg-red-50/30',
  high:     'bg-amber-50/30',
  medium:   '',
  low:      '',
  info:     '',
};

const SeverityIcon = ({ s }) => {
  const props = { size: 13, className: 'inline-block mr-1 align-middle', style: { color: SEV_COLORS[s] } };
  switch (s) {
    case 'critical': return <ShieldAlert {...props} />;
    case 'high':     return <AlertTriangle {...props} />;
    case 'medium':   return <AlertTriangle {...props} />;
    case 'low':      return <AlertCircle {...props} />;
    case 'info':     return <Info {...props} />;
    default:         return <AlertCircle {...props} />;
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

const SevTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white border border-slate-200 rounded-lg shadow-md p-2 text-sm">
      <span style={{ color: payload[0].payload.fill }}>{payload[0].name}</span>: <strong>{payload[0].value}</strong>
    </div>
  );
};

const selectBase = "px-3 py-2 border border-slate-300 rounded-md text-sm bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-500";
const btnBase = "flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-md border transition-colors cursor-pointer";

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [alertTypes, setAlertTypes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [toast, setToast] = useState(null);
  const [filters, setFilters] = useState({ severity: '', type: '', acknowledged: '' });
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [formError, setFormError] = useState('');
  const [creating, setCreating] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);
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
      } catch (err) { console.error('Failed to load alert types', err); }
    };
    loadTypes();
  }, []);

  useEffect(() => {
    (async () => { await load(); })();
    const interval = setInterval(() => { load(); }, 30000);
    return () => clearInterval(interval);
  }, [load]);

  const handleFilterChange = (e) => {
    setFilters(f => ({ ...f, [e.target.name]: e.target.value }));
    setPage(1);
  };

  const handleResolve = async (id) => {
    try { await acknowledgeAlert(id); showToast('Alert resolved'); load(); }
    catch { showToast('Failed to resolve', 'error'); }
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
    try { await deleteAlert(deleteTarget); showToast('Alert deleted'); setDeleteTarget(null); load(); }
    catch { showToast('Failed to delete', 'error'); }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    setFormError('');
    if (!form.type || !form.severity || !form.source || !form.message) {
      setFormError('All fields except Details are required.'); return;
    }
    setCreating(true);
    try {
      let details = {};
      if (form.details.trim()) {
        try { details = JSON.parse(form.details); }
        catch { setFormError('Details must be valid JSON.'); setCreating(false); return; }
      }
      await createAlert({ ...form, details });
      setShowCreate(false); setForm(EMPTY_FORM);
      showToast('Alert created successfully'); load();
    } catch { showToast('Failed to create alert', 'error'); }
    setCreating(false);
  };

  const toggleSelect = (id) => {
    setSelected(prev => { const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next; });
  };

  const selectAll = () => {
    if (selected.size === alerts.length) setSelected(new Set());
    else setSelected(new Set(alerts.map(a => a.id)));
  };

  const pieData = stats
    ? SEVERITY_ORDER
        .map(s => ({ name: s.charAt(0).toUpperCase() + s.slice(1), value: stats.bySeverity?.[s] ?? 0, fill: SEV_COLORS[s] }))
        .filter(d => d.value > 0)
    : [];

  if (loading && !stats)
    return <div className="flex items-center justify-center h-64 text-slate-400 text-sm">Loading Alerts…</div>;

  if (error)
    return <div className="flex items-center gap-2 bg-red-50 text-red-700 border border-red-200 rounded-lg p-4 text-sm"><AlertTriangle size={16} /> {error}</div>;

  const unacknowledged = stats?.unacknowledged ?? 0;

  return (
    <div className="flex flex-col gap-6">
      {/* Toast */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-lg shadow-lg text-sm font-medium text-white ${toast.type === 'error' ? 'bg-red-600' : 'bg-green-600'}`}>
          {toast.msg}
        </div>
      )}

      {/* Header */}
      <header className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 m-0">Alert Management</h1>
          <p className="text-sm text-slate-500 mt-1 mb-0">Monitor, triage and respond to security alerts</p>
        </div>
        <button
          className={`${btnBase} bg-blue-600 text-white border-blue-600 hover:bg-blue-700`}
          id="create-alert-btn"
          onClick={() => setShowCreate(true)}
        >
          <span className="text-base leading-none">＋</span> New Alert
        </button>
      </header>

      {/* Stats + Chart */}
      {stats && (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <div className="xl:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'Total', value: stats.total, cls: 'text-slate-900' },
              { label: 'Open', value: stats.unacknowledged, cls: 'text-amber-600' },
              { label: 'Last 24h', value: stats.recent24h, cls: 'text-blue-600' },
            ].map(s => (
              <div key={s.label} className="bg-white border border-slate-200 rounded-lg p-4 shadow-sm flex flex-col items-center gap-1">
                <span className={`text-3xl font-bold ${s.cls}`}>{s.value}</span>
                <span className="text-xs text-slate-500 uppercase font-semibold">{s.label}</span>
              </div>
            ))}
            {SEVERITY_ORDER.map(sev => (
              <div key={sev} className="bg-white border border-slate-200 rounded-lg p-4 shadow-sm flex flex-col items-center gap-1">
                <span className="text-3xl font-bold" style={{ color: SEV_COLORS[sev] }}>{stats.bySeverity?.[sev] ?? 0}</span>
                <span className="text-xs text-slate-500 uppercase font-semibold">{sev}</span>
              </div>
            ))}
          </div>

          <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm">
            <div className="flex items-center gap-2 mb-3">
              <BarChart2 size={15} className="text-slate-500" />
              <h3 className="text-sm font-semibold text-slate-900 m-0">Severity Breakdown</h3>
            </div>
            {pieData.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 gap-2 text-slate-400">
                <Shield size={28} /> <p className="text-sm m-0">No alerts yet</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={48} outerRadius={72} paddingAngle={3} dataKey="value" strokeWidth={0}>
                    {pieData.map(entry => <Cell key={entry.name} fill={entry.fill} />)}
                  </Pie>
                  <Tooltip content={<SevTooltip />} />
                  <Legend iconType="circle" iconSize={7} formatter={v => <span style={{ color: '#64748b', fontSize: '0.75rem' }}>{v}</span>} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      )}

      {/* Toolbar */}
      <div className="flex justify-between items-center bg-white border border-slate-200 rounded-lg px-4 py-3 shadow-sm gap-3 flex-wrap">
        <div className="flex items-center gap-3 flex-wrap">
          <select name="severity" value={filters.severity} onChange={handleFilterChange} className={selectBase}>
            <option value="">All Severities</option>
            {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
          <select name="type" value={filters.type} onChange={handleFilterChange} className={selectBase}>
            <option value="">All Types</option>
            {alertTypes.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
          <select name="acknowledged" value={filters.acknowledged} onChange={handleFilterChange} className={selectBase}>
            <option value="">All Status</option>
            <option value="false">Open</option>
            <option value="true">Resolved</option>
          </select>
          {(filters.severity || filters.type || filters.acknowledged) && (
            <button className={`${btnBase} border-slate-300 text-slate-600 bg-white hover:bg-slate-50`} onClick={() => { setFilters({ severity: '', type: '', acknowledged: '' }); setPage(1); }}>
              ✕ Clear
            </button>
          )}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-slate-500">{total} alert{total !== 1 ? 's' : ''}</span>
          {unacknowledged > 0 && (
            <button className={`${btnBase} border-slate-300 text-slate-700 bg-white hover:bg-slate-50`} id="resolve-all-btn" onClick={handleResolveAll}>
              <CheckCheck size={14} /> Resolve All{filters.severity || filters.type ? ' Filtered' : ''}
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 h-48 text-slate-400">
            <Shield size={40} /><p className="text-sm m-0">No alerts match your filters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50">
                <tr>
                  <th className="py-3 px-4 border-b-2 border-slate-100">
                    <input type="checkbox" checked={selected.size === alerts.length && alerts.length > 0} onChange={selectAll} />
                  </th>
                  {['Severity', 'Type', 'Message', 'IP / Source', 'Created At', 'Status', 'Action'].map(h => (
                    <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-slate-500 uppercase tracking-wider border-b-2 border-slate-100">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map(alert => (
                  <tr
                    key={alert.id}
                    className={`border-b border-slate-50 hover:bg-slate-50 transition-colors ${SEV_ROW_BG[alert.severity] || ''} ${alert.acknowledged ? 'opacity-60' : ''} ${selected.has(alert.id) ? 'bg-blue-50/50' : ''}`}
                  >
                    <td className="py-3 px-4">
                      <input type="checkbox" checked={selected.has(alert.id)} onChange={() => toggleSelect(alert.id)} />
                    </td>
                    <td className="py-3 px-4">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${SEV_BADGE[alert.severity] || 'bg-slate-100 text-slate-600'}`}>
                        <SeverityIcon s={alert.severity} /> {alert.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-700">{alert.type.replace(/_/g, ' ')}</td>
                    <td className="py-3 px-4 text-slate-700 max-w-xs truncate" title={alert.message}>{alert.message}</td>
                    <td className="py-3 px-4">
                      <span className="font-mono text-xs bg-slate-100 text-slate-700 px-2 py-0.5 rounded">{alert.source || '—'}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="block text-slate-700">{formatDate(alert.timestamp || alert.createdAt)}</span>
                      <span className="text-xs text-slate-400">{timeAgo(alert.timestamp || alert.createdAt)}</span>
                    </td>
                    <td className="py-3 px-4">
                      {alert.acknowledged
                        ? <span className="text-green-600 text-xs font-semibold">✓ Resolved</span>
                        : <span className="text-amber-600 text-xs font-semibold">● Open</span>
                      }
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        {!alert.acknowledged && (
                          <button
                            className="p-1.5 rounded text-green-600 hover:bg-green-50 transition-colors"
                            title="Resolve"
                            onClick={() => handleResolve(alert.id)}
                          >
                            <CheckCheck size={14} />
                          </button>
                        )}
                        <button
                          className="p-1.5 rounded text-red-500 hover:bg-red-50 transition-colors"
                          title="Delete"
                          onClick={() => setDeleteTarget(alert.id)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
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
          {[
            { disabled: page === 1, label: '«', action: () => setPage(1) },
            { disabled: page === 1, label: '‹', action: () => setPage(p => p - 1) },
            { disabled: page === totalPages, label: '›', action: () => setPage(p => p + 1) },
            { disabled: page === totalPages, label: '»', action: () => setPage(totalPages) },
          ].map((btn, i) => (
            <button
              key={i}
              disabled={btn.disabled}
              onClick={btn.action}
              className={`${btnBase} border-slate-200 text-slate-500 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed`}
            >{btn.label}</button>
          ))}
          <span className="text-sm text-slate-600 px-2">Page <strong>{page}</strong> of <strong>{totalPages}</strong></span>
        </div>
      )}

      {/* Create Alert Modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/40 flex justify-center items-center z-50" onClick={e => e.target === e.currentTarget && setShowCreate(false)}>
          <div className="bg-white rounded-lg shadow-xl w-full max-w-lg p-6" role="dialog" aria-modal="true">
            <div className="flex justify-between items-center mb-5">
              <h2 className="text-lg font-bold text-slate-900 m-0">Create Manual Alert</h2>
              <button className="text-slate-400 hover:text-slate-700 text-xl leading-none" onClick={() => setShowCreate(false)}>✕</button>
            </div>
            <form className="flex flex-col gap-4" onSubmit={handleCreate} noValidate>
              {formError && (
                <div className="flex items-center gap-2 bg-red-50 text-red-700 border border-red-200 rounded-md p-3 text-sm">
                  <AlertTriangle size={14} /> {formError}
                </div>
              )}
              {[
                { label: 'Alert Type', req: true, el: (
                  <select className={selectBase} value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))} required>
                    <option value="">Select type…</option>
                    {alertTypes.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
                  </select>
                )},
                { label: 'Severity', req: true, el: (
                  <select className={selectBase} value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                    {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                  </select>
                )},
                { label: 'Source IP / Host', req: true, el: (
                  <input className={selectBase} type="text" value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value }))} placeholder="e.g. 192.168.1.1" />
                )},
                { label: 'Message', req: true, el: (
                  <textarea className={`${selectBase} resize-none`} value={form.message} onChange={e => setForm(f => ({ ...f, message: e.target.value }))} rows={3} />
                )},
                { label: 'Details (JSON, optional)', req: false, el: (
                  <textarea className={`${selectBase} resize-none font-mono text-xs`} value={form.details} onChange={e => setForm(f => ({ ...f, details: e.target.value }))} placeholder='{"key": "value"}' rows={3} />
                )},
              ].map(({ label, req, el }) => (
                <label key={label} className="flex flex-col gap-1.5">
                  <span className="text-sm font-medium text-slate-700">{label}{req && <span className="text-red-500 ml-0.5">*</span>}</span>
                  {el}
                </label>
              ))}
              <div className="flex justify-end gap-3 pt-2">
                <button type="button" className={`${btnBase} border-slate-300 text-slate-600 bg-white hover:bg-slate-50`} onClick={() => setShowCreate(false)}>Cancel</button>
                <button type="submit" className={`${btnBase} bg-blue-600 text-white border-blue-600 hover:bg-blue-700 disabled:opacity-60`} disabled={creating}>
                  {creating ? 'Creating…' : 'Create Alert'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirm Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/40 flex justify-center items-center z-50" onClick={e => e.target === e.currentTarget && setDeleteTarget(null)}>
          <div className="bg-white rounded-lg shadow-xl w-full max-w-sm p-6" role="dialog" aria-modal="true">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-bold text-slate-900 m-0">Delete Alert?</h2>
              <button className="text-slate-400 hover:text-slate-700 text-xl" onClick={() => setDeleteTarget(null)}>✕</button>
            </div>
            <p className="text-sm text-slate-600 mb-5">This action cannot be undone. The alert will be permanently removed.</p>
            <div className="flex justify-end gap-3">
              <button className={`${btnBase} border-slate-300 text-slate-600 bg-white hover:bg-slate-50`} onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button className={`${btnBase} bg-red-600 text-white border-red-600 hover:bg-red-700`} onClick={handleDelete}>Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
