import { useState, useEffect } from 'react';
import { fetchLogs } from '../services/api.service';
import './Logs.css';

const Logs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('');

  useEffect(() => {
    const loadLogs = async () => {
      try {
        setLoading(true);
        const data = await fetchLogs();
        setLogs(data);
      } catch (err) {
        setError('Error loading logs. Make sure backend is running.');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    loadLogs();
  }, []);

  const filteredLogs = logs.filter(log => {
    const matchesSearch = JSON.stringify(log).toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType ? log.eventType === filterType : true;
    return matchesSearch && matchesType;
  });

  return (
    <div className="logs-container">
      <header className="logs-header">
        <h1>Security Logs</h1>
      </header>

      <div className="logs-controls">
        <input 
          type="text" 
          placeholder="Search logs..." 
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-input"
        />
        <select 
          value={filterType} 
          onChange={(e) => setFilterType(e.target.value)}
          className="filter-select"
        >
          <option value="">All Events</option>
          <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
          <option value="LOGIN_FAILED">LOGIN_FAILED</option>
          <option value="ACCESS_DENIED">ACCESS_DENIED</option>
          <option value="TOKEN_INVALID">TOKEN_INVALID</option>
        </select>
      </div>

      {loading ? (
        <div className="loading">Loading logs...</div>
      ) : error ? (
        <div className="error">{error}</div>
      ) : (
        <div className="logs-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>User ID</th>
                <th>IP Address</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.length > 0 ? (
                filteredLogs.map(log => (
                  <tr key={log.id || log._id}>
                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                    <td>
                      <span className={`badge log-${log.eventType?.toLowerCase() || 'unknown'}`}>
                        {log.eventType || 'UNKNOWN'}
                      </span>
                    </td>
                    <td>{log.userId || 'N/A'}</td>
                    <td>{log.ipAddress || 'N/A'}</td>
                    <td className="log-details">{log.details ? JSON.stringify(log.details) : '-'}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" className="empty-state">No logs found matching criteria.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Logs;
