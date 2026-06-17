import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FileText, Bell, LogOut } from 'lucide-react';
import { logoutUser } from '../services/api.service';
import './Sidebar.css';

const Sidebar = () => {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <h2>Mini-SIEM</h2>
      </div>
      <nav className="sidebar-nav">
        <NavLink to="/" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          <LayoutDashboard size={20} className="icon" />
          Dashboard
        </NavLink>
        <NavLink to="/logs" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          <FileText size={20} className="icon" />
          Logs
        </NavLink>
        <NavLink to="/alerts" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          <Bell size={20} className="icon" />
          Alerts
        </NavLink>
      </nav>
      <div className="sidebar-footer" style={{ marginTop: 'auto', padding: '1rem' }}>
        <button 
          onClick={logoutUser} 
          className="nav-link" 
          style={{ width: '100%', background: 'transparent', border: 'none', cursor: 'pointer', textAlign: 'left', color: '#f85149' }}
        >
          <LogOut size={20} className="icon" color="#f85149" />
          Logout
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
