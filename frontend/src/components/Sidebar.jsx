import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FileText, Bell } from 'lucide-react';
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
    </aside>
  );
};

export default Sidebar;
