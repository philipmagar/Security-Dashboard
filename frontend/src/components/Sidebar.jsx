import { NavLink } from 'react-router-dom';
import './Sidebar.css';

const Sidebar = () => {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <h2>Mini-SIEM</h2>
      </div>
      <nav className="sidebar-nav">
        <NavLink to="/" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          <span className="icon">📊</span>
          Dashboard
        </NavLink>
        <NavLink to="/logs" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          <span className="icon">📝</span>
          Logs
        </NavLink>
        <NavLink to="/alerts" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          <span className="icon">🔔</span>
          Alerts
        </NavLink>
      </nav>
    </aside>
  );
};

export default Sidebar;
