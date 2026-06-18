import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FileText, Bell, LogOut } from 'lucide-react';
import { logoutUser } from '../services/api.service';

const Sidebar = () => {
  const linkClass = "flex items-center gap-3 px-4 py-3 text-slate-500 rounded-md font-medium transition-colors hover:bg-slate-100 hover:text-slate-900";
  const activeLinkClass = "flex items-center gap-3 px-4 py-3 bg-blue-50 text-blue-600 rounded-md font-medium transition-colors";

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col shadow-sm z-10">
      <div className="p-6 border-b border-slate-200">
        <h2 className="m-0 text-blue-600 text-2xl font-bold tracking-tight">Mini-SIEM</h2>
      </div>
      <nav className="flex-1 p-4 flex flex-col gap-2">
        <NavLink to="/" className={({ isActive }) => isActive ? activeLinkClass : linkClass}>
          <LayoutDashboard size={20} className="opacity-80" />
          Dashboard
        </NavLink>
        <NavLink to="/logs" className={({ isActive }) => isActive ? activeLinkClass : linkClass}>
          <FileText size={20} className="opacity-80" />
          Logs
        </NavLink>
        <NavLink to="/alerts" className={({ isActive }) => isActive ? activeLinkClass : linkClass}>
          <Bell size={20} className="opacity-80" />
          Alerts
        </NavLink>
      </nav>
      <div className="mt-auto p-4 border-t border-slate-200">
        <button 
          onClick={logoutUser} 
          className="flex items-center gap-3 w-full px-4 py-3 text-red-500 hover:bg-red-50 rounded-md font-medium transition-colors"
        >
          <LogOut size={20} className="opacity-80" />
          Logout
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
