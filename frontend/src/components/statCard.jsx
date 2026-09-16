function StatCard({ title, value, subtitle }) {
    return (
        <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm transition-colors hover:border-slate-300">
            <h3 className="m-0 mb-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">{title}</h3>
            <p className="m-0 text-3xl font-bold text-slate-900 tracking-tight">{value}</p>
            {subtitle && <p className="m-0 mt-1 text-xs text-slate-500">{subtitle}</p>}
        </div>
    );
}

export default StatCard;