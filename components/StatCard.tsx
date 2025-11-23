import React from 'react';

interface StatCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
  alert?: boolean;
}

export const StatCard: React.FC<StatCardProps> = ({ title, value, subtitle, alert }) => {
  return (
    <div className={`p-6 rounded-lg border ${alert ? 'bg-red-950/30 border-red-900' : 'bg-slate-800 border-slate-700'}`}>
      <h3 className="text-slate-400 text-sm font-medium uppercase tracking-wider">{title}</h3>
      <div className={`text-3xl font-bold mt-2 ${alert ? 'text-red-500' : 'text-slate-100'}`}>
        {value}
      </div>
      {subtitle && <div className="text-slate-500 text-xs mt-1">{subtitle}</div>}
    </div>
  );
};
