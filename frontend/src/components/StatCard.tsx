import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  subtitle?: string;
  variant?: 'default' | 'mint' | 'warning' | 'danger';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  icon: Icon,
  subtitle,
  variant = 'default',
}) => {
  const getVariantStyles = () => {
    switch (variant) {
      case 'mint':
        return {
          iconBox: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          border: 'border-phantom-border hover:border-emerald-500/30',
        };
      case 'warning':
        return {
          iconBox: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          border: 'border-phantom-border hover:border-amber-500/30',
        };
      case 'danger':
        return {
          iconBox: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          border: 'border-phantom-border hover:border-rose-500/30',
        };
      default:
        return {
          iconBox: 'bg-slate-800/60 text-slate-300 border-slate-700/50',
          border: 'border-phantom-border hover:border-slate-700',
        };
    }
  };

  const styles = getVariantStyles();

  return (
    <div className={`p-4 rounded-xl bg-phantom-card border transition-all ${styles.border}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-slate-400 font-mono uppercase tracking-wider">
          {title}
        </span>
        <div className={`p-2 rounded-lg border ${styles.iconBox}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="mt-2 flex items-baseline space-x-2">
        <span className="text-2xl font-bold font-mono text-slate-100">{value}</span>
        {subtitle && <span className="text-xs text-slate-400 truncate">{subtitle}</span>}
      </div>
    </div>
  );
};
