import React from 'react';

interface RiskGaugeProps {
  score: number;
  level: string;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, level }) => {
  const normalizedScore = Math.min(Math.max(score, 0), 100);
  
  // Calculate SVG arc
  const radius = 68;
  const stroke = 12;
  const circumference = 2 * Math.PI * radius;
  // Use a 240 degree gauge (arc from 150deg to 390deg)
  const arcLength = circumference * (240 / 360);
  const strokeDashoffset = arcLength - (normalizedScore / 100) * arcLength;

  const getColor = (lvl: string) => {
    switch (lvl.toUpperCase()) {
      case 'CRITICAL':
        return { text: 'text-red-400', stroke: '#ef4444', bg: 'bg-red-950/40 border-red-500/30' };
      case 'HIGH':
        return { text: 'text-orange-400', stroke: '#f97316', bg: 'bg-orange-950/40 border-orange-500/30' };
      case 'MEDIUM':
        return { text: 'text-amber-400', stroke: '#f59e0b', bg: 'bg-amber-950/40 border-amber-500/30' };
      case 'LOW':
      default:
        return { text: 'text-emerald-400', stroke: '#34d399', bg: 'bg-emerald-950/40 border-emerald-500/30' };
    }
  };

  const colorConfig = getColor(level);

  return (
    <div className="flex flex-col items-center justify-center p-4 bg-phantom-card rounded-xl border border-phantom-border relative">
      <div className="relative w-44 h-44 flex items-center justify-center">
        <svg className="w-full h-full -rotate-[210deg] transform" viewBox="0 0 160 160">
          {/* Background track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="transparent"
            stroke="#1b263b"
            strokeWidth={stroke}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
          />
          {/* Active progress track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="transparent"
            stroke={colorConfig.stroke}
            strokeWidth={stroke}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Score Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pt-2">
          <span className="text-4xl font-extrabold font-mono text-slate-100 tracking-tight">
            {normalizedScore}
          </span>
          <span className="text-[11px] font-mono uppercase text-slate-400 tracking-wider">
            Risk Score
          </span>
        </div>
      </div>

      {/* Risk Level Badge */}
      <div className={`mt-1 px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider uppercase border ${colorConfig.bg} ${colorConfig.text}`}>
        {level || 'LOW'} RISK
      </div>
    </div>
  );
};
