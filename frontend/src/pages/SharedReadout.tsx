import React, { useEffect, useState } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, Clock, Download, FileText,
  Globe, Server, Mail, AlertTriangle, Eye, RefreshCw
} from 'lucide-react';
import { getSharedReadout } from '../api';
import { SharedReadoutData } from '../types';
import { RiskGauge } from '../components/RiskGauge';
import { StatCard } from '../components/StatCard';
import { FindingsAccordion } from '../components/FindingsAccordion';

interface SharedReadoutProps {
  token: string;
}

export const SharedReadout: React.FC<SharedReadoutProps> = ({ token }) => {
  const [data, setData] = useState<SharedReadoutData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    getSharedReadout(token)
      .then((res) => {
        if (!mounted) return;
        setData(res);
      })
      .catch((err) => {
        if (!mounted) return;
        setError(err.message || 'Unable to retrieve shared readout.');
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [token]);

  const handleExportJSON = () => {
    if (!data?.scan?.results) return;
    const blob = new Blob([JSON.stringify(data.scan.results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${data.scan.target}_shared_readout.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadHTML = () => {
    if (!data?.scan?.id) return;
    const backendUrl = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');
    window.open(`${backendUrl}/api/scan/${data.scan.id}/report/html`, '_blank');
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#070a0f] flex flex-col items-center justify-center space-y-4 text-slate-400">
        <RefreshCw className="w-8 h-8 text-emerald-400 animate-spin" />
        <p className="font-mono text-xs">Authenticating shared token and loading readout...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen bg-[#070a0f] flex items-center justify-center p-4">
        <div className="max-w-md w-full p-6 bg-red-950/20 border border-red-500/40 rounded-xl text-center space-y-3">
          <ShieldAlert className="w-10 h-10 text-red-400 mx-auto" />
          <h2 className="text-base font-bold font-mono text-red-300">Invalid Shared Link</h2>
          <p className="text-xs text-slate-300 font-mono">{error || 'This link does not exist.'}</p>
        </div>
      </div>
    );
  }

  if (data.expired) {
    return (
      <div className="min-h-screen bg-[#070a0f] flex items-center justify-center p-4">
        <div className="max-w-md w-full p-6 bg-amber-950/20 border border-amber-500/40 rounded-xl text-center space-y-3">
          <Clock className="w-10 h-10 text-amber-400 mx-auto" />
          <h2 className="text-base font-bold font-mono text-amber-300">Shared Readout Link Expired</h2>
          <p className="text-xs text-slate-300 leading-relaxed font-mono">
            This time-limited review link expired on {new Date(data.expires_at).toLocaleString()}.
            Please contact the red-team capstone researcher to request a refreshed readout link.
          </p>
        </div>
      </div>
    );
  }

  const scan = data.scan!;
  const summary = scan.summary || {};
  const riskFactors = summary.risk_factors || [];

  return (
    <div className="min-h-screen bg-[#070a0f] text-slate-200">
      {/* Readout Banner */}
      <div className="border-b border-phantom-border bg-[#0d131f]/95 py-3 px-4 sm:px-6">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span className="font-bold text-slate-100">PHANTOM RECON v2.1</span>
            <span className="text-slate-500">|</span>
            <span className="text-emerald-400">READ-ONLY CAPSTONE REVIEW</span>
          </div>

          <div className="flex items-center space-x-4 text-[11px] text-slate-400">
            <span className="flex items-center space-x-1">
              <Clock className="w-3.5 h-3.5 text-amber-400" />
              <span>Expires: {new Date(data.expires_at).toLocaleString()}</span>
            </span>
            <span className="flex items-center space-x-1">
              <Eye className="w-3.5 h-3.5 text-slate-400" />
              <span>Views: {data.views_count}</span>
            </span>
          </div>
        </div>
      </div>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Header & Target Information */}
        <div className="bg-phantom-card border border-phantom-border rounded-xl p-4 sm:p-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/20">
                Official Reconnaissance Readout
              </span>
              <h1 className="text-2xl font-bold font-mono text-slate-100 mt-2 break-all">
                {scan.target}
              </h1>
              <p className="text-xs font-mono text-slate-400 mt-1">
                Completed on {new Date(scan.created_at).toLocaleString()} // Status: {scan.status.toUpperCase()}
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={handleDownloadHTML}
                className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs flex items-center space-x-1.5 border border-slate-700 transition-all"
              >
                <FileText className="w-3.5 h-3.5 text-emerald-400" />
                <span>HTML Report</span>
              </button>

              <button
                onClick={handleExportJSON}
                className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs flex items-center space-x-1.5 border border-slate-700 transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>JSON</span>
              </button>
            </div>
          </div>
        </div>

        {/* Top Overview: Risk Gauge + Stat Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-4">
          <div className="md:col-span-1">
            <RiskGauge
              score={scan.risk_score || summary.risk_score || 0}
              level={scan.risk_level || summary.risk_level || 'LOW'}
            />
          </div>

          <div className="md:col-span-2 lg:col-span-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 gap-3">
            <StatCard
              title="Subdomains Discovered"
              value={summary.subdomains_found ?? 0}
              icon={Globe}
              subtitle="Aggregated OSINT & DNS"
              variant="mint"
            />
            <StatCard
              title="Open Public Ports"
              value={summary.open_ports ?? 0}
              icon={Server}
              subtitle="Direct socket probes"
              variant={summary.open_ports > 0 ? 'warning' : 'default'}
            />
            <StatCard
              title="Harvested Emails"
              value={summary.emails_found ?? 0}
              icon={Mail}
              subtitle="Corporate patterns & OSINT"
              variant="default"
            />
            <StatCard
              title="Shodan CVEs Flagged"
              value={summary.cve_count ?? 0}
              icon={AlertTriangle}
              subtitle="Known vulnerabilities"
              variant={summary.cve_count > 0 ? 'danger' : 'default'}
            />
          </div>
        </div>

        {/* Risk Factors Alert Banner */}
        {riskFactors.length > 0 && (
          <div className="p-4 sm:p-5 rounded-xl bg-amber-950/30 border border-amber-500/30 space-y-2">
            <h3 className="font-mono text-xs sm:text-sm font-bold text-amber-300 flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>Identified Security Risk Factors ({riskFactors.length})</span>
            </h3>
            <ul className="space-y-1.5 pl-6 list-disc text-xs font-mono text-slate-300">
              {riskFactors.map((factor: string, idx: number) => (
                <li key={idx} className="leading-relaxed">
                  {factor}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Findings Breakdown */}
        <div>
          <h3 className="font-mono text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
            Detailed Findings Breakdown
          </h3>
          <FindingsAccordion results={scan.results} />
        </div>
      </main>
    </div>
  );
};
