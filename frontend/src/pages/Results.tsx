import React, { useEffect, useState } from 'react';
import {
  ShieldAlert, Globe, Server, Mail, AlertTriangle, Share2,
  Download, FileText, ArrowLeft, RefreshCw, CheckCircle, ExternalLink,
  ShieldCheck, Lock
} from 'lucide-react';
import { getScan } from '../api';
import { ScanRecord } from '../types';
import { RiskGauge } from '../components/RiskGauge';
import { StatCard } from '../components/StatCard';
import { FindingsAccordion } from '../components/FindingsAccordion';
import { ShareModal } from '../components/ShareModal';

interface ResultsProps {
  scanId: string;
  onBackToScanner: () => void;
}

export const Results: React.FC<ResultsProps> = ({ scanId, onBackToScanner }) => {
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [shareModalOpen, setShareModalOpen] = useState(false);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    getScan(scanId)
      .then((data) => {
        if (!mounted) return;
        setScan(data);
      })
      .catch((err) => {
        if (!mounted) return;
        setError(err.message || 'Unable to load scan findings.');
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [scanId]);

  const handleExportJSON = () => {
    if (!scan?.results) return;
    const blob = new Blob([JSON.stringify(scan.results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${scan.target}_recon_full.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadHTML = () => {
    const backendUrl = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');
    window.open(`${backendUrl}/api/scan/${scanId}/report/html`, '_blank');
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-4">
        <RefreshCw className="w-8 h-8 text-emerald-400 animate-spin" />
        <p className="font-mono text-sm text-slate-400">Loading intelligence findings...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-2xl mx-auto p-6 bg-red-950/30 border border-red-500/30 rounded-xl space-y-4 text-center">
        <ShieldAlert className="w-10 h-10 text-red-400 mx-auto" />
        <h3 className="font-mono text-base font-bold text-red-300">Failed to Load Scan Results</h3>
        <p className="text-xs text-slate-300">{error || 'Scan not found.'}</p>
        <button
          onClick={onBackToScanner}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg"
        >
          Return to Scanner
        </button>
      </div>
    );
  }

  const summary = scan.summary || {};
  const riskFactors = summary.risk_factors || [];

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-16">
      {/* Header Bar - Mobile responsive flex */}
      <div className="bg-phantom-card border border-phantom-border rounded-xl p-4 sm:p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <button
              onClick={onBackToScanner}
              className="inline-flex items-center space-x-1.5 text-xs font-mono text-slate-400 hover:text-emerald-400 mb-2 transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Scanner</span>
            </button>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-xl sm:text-2xl font-bold font-mono text-slate-100 tracking-tight break-all">
                {scan.target}
              </h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-500/30 font-bold uppercase">
                {scan.status}
              </span>
              {scan.passive_only && (
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300">
                  Passive Only
                </span>
              )}
              {scan.demo_mode && (
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                  Demo Simulation
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Scanned on: {new Date(scan.created_at).toLocaleString()} // Tool: PHANTOM RECON v2.1
            </p>
          </div>

          {/* Action Buttons - Stacked on compact mobile, row on tablet/desktop */}
          <div className="flex flex-wrap sm:flex-nowrap items-center gap-2">
            <button
              onClick={() => setShareModalOpen(true)}
              className="w-full sm:w-auto px-3.5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold font-mono text-xs flex items-center justify-center space-x-1.5 mint-glow transition-all shadow"
            >
              <Share2 className="w-3.5 h-3.5" />
              <span>Share Readout</span>
            </button>

            <button
              onClick={handleDownloadHTML}
              className="w-full sm:w-auto px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs flex items-center justify-center space-x-1.5 border border-slate-700 transition-all"
            >
              <FileText className="w-3.5 h-3.5 text-emerald-400" />
              <span>HTML Report</span>
            </button>

            <button
              onClick={handleExportJSON}
              className="w-full sm:w-auto px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs flex items-center justify-center space-x-1.5 border border-slate-700 transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>JSON</span>
            </button>
          </div>
        </div>
      </div>

      {/* Top Overview: Risk Gauge + Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-4">
        {/* Risk Gauge Column */}
        <div className="md:col-span-1">
          <RiskGauge
            score={scan.risk_score || summary.risk_score || 0}
            level={scan.risk_level || summary.risk_level || 'LOW'}
          />
        </div>

        {/* Key Stat Cards Column */}
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

      {/* Findings Deep Dive */}
      <div>
        <h3 className="font-mono text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
          Detailed Findings Breakdown
        </h3>
        <FindingsAccordion results={scan.results} />
      </div>

      {/* Share Modal */}
      <ShareModal
        scanId={scanId}
        target={scan.target}
        isOpen={shareModalOpen}
        onClose={() => setShareModalOpen(false)}
      />
    </div>
  );
};
