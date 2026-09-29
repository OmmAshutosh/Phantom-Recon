import React, { useState } from 'react';
import {
  ShieldAlert, Terminal, Play, CheckSquare, Square, AlertCircle,
  HelpCircle, Layers, ShieldCheck, Zap
} from 'lucide-react';
import { initiateScan } from '../api';

interface ScannerProps {
  onScanStarted: (scanId: string) => void;
}

const AVAILABLE_MODULES = [
  { id: 'whois', name: 'WHOIS & Registrar', desc: 'Registrar, creation/expiry dates, nameservers, reverse DNS', type: 'Passive' },
  { id: 'dns', name: 'DNS Enumeration', desc: 'A, MX, NS, TXT, SOA records, AXFR zone transfer, SPF/DMARC', type: 'Passive' },
  { id: 'subdomain', name: 'Subdomain Enum', desc: 'Certificate transparency (crt.sh) & DNS wordlist enumeration', type: 'Passive' },
  { id: 'email', name: 'Email Harvesting', desc: 'OSINT search, Hunter.io pattern discovery, leaked contacts', type: 'Passive' },
  { id: 'shodan', name: 'Shodan Intelligence', desc: 'Exposed services, CVE vulnerabilities, banners (needs key)', type: 'Passive' },
  { id: 'tech', name: 'Tech Fingerprint', desc: 'HTTP headers, CMS, JavaScript libraries, missing defenses', type: 'Passive' },
  { id: 'ssl', name: 'SSL/TLS Analysis', desc: 'Cert validity, cipher strength, expiration countdown, SANs', type: 'Passive' },
  { id: 'osint', name: 'OSINT Aggregation', desc: 'VirusTotal malware checks, Wayback Machine history, GitHub', type: 'Passive' },
  { id: 'cloud', name: 'Cloud Discovery', desc: 'AWS S3, Azure Blob, GCP Buckets, public repo credential leaks', type: 'Passive' },
  { id: 'port', name: 'Port Probing', desc: 'Direct socket TCP probes against top ports and service banners', type: 'Active' },
];

export const Scanner: React.FC<ScannerProps> = ({ onScanStarted }) => {
  const [target, setTarget] = useState('scanme.nmap.org');
  const [selectedModules, setSelectedModules] = useState<string[]>([
    'whois', 'dns', 'subdomain', 'email', 'shodan', 'tech', 'ssl', 'osint', 'cloud', 'port'
  ]);
  const [passiveOnly, setPassiveOnly] = useState(false);
  const [demoMode, setDemoMode] = useState(false);
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleModule = (id: string) => {
    setSelectedModules((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]
    );
  };

  const handleSelectAll = () => {
    setSelectedModules(AVAILABLE_MODULES.map((m) => m.id));
  };

  const handlePassiveOnly = () => {
    setPassiveOnly(true);
    setSelectedModules(AVAILABLE_MODULES.filter((m) => m.type === 'Passive').map((m) => m.id));
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!consent) {
      setError('Consent is mandatory. You must certify authorization before initiating reconnaissance.');
      return;
    }

    if (!target.trim()) {
      setError('Please specify a target domain name.');
      return;
    }

    if (selectedModules.length === 0) {
      setError('Please select at least one reconnaissance module.');
      return;
    }

    try {
      setLoading(true);
      const res = await initiateScan({
        target: target.trim(),
        consent: consent,
        passive_only: passiveOnly,
        demo_mode: demoMode,
        modules: selectedModules,
      });

      onScanStarted(res.scan_id);
    } catch (err: any) {
      setError(err.message || 'Failed to start reconnaissance.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      {/* Hero header */}
      <div className="bg-phantom-surface border border-phantom-border rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-mono text-emerald-400 mb-1">
              <Zap className="w-3.5 h-3.5" />
              <span>RECON ENGINE v2.1 // FASTAPI CORE</span>
            </div>
            <h1 className="text-2xl font-bold font-mono text-slate-100 tracking-tight">
              Target Intake & Module Matrix
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Select authorized target domain and configure reconnaissance depth.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-slate-400">Authorized Test Targets:</span>
            <button
              type="button"
              onClick={() => setTarget('scanme.nmap.org')}
              className="text-xs font-mono px-2 py-1 rounded bg-slate-800 text-emerald-300 hover:bg-slate-750 border border-slate-700 transition-colors"
            >
              scanme.nmap.org
            </button>
            <button
              type="button"
              onClick={() => setTarget('example.com')}
              className="text-xs font-mono px-2 py-1 rounded bg-slate-800 text-emerald-300 hover:bg-slate-750 border border-slate-700 transition-colors"
            >
              example.com
            </button>
          </div>
        </div>
      </div>

      <form onSubmit={handleLaunch} className="space-y-6">
        {/* Target Input */}
        <div className="bg-phantom-card border border-phantom-border rounded-xl p-6 space-y-4">
          <label className="block text-sm font-mono font-semibold text-slate-200">
            TARGET DOMAIN (FQDN)
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
              <Terminal className="w-5 h-5 text-emerald-400" />
            </div>
            <input
              type="text"
              required
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. scanme.nmap.org"
              className="w-full pl-11 pr-4 py-3 bg-[#090d16] border border-phantom-borderLight rounded-lg text-slate-100 font-mono text-base placeholder-slate-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 text-xs font-mono">
            <div className="flex items-center space-x-3">
              <label className="flex items-center space-x-2 cursor-pointer text-slate-300 hover:text-slate-100">
                <input
                  type="checkbox"
                  checked={demoMode}
                  onChange={(e) => setDemoMode(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-900 text-emerald-500 focus:ring-0"
                />
                <span>Demo Simulation (Mock Data Generator)</span>
              </label>
            </div>
            <span className="text-slate-500">
              {demoMode ? '✨ Emulates full scan output without sending network packets' : '⚠️ Live queries will be sent to the target'}
            </span>
          </div>
        </div>

        {/* Module Matrix */}
        <div className="bg-phantom-card border border-phantom-border rounded-xl p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-phantom-border pb-3">
            <div>
              <h3 className="font-mono text-base font-bold text-slate-100 flex items-center space-x-2">
                <Layers className="w-4 h-4 text-emerald-400" />
                <span>Reconnaissance Modules ({selectedModules.length}/10 Active)</span>
              </h3>
              <p className="text-xs text-slate-400">Toggle individual modules or select presets</p>
            </div>
            <div className="flex items-center space-x-2 text-xs font-mono">
              <button
                type="button"
                onClick={handleSelectAll}
                className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-colors"
              >
                All Modules
              </button>
              <button
                type="button"
                onClick={handlePassiveOnly}
                className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-colors"
              >
                Passive Only
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 gap-3 pt-1">
            {AVAILABLE_MODULES.map((mod) => {
              const isSelected = selectedModules.includes(mod.id);
              return (
                <div
                  key={mod.id}
                  onClick={() => toggleModule(mod.id)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-slate-900/90 border-emerald-500/40 shadow-sm'
                      : 'bg-slate-950/40 border-slate-800/80 hover:border-slate-750 opacity-60'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-2.5">
                      {isSelected ? (
                        <CheckSquare className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      ) : (
                        <Square className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
                      )}
                      <div>
                        <span className={`text-xs font-mono font-bold ${isSelected ? 'text-slate-100' : 'text-slate-400'}`}>
                          {mod.name}
                        </span>
                        <p className="text-[11px] text-slate-400 mt-0.5 leading-snug line-clamp-2">
                          {mod.desc}
                        </p>
                      </div>
                    </div>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-bold shrink-0 ml-2 ${
                      mod.type === 'Active'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800/50'
                        : 'bg-slate-800 text-slate-400'
                    }`}>
                      {mod.type}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Mandatory Consent Gate */}
        <div className="bg-[#120e0e] border-2 border-red-500/40 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2 text-red-400 font-mono text-sm font-bold">
            <ShieldAlert className="w-5 h-5 shrink-0" />
            <span>MANDATORY AUTHORIZATION & CONSENT ENFORCEMENT</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            This tool is built for university cybersecurity capstone evaluation and authorized red-team engagements only.
            Port scanning, AXFR queries, and cloud probing against targets without written authorization is illegal.
          </p>
          <label className="flex items-start space-x-3 p-3 bg-red-950/20 border border-red-500/30 rounded-lg cursor-pointer hover:bg-red-950/30 transition-colors">
            <input
              type="checkbox"
              id="consent-checkbox"
              required
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
              className="mt-1 w-4 h-4 rounded border-red-500/50 bg-slate-900 text-emerald-500 focus:ring-0 shrink-0"
            />
            <span className="text-xs font-mono font-semibold text-slate-100 leading-normal">
              I legally certify that I own this target or possess explicit written authorization to perform security reconnaissance under applicable computer crime statutes.
            </span>
          </label>
        </div>

        {error && (
          <div className="p-4 bg-red-950/40 border border-red-500/40 rounded-xl flex items-center space-x-3 text-sm text-red-300 font-mono">
            <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Submit Button */}
        <button
          type="submit"
          disabled={!consent || loading}
          className={`w-full py-3.5 px-6 rounded-xl font-mono font-bold text-sm tracking-wide transition-all flex items-center justify-center space-x-2 shadow-lg ${
            consent && !loading
              ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 mint-glow cursor-pointer'
              : 'bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed opacity-60'
          }`}
        >
          {loading ? (
            <>
              <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></div>
              <span>QUEUING RECONNAISSANCE ENGINE...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              <span>LAUNCH RECONNAISSANCE SCAN</span>
            </>
          )}
        </button>
      </form>
    </div>
  );
};
