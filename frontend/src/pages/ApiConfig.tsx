import React, { useEffect, useState } from 'react';
import {
  Key, ShieldCheck, CheckCircle2, XCircle, ExternalLink,
  Lock, RefreshCw, AlertCircle, Info, Server
} from 'lucide-react';
import { getKeyStatus } from '../api';
import { KeyStatus } from '../types';

export const ApiConfig: React.FC = () => {
  const [keys, setKeys] = useState<KeyStatus>({
    shodan: false,
    hunter: false,
    virustotal: false,
    netlas: false,
    github: false,
    censys: false,
  });
  const [loading, setLoading] = useState(true);

  const fetchKeys = async () => {
    try {
      setLoading(true);
      const res = await getKeyStatus();
      setKeys(res);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const keyDefinitions = [
    {
      id: 'shodan',
      name: 'Shodan API',
      envVar: 'SHODAN_API_KEY',
      url: 'https://account.shodan.io',
      desc: 'Enables querying exposed server banners, IoT devices, open ports, and known CVE vulnerabilities.',
      freeTier: '1 free scan/month on free registration; full API with membership',
      active: keys.shodan,
    },
    {
      id: 'virustotal',
      name: 'VirusTotal API',
      envVar: 'VIRUSTOTAL_API_KEY',
      url: 'https://www.virustotal.com/gui/my-apikey',
      desc: 'Provides automated domain & IP threat reputation scoring and passive DNS resolutions.',
      freeTier: '500 requests/day free tier',
      active: keys.virustotal,
    },
    {
      id: 'hunter',
      name: 'Hunter.io API',
      envVar: 'HUNTER_API_KEY',
      url: 'https://hunter.io/api-keys',
      desc: 'Used for corporate email discovery and automated corporate username/email pattern synthesis.',
      freeTier: '25 free searches/month',
      active: keys.hunter,
    },
    {
      id: 'netlas',
      name: 'Netlas.io API',
      envVar: 'NETLAS_API_KEY',
      url: 'https://netlas.io/account',
      desc: 'Performs DNS history exploration, historical IP lookups, and deep subdomain search.',
      freeTier: '50 free searches/day',
      active: keys.netlas,
    },
    {
      id: 'github',
      name: 'GitHub Personal Token',
      envVar: 'GITHUB_TOKEN',
      url: 'https://github.com/settings/tokens',
      desc: 'Searches public repositories for sensitive credential leaks, tokens, and target assets.',
      freeTier: 'Free personal access token',
      active: keys.github,
    },
    {
      id: 'censys',
      name: 'Censys API',
      envVar: 'CENSYS_API_ID & CENSYS_API_SECRET',
      url: 'https://search.censys.io/account',
      desc: 'Alternative host and certificate exploration engine for global internet reconnaissance.',
      freeTier: '250 queries/month free tier',
      active: keys.censys,
    },
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      {/* Header */}
      <div className="bg-phantom-surface border border-phantom-border rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-emerald-400 mb-1">
            <Lock className="w-3.5 h-3.5" />
            <span>SERVER-SIDE ZERO LEAKAGE ARCHITECTURE</span>
          </div>
          <h1 className="text-2xl font-bold font-mono text-slate-100">API Key Telemetry</h1>
          <p className="text-xs text-slate-400 mt-1">
            External reconnaissance API integrations configured on the backend server.
          </p>
        </div>

        <button
          onClick={fetchKeys}
          className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs flex items-center space-x-1.5 border border-slate-700"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Security Architecture Box */}
      <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/20 flex items-start space-x-3 text-xs text-slate-300">
        <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-mono font-bold text-emerald-300 block">Strict Secret Isolation:</span>
          <p className="leading-relaxed">
            API keys are strictly loaded and stored server-side via environment variables (<code className="text-emerald-400">backend/.env</code> or production platform secrets). The <code className="text-emerald-400">/api/config/keys</code> endpoint only returns boolean status flags. Raw tokens never enter the browser bundle or client network traffic.
          </p>
        </div>
      </div>

      {/* Key Status Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {keyDefinitions.map((keyDef) => (
          <div
            key={keyDef.id}
            className="p-5 rounded-xl bg-phantom-card border border-phantom-border space-y-3"
          >
            <div className="flex items-start justify-between">
              <div>
                <h3 className="font-mono text-sm font-bold text-slate-100">{keyDef.name}</h3>
                <span className="text-[10px] font-mono text-emerald-400/80">{keyDef.envVar}</span>
              </div>
              <span
                className={`inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border ${
                  keyDef.active
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-600/50'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}
              >
                {keyDef.active ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>CONFIGURED</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-3.5 h-3.5 text-slate-500" />
                    <span>OPTIONAL</span>
                  </>
                )}
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">{keyDef.desc}</p>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
              <span className="text-slate-500 text-[11px] truncate max-w-[240px]">{keyDef.freeTier}</span>
              <a
                href={keyDef.url}
                target="_blank"
                rel="noreferrer"
                className="text-emerald-400 hover:text-emerald-300 flex items-center space-x-1 shrink-0"
              >
                <span>Get Key</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        ))}
      </div>

      {/* Setup Guide Box */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-phantom-border space-y-3 font-mono text-xs">
        <h4 className="font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
          <Server className="w-4 h-4 text-emerald-400" />
          <span>Configuring Keys on Server</span>
        </h4>
        <p className="text-slate-400 leading-relaxed">
          Create or edit <code className="text-slate-200">backend/.env</code> (or set them in Railway / Render / Fly.io Environment Variables):
        </p>
        <pre className="p-3 bg-black/60 rounded-lg border border-slate-800 text-emerald-300 overflow-x-auto text-[11px]">
{`SHODAN_API_KEY=your_shodan_key_here
VIRUSTOTAL_API_KEY=your_vt_key_here
HUNTER_API_KEY=your_hunter_key_here
NETLAS_API_KEY=your_netlas_key_here
GITHUB_TOKEN=ghp_your_github_token_here
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret`}
        </pre>
        <p className="text-slate-500 text-[11px]">
          Note: If no keys are provided, PHANTOM RECON gracefully falls back to passive DNS, WHOIS, web scraping, and simulated demo mode.
        </p>
      </div>
    </div>
  );
};
