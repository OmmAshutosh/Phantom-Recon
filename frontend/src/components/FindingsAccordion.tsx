import React, { useState } from 'react';
import {
  Globe, Shield, Server, Mail, Lock, Cloud, Terminal, Cpu, Search,
  ChevronDown, ChevronUp, AlertTriangle, CheckCircle, XCircle, Info
} from 'lucide-react';

interface FindingsAccordionProps {
  results: any;
}

export const FindingsAccordion: React.FC<FindingsAccordionProps> = ({ results }) => {
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    subdomains: true,
    ports: true,
    tech: false,
    dns: false,
    whois: false,
    ssl: false,
    cloud: false,
    osint: false,
    shodan: false,
  });

  const toggle = (section: string) => {
    setOpenSections((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  const whois = results?.whois || {};
  const dns = results?.dns || {};
  const subdomains = results?.subdomains || [];
  const rawEmails = results?.emails || [];
  const emails = rawEmails.filter((e: any) => typeof e === 'object' && e?.email);
  const emailPatterns = rawEmails.find((e: any) => e?._meta === 'email_patterns')?.patterns || [];
  const tech = results?.technologies || {};
  const ssl = results?.ssl || {};
  const ports = results?.ports || [];
  const cloud = results?.cloud || {};
  const osint = results?.osint || {};
  const shodan = results?.shodan || {};

  return (
    <div className="space-y-4">
      {/* 1. Subdomain Reconnaissance */}
      <div className="bg-phantom-card border border-phantom-border rounded-xl overflow-hidden transition-all">
        <button
          onClick={() => toggle('subdomains')}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/30 transition-colors"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Globe className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-mono text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <span>Subdomain Enumeration</span>
                <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-emerald-400 font-mono">
                  {subdomains.length}
                </span>
              </h4>
              <p className="text-xs text-slate-400">Aggregated OSINT & DNS brute force discovery</p>
            </div>
          </div>
          {openSections.subdomains ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
        </button>

        {openSections.subdomains && (
          <div className="p-4 border-t border-phantom-border bg-slate-950/40">
            {subdomains.length === 0 ? (
              <p className="text-xs text-slate-400 font-mono italic">No subdomains discovered.</p>
            ) : (
              <div className="overflow-x-auto -mx-4 sm:mx-0">
                <table className="w-full text-left text-xs font-mono min-w-[500px]">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                      <th className="pb-2 px-3">Subdomain</th>
                      <th className="pb-2 px-3">IP Address</th>
                      <th className="pb-2 px-3">HTTP Status</th>
                      <th className="pb-2 px-3">Takeover Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {subdomains.map((sub: any, idx: number) => {
                      const hasTakeover = Boolean(sub.takeover_risk);
                      return (
                        <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-2.5 px-3 font-semibold text-slate-200 break-all">
                            {sub.subdomain}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400">
                            {sub.ips && sub.ips.length > 0 ? sub.ips.join(', ') : '—'}
                          </td>
                          <td className="py-2.5 px-3">
                            {sub.http_status ? (
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                sub.http_status >= 200 && sub.http_status < 300
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                  : 'bg-slate-800 text-slate-300'
                              }`}>
                                {sub.http_status}
                              </span>
                            ) : (
                              '—'
                            )}
                          </td>
                          <td className="py-2.5 px-3">
                            {hasTakeover ? (
                              <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-600/50">
                                <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                                <span>{sub.takeover_risk}</span>
                              </span>
                            ) : (
                              <span className="text-slate-500 text-[11px]">None</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 2. Port Scanning & Exposed Services */}
      <div className="bg-phantom-card border border-phantom-border rounded-xl overflow-hidden transition-all">
        <button
          onClick={() => toggle('ports')}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/30 transition-colors"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-mono text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <span>Port Probing & Service Fingerprinting</span>
                <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-emerald-400 font-mono">
                  {ports.filter((p: any) => p.state === 'open').length} Open
                </span>
              </h4>
              <p className="text-xs text-slate-400">Top ports socket probing & banner acquisition</p>
            </div>
          </div>
          {openSections.ports ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
        </button>

        {openSections.ports && (
          <div className="p-4 border-t border-phantom-border bg-slate-950/40">
            {ports.length === 0 ? (
              <p className="text-xs text-slate-400 font-mono italic">No ports tested or open.</p>
            ) : (
              <div className="overflow-x-auto -mx-4 sm:mx-0">
                <table className="w-full text-left text-xs font-mono min-w-[500px]">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                      <th className="pb-2 px-3">Port</th>
                      <th className="pb-2 px-3">Service</th>
                      <th className="pb-2 px-3">State</th>
                      <th className="pb-2 px-3">Banner / Signature</th>
                      <th className="pb-2 px-3">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {ports.map((p: any, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-emerald-400">
                          {p.port}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {p.service || 'Unknown'}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                            p.state === 'open'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-700'
                              : 'bg-slate-800 text-slate-400'
                          }`}>
                            {p.state}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px] truncate max-w-xs">
                          {p.banner || '—'}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            p.risk === 'HIGH' || p.risk === 'CRITICAL'
                              ? 'bg-red-950 text-red-400 border border-red-800'
                              : 'bg-slate-800 text-slate-300'
                          }`}>
                            {p.risk || 'LOW'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 3. Web Technologies & Headers */}
      <div className="bg-phantom-card border border-phantom-border rounded-xl overflow-hidden transition-all">
        <button
          onClick={() => toggle('tech')}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/30 transition-colors"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-mono text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <span>Web Technologies & Security Headers</span>
                <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-emerald-400 font-mono">
                  {tech.detected?.length || 0} Technologies
                </span>
              </h4>
              <p className="text-xs text-slate-400">HTTP response headers, CMS, frameworks, and defense policies</p>
            </div>
          </div>
          {openSections.tech ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
        </button>

        {openSections.tech && (
          <div className="p-4 border-t border-phantom-border bg-slate-950/40 space-y-4">
            <div>
              <h5 className="text-xs font-mono uppercase text-slate-400 mb-2">Detected Frameworks & Components:</h5>
              <div className="flex flex-wrap gap-2">
                {tech.detected && tech.detected.length > 0 ? (
                  tech.detected.map((t: any, idx: number) => (
                    <div key={idx} className="p-2 rounded-lg bg-slate-900 border border-slate-800 flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-slate-200">{t.name}</span>
                      {t.version && <span className="text-[10px] text-emerald-400 font-mono">v{t.version}</span>}
                      {t.category && <span className="text-[10px] text-slate-400 bg-slate-800 px-1 rounded">({t.category})</span>}
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 font-mono">No specific technologies identified.</p>
                )}
              </div>
            </div>

            {tech.missing_security_headers && tech.missing_security_headers.length > 0 && (
              <div>
                <h5 className="text-xs font-mono uppercase text-amber-400 flex items-center space-x-1 mb-2">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Missing Crucial Security Headers:</span>
                </h5>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {tech.missing_security_headers.map((h: any, idx: number) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/20 text-xs font-mono">
                      <span className="text-amber-300 font-bold block">{h.header}</span>
                      <span className="text-slate-400 text-[11px]">{h.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4. DNS & Mail Security */}
      <div className="bg-phantom-card border border-phantom-border rounded-xl overflow-hidden transition-all">
        <button
          onClick={() => toggle('dns')}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/30 transition-colors"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-mono text-sm font-semibold text-slate-100">
                DNS Configuration & Email Defenses
              </h4>
              <p className="text-xs text-slate-400">SPF, DMARC, DKIM, nameservers, and AXFR zone transfer checks</p>
            </div>
          </div>
          {openSections.dns ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
        </button>

        {openSections.dns && (
          <div className="p-4 border-t border-phantom-border bg-slate-950/40 space-y-3 font-mono text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block mb-1">SPF Policy</span>
                <span className="text-emerald-400 break-all">{dns.spf || 'No SPF record published (Vulnerable to spoofing)'}</span>
              </div>
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block mb-1">DMARC Policy</span>
                <span className="text-emerald-400 break-all">{dns.dmarc || 'No DMARC record found'}</span>
              </div>
            </div>

            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block mb-1">Zone Transfer (AXFR) Attempt</span>
              <span className={dns.zone_transfer?.success ? 'text-red-400 font-bold' : 'text-slate-300'}>
                {dns.zone_transfer?.success ? 'CRITICAL: AXFR Zone Transfer succeeded! Internal records exposed.' : 'Zone transfer refused by nameservers (Standard Secure Behavior)'}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* 5. SSL/TLS Certificate Intelligence */}
      <div className="bg-phantom-card border border-phantom-border rounded-xl overflow-hidden transition-all">
        <button
          onClick={() => toggle('ssl')}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/30 transition-colors"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-mono text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <span>SSL / TLS Certificate Intelligence</span>
                {ssl.valid && (
                  <span className="px-2 py-0.5 rounded-full text-xs bg-emerald-950 text-emerald-400 border border-emerald-800">
                    Valid
                  </span>
                )}
              </h4>
              <p className="text-xs text-slate-400">Issuer, validity timeline, SAN hostnames, protocol, cipher suite</p>
            </div>
          </div>
          {openSections.ssl ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
        </button>

        {openSections.ssl && (
          <div className="p-4 border-t border-phantom-border bg-slate-950/40 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono text-xs">
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
              <span className="text-[10px] text-slate-400 uppercase block mb-1">Issuer Org</span>
              <span className="text-slate-200">{ssl.issuer?.organizationName || ssl.issuer?.commonName || '—'}</span>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
              <span className="text-[10px] text-slate-400 uppercase block mb-1">Days Remaining</span>
              <span className={`font-bold ${ssl.days_remaining && ssl.days_remaining < 30 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {ssl.days_remaining ? `${ssl.days_remaining} days` : '—'}
              </span>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
              <span className="text-[10px] text-slate-400 uppercase block mb-1">Protocol & Cipher</span>
              <span className="text-slate-200">{ssl.protocol_version || 'TLS'} // {ssl.cipher || 'Standard'}</span>
            </div>
            {ssl.san_domains && ssl.san_domains.length > 0 && (
              <div className="sm:col-span-2 md:col-span-3 p-3 bg-slate-900 border border-slate-800 rounded-lg">
                <span className="text-[10px] text-slate-400 uppercase block mb-1">Subject Alternative Names (SANs)</span>
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {ssl.san_domains.map((san: string, idx: number) => (
                    <span key={idx} className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded text-[11px]">
                      {san}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 6. Harvested Emails & Patterns */}
      <div className="bg-phantom-card border border-phantom-border rounded-xl overflow-hidden transition-all">
        <button
          onClick={() => toggle('osint')}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/30 transition-colors"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Mail className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-mono text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <span>Email Harvesting & OSINT Reconnaissance</span>
                <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-emerald-400 font-mono">
                  {emails.length} Addresses
                </span>
              </h4>
              <p className="text-xs text-slate-400">Public mail addresses, corporate patterns, Hunter.io intelligence</p>
            </div>
          </div>
          {openSections.osint ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
        </button>

        {openSections.osint && (
          <div className="p-4 border-t border-phantom-border bg-slate-950/40 space-y-3 font-mono text-xs">
            {emailPatterns.length > 0 && (
              <div className="p-2.5 bg-emerald-950/20 border border-emerald-500/20 rounded-lg text-emerald-300">
                <span className="font-bold">Discovered Corporate Pattern: </span>
                <span>{emailPatterns.join(', ')}</span>
              </div>
            )}

            {emails.length === 0 ? (
              <p className="text-slate-400 italic">No email addresses discovered.</p>
            ) : (
              <div className="overflow-x-auto -mx-4 sm:mx-0">
                <table className="w-full text-left text-xs min-w-[450px]">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                      <th className="pb-2 px-3">Email Address</th>
                      <th className="pb-2 px-3">Associated Name</th>
                      <th className="pb-2 px-3">Sources</th>
                      <th className="pb-2 px-3">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {emails.map((e: any, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-800/30">
                        <td className="py-2 px-3 font-semibold text-slate-200">{e.email}</td>
                        <td className="py-2 px-3 text-slate-400">{e.name || e.position || '—'}</td>
                        <td className="py-2 px-3 text-slate-400">
                          {Array.isArray(e.sources) ? e.sources.join(', ') : e.sources || 'web'}
                        </td>
                        <td className="py-2 px-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${
                            e.confidence === 'high' ? 'text-emerald-400 bg-emerald-950' : 'text-slate-300 bg-slate-800'
                          }`}>
                            {e.confidence || 'medium'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 7. Cloud Asset Discovery */}
      <div className="bg-phantom-card border border-phantom-border rounded-xl overflow-hidden transition-all">
        <button
          onClick={() => toggle('cloud')}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/30 transition-colors"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Cloud className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-mono text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <span>Cloud & Code Asset Discovery</span>
                <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-emerald-400 font-mono">
                  {(cloud.s3_buckets?.length || 0) + (cloud.github_repos?.length || 0)} Assets
                </span>
              </h4>
              <p className="text-xs text-slate-400">AWS S3, Azure, GCP buckets, and public GitHub code exposure</p>
            </div>
          </div>
          {openSections.cloud ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
        </button>

        {openSections.cloud && (
          <div className="p-4 border-t border-phantom-border bg-slate-950/40 space-y-3 font-mono text-xs">
            {cloud.s3_buckets && cloud.s3_buckets.length > 0 && (
              <div>
                <span className="text-[10px] text-slate-400 uppercase block mb-2">Storage Buckets:</span>
                <div className="space-y-1.5">
                  {cloud.s3_buckets.map((b: any, idx: number) => (
                    <div key={idx} className="p-2.5 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-200 font-semibold truncate mr-2">{b.name}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        b.accessible ? 'bg-red-950 text-red-400 border border-red-700' : 'bg-slate-800 text-slate-400'
                      }`}>
                        {b.accessible ? 'EXPOSED (Public)' : 'Private (403)'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {cloud.github_repos && cloud.github_repos.length > 0 && (
              <div>
                <span className="text-[10px] text-slate-400 uppercase block mb-2">Associated Public GitHub Repos:</span>
                <div className="space-y-1.5">
                  {cloud.github_repos.map((repo: any, idx: number) => (
                    <div key={idx} className="p-2.5 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                      <div>
                        <span className="text-emerald-400 font-bold block">{repo.name}</span>
                        <span className="text-slate-400 text-[11px]">{repo.description || 'Public repository'}</span>
                      </div>
                      <span className="text-slate-400 text-[11px]">{repo.language}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
