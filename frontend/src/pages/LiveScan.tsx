import React, { useEffect, useState, useRef } from 'react';
import {
  Terminal, ShieldCheck, AlertCircle, ArrowRight, RefreshCw,
  Sliders, Play, CheckCircle2, ChevronRight
} from 'lucide-react';
import { getWebSocketUrl, getScan, getScanLogs } from '../api';
import { LogMessage, ScanRecord } from '../types';

interface LiveScanProps {
  scanId: string;
  onViewResults: (scanId: string) => void;
}

export const LiveScan: React.FC<LiveScanProps> = ({ scanId, onViewResults }) => {
  const [logs, setLogs] = useState<LogMessage[]>([]);
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('INITIALIZING');
  const [status, setStatus] = useState<'queued' | 'running' | 'completed' | 'failed'>('running');
  const [autoScroll, setAutoScroll] = useState(true);
  const [target, setTarget] = useState('');
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Initial load: fetch scan status and any pre-existing logs
  useEffect(() => {
    let mounted = true;

    getScan(scanId).then((scan) => {
      if (!mounted) return;
      setTarget(scan.target);
      setStatus(scan.status);
      if (scan.status === 'completed') setProgress(100);
    }).catch(() => {});

    getScanLogs(scanId).then((existingLogs) => {
      if (!mounted) return;
      if (existingLogs && existingLogs.length > 0) {
        setLogs(existingLogs);
        const lastLog = existingLogs[existingLogs.length - 1];
        if (lastLog.phase) setCurrentPhase(lastLog.phase);
        if (lastLog.progress) setProgress(lastLog.progress);
      }
    }).catch(() => {});

    return () => {
      mounted = false;
    };
  }, [scanId]);

  // Connect WebSocket for live streaming
  useEffect(() => {
    const wsUrl = getWebSocketUrl(scanId);
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'log') {
            setLogs((prev) => [...prev, data]);
            if (data.phase) setCurrentPhase(data.phase);
            if (typeof data.progress === 'number') setProgress(data.progress);
          } else if (data.type === 'complete') {
            setStatus('completed');
            setProgress(100);
            setCurrentPhase('COMPLETE');
          } else if (data.type === 'error') {
            setStatus('failed');
            setCurrentPhase('FAILED');
          }
        } catch (e) {
          // ignore parse error
        }
      };

      ws.onerror = () => {
        // Fallback polling if WebSocket encounters an issue
        const interval = setInterval(async () => {
          try {
            const scan = await getScan(scanId);
            setStatus(scan.status);
            if (scan.status === 'completed' || scan.status === 'failed') {
              clearInterval(interval);
              const allLogs = await getScanLogs(scanId);
              setLogs(allLogs);
              setProgress(100);
            }
          } catch {}
        }, 1500);
      };
    } catch (e) {
      // ws unsupported or blocked
    }

    return () => {
      if (ws) ws.close();
    };
  }, [scanId]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const renderLogBadge = (level: string) => {
    switch (level) {
      case 'phase':
        return <span className="text-cyan-400 font-bold shrink-0">[PHASE]</span>;
      case 'success':
        return <span className="text-emerald-400 font-bold shrink-0">[+]</span>;
      case 'warning':
        return <span className="text-amber-400 font-bold shrink-0">[!]</span>;
      case 'error':
        return <span className="text-rose-400 font-bold shrink-0">[-]</span>;
      case 'info':
      default:
        return <span className="text-sky-400 font-bold shrink-0">[*]</span>;
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-4 pb-12">
      {/* Top Status Bar - Responsive for mobile */}
      <div className="bg-phantom-card border border-phantom-border rounded-xl p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-lg border ${
              status === 'completed'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : status === 'failed'
                ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse'
            }`}>
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono font-bold text-slate-100 text-sm sm:text-base">
                  {target || 'Recon Target'}
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full uppercase font-bold ${
                  status === 'completed'
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : status === 'failed'
                    ? 'bg-rose-950 text-rose-300 border border-rose-800'
                    : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                }`}>
                  {status}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Current Phase: <span className="text-emerald-400 font-semibold">{currentPhase}</span>
              </p>
            </div>
          </div>

          {/* Action button */}
          {status === 'completed' && (
            <button
              onClick={() => onViewResults(scanId)}
              className="w-full sm:w-auto px-4 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold font-mono text-xs rounded-lg transition-all flex items-center justify-center space-x-2 mint-glow shadow-md"
            >
              <span>View Results Dashboard</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Progress Bar */}
        <div className="mt-4 space-y-1.5">
          <div className="flex justify-between text-xs font-mono text-slate-400">
            <span>Scan Pipeline Execution</span>
            <span>{progress}%</span>
          </div>
          <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
            <div
              className="h-full bg-emerald-400 transition-all duration-300 ease-out"
              style={{ width: `${progress}%` }}
            ></div>
          </div>
        </div>
      </div>

      {/* Terminal View Container */}
      <div className="bg-[#05080e] border border-phantom-border rounded-xl overflow-hidden terminal-glow">
        {/* Terminal Header */}
        <div className="flex items-center justify-between px-3 sm:px-4 py-2.5 bg-slate-900/90 border-b border-phantom-border">
          <div className="flex items-center space-x-2">
            <div className="flex space-x-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-rose-500/80"></div>
              <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80"></div>
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80"></div>
            </div>
            <span className="text-xs font-mono text-slate-400 ml-2 hidden sm:inline">
              phantom-recon@stream:~/{target || scanId.slice(0, 8)}
            </span>
          </div>

          <div className="flex items-center space-x-3 text-xs font-mono">
            <label className="flex items-center space-x-1.5 text-slate-400 hover:text-slate-200 cursor-pointer text-[11px]">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
                className="rounded border-slate-700 bg-slate-900 text-emerald-500 focus:ring-0 w-3.5 h-3.5"
              />
              <span>Auto-scroll</span>
            </label>
            <button
              onClick={() => setLogs([])}
              className="text-slate-400 hover:text-slate-200 text-[11px] px-2 py-0.5 rounded bg-slate-800 border border-slate-700"
            >
              Clear
            </button>
          </div>
        </div>

        {/* Log stream output - Mobile polished with word breaking and padding */}
        <div className="p-3 sm:p-4 font-mono text-[11px] sm:text-xs leading-relaxed max-h-[500px] min-h-[340px] overflow-y-auto space-y-1.5">
          {logs.length === 0 ? (
            <div className="flex items-center space-x-2 text-slate-500 italic py-8 justify-center">
              <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" />
              <span>Connecting to live reconnaissance telemetry stream...</span>
            </div>
          ) : (
            logs.map((log, idx) => (
              <div
                key={idx}
                className={`flex items-start space-x-2 transition-opacity ${
                  log.level === 'phase'
                    ? 'pt-2 pb-1 text-cyan-300 font-bold border-t border-slate-900'
                    : 'text-slate-300'
                }`}
              >
                {renderLogBadge(log.level)}
                <span className="text-slate-500 text-[10px] shrink-0 hidden sm:inline">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
                <span className="break-all whitespace-pre-wrap flex-1">
                  {log.message}
                </span>
              </div>
            ))
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
};
