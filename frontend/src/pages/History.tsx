import React, { useEffect, useState } from 'react';
import {
  History as HistoryIcon, Globe, ArrowRight, Trash2, Share2,
  RefreshCw, AlertTriangle, ShieldCheck, Clock
} from 'lucide-react';
import { listScans, deleteScan } from '../api';
import { ScanRecord } from '../types';
import { ShareModal } from '../components/ShareModal';

interface HistoryProps {
  onSelectScan: (scanId: string) => void;
  onNewScan: () => void;
}

export const History: React.FC<HistoryProps> = ({ onSelectScan, onNewScan }) => {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeShareScan, setActiveShareScan] = useState<{ id: string; target: string } | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const data = await listScans();
      setScans(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm('Delete this reconnaissance scan and all historical logs from database?')) {
      await deleteScan(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
    }
  };

  const getRiskBadge = (level: string, score: number) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-300 border-red-700';
      case 'HIGH':
        return 'bg-orange-950 text-orange-300 border-orange-700';
      case 'MEDIUM':
        return 'bg-amber-950 text-amber-300 border-amber-700';
      case 'LOW':
      default:
        return 'bg-emerald-950 text-emerald-300 border-emerald-700';
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      {/* Header */}
      <div className="bg-phantom-surface border border-phantom-border rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-emerald-400 mb-1">
            <HistoryIcon className="w-3.5 h-3.5" />
            <span>SQLITE AUDIT PERSISTENCE</span>
          </div>
          <h1 className="text-2xl font-bold font-mono text-slate-100">Historical Recon Scans</h1>
          <p className="text-xs text-slate-400 mt-1">
            Audit logs and archived results persisted in WAL-mode SQLite database.
          </p>
        </div>

        <button
          onClick={fetchScans}
          className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs flex items-center space-x-1.5 border border-slate-700"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center space-y-3 text-slate-400">
          <RefreshCw className="w-6 h-6 animate-spin text-emerald-400" />
          <p className="text-xs font-mono">Retrieving scans from SQLite database...</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="p-12 text-center bg-phantom-card border border-phantom-border rounded-xl space-y-4">
          <HistoryIcon className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-base font-bold font-mono text-slate-300">No Reconnaissance Scans Yet</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Run your first authorized scan through the intake console to generate findings and telemetry.
          </p>
          <button
            onClick={onNewScan}
            className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold font-mono text-xs"
          >
            Launch First Scan
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => (
            <div
              key={scan.id}
              onClick={() => onSelectScan(scan.id)}
              className="p-4 sm:p-5 rounded-xl bg-phantom-card border border-phantom-border hover:border-emerald-500/30 cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4"
            >
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-bold text-base text-slate-100 hover:text-emerald-400 transition-colors">
                    {scan.target}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getRiskBadge(scan.risk_level, scan.risk_score)}`}>
                    {scan.risk_level || 'LOW'} ({scan.risk_score || 0}/100)
                  </span>
                  {scan.demo_mode && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800">
                      Demo
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono">
                  <span>{new Date(scan.created_at).toLocaleString()}</span>
                  <span>•</span>
                  <span>{scan.modules?.length || 0} modules</span>
                  <span>•</span>
                  <span className="capitalize">{scan.status}</span>
                </div>
              </div>

              <div className="flex items-center space-x-2 shrink-0" onClick={(e) => e.stopPropagation()}>
                <button
                  onClick={() => setActiveShareScan({ id: scan.id, target: scan.target })}
                  title="Share Readout"
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-emerald-400 border border-slate-700 transition-colors"
                >
                  <Share2 className="w-4 h-4" />
                </button>
                <button
                  onClick={(e) => handleDelete(scan.id, e)}
                  title="Delete Scan Record"
                  className="p-2 rounded-lg bg-slate-800 hover:bg-red-950 text-slate-400 hover:text-red-400 border border-slate-700 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
                <button
                  onClick={() => onSelectScan(scan.id)}
                  className="px-3 py-2 rounded-lg bg-emerald-500/10 hover:bg-emerald-500 text-emerald-400 hover:text-slate-950 font-bold font-mono text-xs flex items-center space-x-1 border border-emerald-500/30 transition-all"
                >
                  <span>Results</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Share Modal */}
      {activeShareScan && (
        <ShareModal
          scanId={activeShareScan.id}
          target={activeShareScan.target}
          isOpen={Boolean(activeShareScan)}
          onClose={() => setActiveShareScan(null)}
        />
      )}
    </div>
  );
};
