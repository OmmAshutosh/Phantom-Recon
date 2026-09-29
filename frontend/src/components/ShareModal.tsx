import React, { useState } from 'react';
import { Share2, Copy, Check, Clock, ShieldCheck, X, AlertCircle } from 'lucide-react';
import { createShareLink } from '../api';
import { ShareResponse } from '../types';

interface ShareModalProps {
  scanId: string;
  target: string;
  isOpen: boolean;
  onClose: () => void;
}

export const ShareModal: React.FC<ShareModalProps> = ({ scanId, target, isOpen, onClose }) => {
  const [durationHours, setDurationHours] = useState<number>(24);
  const [loading, setLoading] = useState(false);
  const [shareData, setShareData] = useState<ShareResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleGenerate = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await createShareLink(scanId, durationHours);
      setShareData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to generate share link.');
    } finally {
      setLoading(false);
    }
  };

  const getFullUrl = (token: string) => {
    return `${window.location.origin}?shared=${token}`;
  };

  const handleCopy = () => {
    if (!shareData) return;
    const url = getFullUrl(shareData.share_token);
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-lg bg-[#0d131f] border border-phantom-border rounded-xl shadow-2xl p-6 relative">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-200 p-1 rounded-md"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center space-x-3 mb-4">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <Share2 className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-slate-100 font-mono">Share Readout</h3>
            <p className="text-xs text-slate-400">Generate expiring, read-only capstone review link</p>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-950/40 border border-red-500/30 rounded-lg flex items-center space-x-2 text-xs text-red-300">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        {!shareData ? (
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-2">
                TARGET RECON REPORT:
              </label>
              <div className="p-2.5 bg-slate-900/80 rounded-md border border-slate-800 font-mono text-sm text-emerald-400">
                {target}
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-2">
                LINK EXPIRATION DURATION:
              </label>
              <div className="grid grid-cols-4 gap-2">
                {[
                  { label: '1 Hour', hours: 1 },
                  { label: '24 Hours', hours: 24 },
                  { label: '3 Days', hours: 72 },
                  { label: '7 Days', hours: 168 },
                ].map((opt) => (
                  <button
                    key={opt.hours}
                    type="button"
                    onClick={() => setDurationHours(opt.hours)}
                    className={`py-2 px-3 text-xs font-mono rounded-lg border text-center transition-all ${
                      durationHours === opt.hours
                        ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-semibold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="p-3 bg-emerald-950/20 border border-emerald-500/20 rounded-lg flex items-start space-x-2.5 text-xs text-slate-300">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <span>
                Reviewers accessing this link will only see this specific scan's findings and risk assessment. They cannot execute new scans, view history, or view API keys.
              </span>
            </div>

            <button
              onClick={handleGenerate}
              disabled={loading}
              className="w-full py-2.5 px-4 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold font-mono text-sm rounded-lg transition-all flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></div>
                  <span>Generating Secure Link...</span>
                </>
              ) : (
                <>
                  <Share2 className="w-4 h-4" />
                  <span>Generate Expiring Review Link</span>
                </>
              )}
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="p-3 bg-slate-900/90 border border-emerald-500/30 rounded-lg space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                <span className="flex items-center space-x-1">
                  <Clock className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Expires: {new Date(shareData.expires_at).toLocaleString()}</span>
                </span>
                <span className="text-emerald-400">Active</span>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="text"
                  readOnly
                  value={getFullUrl(shareData.share_token)}
                  className="w-full bg-black/60 border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 select-all focus:outline-none"
                />
                <button
                  onClick={handleCopy}
                  className="py-1.5 px-3 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold font-mono text-xs rounded transition-all flex items-center space-x-1 shrink-0"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            <p className="text-xs text-slate-400">
              Send this link directly to capstone reviewers or mentors. The link automatically expires once the configured window elapses.
            </p>

            <button
              onClick={() => {
                setShareData(null);
                onClose();
              }}
              className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-lg transition-all"
            >
              Done
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
