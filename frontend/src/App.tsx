import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Scanner } from './pages/Scanner';
import { LiveScan } from './pages/LiveScan';
import { Results } from './pages/Results';
import { History } from './pages/History';
import { ApiConfig } from './pages/ApiConfig';
import { SharedReadout } from './pages/SharedReadout';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('scanner');
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [sharedToken, setSharedToken] = useState<string | null>(null);

  // Check URL parameters or pathname for shared token
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const queryToken = params.get('shared');
    if (queryToken) {
      setSharedToken(queryToken);
      return;
    }

    const path = window.location.pathname;
    const match = path.match(/^\/shared\/([^/]+)/);
    if (match && match[1]) {
      setSharedToken(match[1]);
    }
  }, []);

  // If a shared token is present, show ONLY the read-only SharedReadout view
  if (sharedToken) {
    return <SharedReadout token={sharedToken} />;
  }

  const handleScanStarted = (scanId: string) => {
    setActiveScanId(scanId);
    setCurrentTab('live');
  };

  const handleViewResults = (scanId: string) => {
    setActiveScanId(scanId);
    setCurrentTab('results');
  };

  const handleSelectHistoryScan = (scanId: string) => {
    setActiveScanId(scanId);
    setCurrentTab('results');
  };

  return (
    <div className="min-h-screen bg-[#070a0f] text-slate-200 flex flex-col font-sans">
      <Navbar currentTab={currentTab} onTabChange={setCurrentTab} />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {currentTab === 'scanner' && (
          <Scanner onScanStarted={handleScanStarted} />
        )}

        {currentTab === 'live' && activeScanId && (
          <LiveScan
            scanId={activeScanId}
            onViewResults={handleViewResults}
          />
        )}

        {currentTab === 'results' && activeScanId && (
          <Results
            scanId={activeScanId}
            onBackToScanner={() => setCurrentTab('scanner')}
          />
        )}

        {currentTab === 'history' && (
          <History
            onSelectScan={handleSelectHistoryScan}
            onNewScan={() => setCurrentTab('scanner')}
          />
        )}

        {currentTab === 'apiconfig' && (
          <ApiConfig />
        )}
      </main>

      <footer className="border-t border-phantom-border bg-[#05080e] py-6 px-4">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-slate-500">
          <div className="flex items-center space-x-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            <span>PHANTOM RECON v2.1 // University Cybersecurity Capstone</span>
          </div>
          <div>
            <span>Authorized Penetration Testing & Reconnaissance Framework</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
