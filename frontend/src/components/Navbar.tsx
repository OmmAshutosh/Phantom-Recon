import React, { useState } from 'react';
import { Shield, Terminal, History, Key, Menu, X, ExternalLink } from 'lucide-react';

interface NavbarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, onTabChange }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { id: 'scanner', label: 'Scanner', icon: Terminal },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'apiconfig', label: 'API Keys', icon: Key },
  ];

  const handleNav = (id: string) => {
    onTabChange(id);
    setMobileMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-phantom-border bg-[#070a0f]/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => handleNav('scanner')}>
            <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mint-glow">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-wider text-slate-100 font-mono">
                  PHANTOM<span className="text-emerald-400">RECON</span>
                </span>
                <span className="text-[10px] px-1.5 py-0.5 font-mono rounded bg-emerald-950/80 text-emerald-300 border border-emerald-500/20">
                  v2.1
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-mono tracking-tight hidden sm:block">
                RED-TEAM RECONNAISSANCE CONSOLE
              </p>
            </div>
          </div>

          {/* Desktop Nav Items */}
          <nav className="hidden md:flex items-center space-x-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNav(item.id)}
                  className={`flex items-center space-x-2 px-3.5 py-2 rounded-md text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right capstone badge */}
          <div className="hidden lg:flex items-center space-x-2 border-l border-slate-800 pl-4">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-xs font-mono text-slate-400">CAPSTONE MODE</span>
          </div>

          {/* Mobile hamburger button */}
          <div className="flex md:hidden">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 focus:outline-none"
              aria-label="Toggle Navigation"
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-phantom-border bg-[#090d16] px-4 pt-2 pb-4 space-y-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleNav(item.id)}
                className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium ${
                  isActive
                    ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                    : 'text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
          <div className="pt-2 border-t border-slate-800 flex items-center space-x-2 text-xs text-slate-400 font-mono px-3">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            <span>Authorized Academic Red-Team Framework</span>
          </div>
        </div>
      )}
    </header>
  );
};
