export interface ScanRequest {
  target: string;
  consent: boolean;
  passive_only: boolean;
  demo_mode: boolean;
  modules: string[];
  threads?: number;
  timeout?: number;
}

export interface ScanSummary {
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  risk_factors: string[];
  subdomains_found: number;
  emails_found: number;
  open_ports: number;
  cve_count: number;
  cloud_exposed: number;
  confirmed_takeovers?: number;
  leaked_repos?: number;
  ssl_valid?: boolean;
  technologies_detected?: number;
}

export interface ScanRecord {
  id: string;
  target: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  consent_given: boolean;
  passive_only: boolean;
  demo_mode: boolean;
  modules: string[];
  risk_score: number;
  risk_level: string;
  summary: ScanSummary;
  results?: any;
  error_message?: string | null;
  created_at: string;
  completed_at?: string | null;
}

export interface LogMessage {
  id?: number;
  type?: string;
  scan_id?: string;
  timestamp: string;
  level: 'info' | 'phase' | 'success' | 'warning' | 'error';
  message: string;
  phase?: string;
  progress: number;
}

export interface KeyStatus {
  shodan: boolean;
  hunter: boolean;
  virustotal: boolean;
  netlas: boolean;
  github: boolean;
  censys: boolean;
}

export interface ShareResponse {
  share_token: string;
  share_url: string;
  expires_at: string;
  expires_in_hours: number;
  target: string;
}

export interface SharedReadoutData {
  expired: boolean;
  token?: string;
  expires_at: string;
  views_count?: number;
  scan?: {
    id: string;
    target: string;
    status: string;
    created_at: string;
    completed_at?: string;
    risk_score: number;
    risk_level: string;
    modules: string[];
    summary: ScanSummary;
    results: any;
  };
}
