import { ScanRequest, ScanRecord, KeyStatus, ShareResponse, SharedReadoutData, LogMessage } from './types';

// Supports custom production backend URL via VITE_API_URL, otherwise relative /api for local Vite proxy
const API_BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '') + '/api';

export function getWebSocketUrl(scanId: string): string {
  if (import.meta.env.VITE_API_URL) {
    const url = new URL(import.meta.env.VITE_API_URL);
    const proto = url.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${url.host}/api/scan/${scanId}/stream`;
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/api/scan/${scanId}/stream`;
}

export async function initiateScan(request: ScanRequest): Promise<{ scan_id: string; target: string; status: string }> {
  let resp: Response;
  try {
    resp = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  } catch (networkErr: any) {
    if (window.location.hostname !== 'localhost' && !import.meta.env.VITE_API_URL) {
      throw new Error(
        'Backend connection failed: VITE_API_URL is missing in your frontend deployment. Add VITE_API_URL in your Vercel/Netlify Environment Variables pointing to your Railway backend URL.'
      );
    }
    throw new Error(
      `Cannot connect to backend server at ${API_BASE}. If running locally, start the backend with: uvicorn main:app --port 8000`
    );
  }

  if (!resp.ok) {
    if (resp.status === 404) {
      throw new Error(
        `Backend endpoint not found (404) at ${API_BASE}/scan. Verify that VITE_API_URL is set to your backend server.`
      );
    }
    if (resp.status === 502 || resp.status === 503) {
      throw new Error('Backend server is starting up or temporarily unavailable (502/503). Please check your Railway deployment.');
    }
    if (resp.status === 429) {
      throw new Error('Rate limit exceeded: Maximum 20 scans per hour per IP.');
    }
    const errorData = await resp.json().catch(() => ({ detail: `Server error (HTTP ${resp.status})` }));
    const msg = Array.isArray(errorData.detail)
      ? errorData.detail.map((d: any) => d.msg || d.message).join('; ')
      : errorData.detail || 'Failed to initiate scan.';
    throw new Error(msg);
  }

  return resp.json();
}

export async function getScan(scanId: string): Promise<ScanRecord> {
  const resp = await fetch(`${API_BASE}/scan/${scanId}`);
  if (!resp.ok) {
    throw new Error('Scan record not found.');
  }
  return resp.json();
}

export async function getScanLogs(scanId: string): Promise<LogMessage[]> {
  const resp = await fetch(`${API_BASE}/scan/${scanId}/logs`);
  if (!resp.ok) return [];
  const data = await resp.json();
  return data.logs || [];
}

export async function listScans(): Promise<ScanRecord[]> {
  const resp = await fetch(`${API_BASE}/scans`);
  if (!resp.ok) return [];
  const data = await resp.json();
  return data.scans || [];
}

export async function deleteScan(scanId: string): Promise<boolean> {
  const resp = await fetch(`${API_BASE}/scan/${scanId}`, { method: 'DELETE' });
  return resp.ok;
}

export async function getKeyStatus(): Promise<KeyStatus> {
  const resp = await fetch(`${API_BASE}/config/keys`);
  if (!resp.ok) {
    return {
      shodan: false,
      hunter: false,
      virustotal: false,
      netlas: false,
      github: false,
      censys: false,
    };
  }
  return resp.json();
}

export async function createShareLink(scanId: string, expiresInHours: number = 24): Promise<ShareResponse> {
  const resp = await fetch(`${API_BASE}/scan/${scanId}/share`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ expires_in_hours: expiresInHours }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: 'Failed to create share link.' }));
    throw new Error(err.detail || 'Failed to create share link.');
  }
  return resp.json();
}

export async function getSharedReadout(token: string): Promise<SharedReadoutData> {
  const resp = await fetch(`${API_BASE}/shared/${token}`);
  if (resp.status === 410) {
    const err = await resp.json();
    return { expired: true, expires_at: err.detail || 'Expired' };
  }
  if (!resp.ok) {
    throw new Error('This share readout link is invalid or does not exist.');
  }
  return resp.json();
}
