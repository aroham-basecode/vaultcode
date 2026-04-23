"use client";

import { useEffect, useMemo, useState, useCallback } from 'react';
import { apiForgotPassword, apiGetVault, apiLogin, apiPutVault, apiRegister, apiResetPassword } from '../lib/api';
import type { EncryptedVaultV1, VaultBlobV1, VaultItem } from '../lib/vault';
import { createEmptyVault, decryptVault, encryptVault } from '../lib/vault';
import { ZipWriter, BlobWriter, TextReader } from '@zip.js/zip.js';

const TOKEN_KEY = 'pm_token_v1';
const THEME_KEY = 'vc_theme';

function getTheme(): 'light' | 'dark' {
  try {
    const t = document.documentElement.dataset.theme;
    return t === 'light' ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
}

function setTheme(next: 'light' | 'dark') {
  try {
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem(THEME_KEY, next);
  } catch {}
}

function nowIso(): string {
  return new Date().toISOString();
}

function formatDateShort(iso: string | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
}

function autoCategoryFor(item: Partial<Pick<VaultItem, 'title' | 'url' | 'host'>>): string {
  const s = `${item.title ?? ''} ${item.url ?? ''} ${item.host ?? ''}`.toLowerCase();
  if (/(gmail|google|g suite|youtube)/.test(s)) return 'Google';
  if (/(facebook|instagram|whatsapp|meta|twitter|x\.com|linkedin)/.test(s)) return 'Social';
  if (/(bank|hdfc|icici|sbi|axis|kotak|paytm|phonepe|gpay|upi|wallet)/.test(s)) return 'Banking';
  if (/(aws|azure|gcp|cloud|digitalocean|hostinger|cpanel|server|ssh|vps)/.test(s)) return 'Hosting';
  if (/(github|gitlab|bitbucket|jira|confluence)/.test(s)) return 'Work';
  if (/(netflix|primevideo|hotstar|spotify|music|stream)/.test(s)) return 'Entertainment';
  if (/(email|mail)/.test(s)) return 'Email';
  if (/(shopping|amazon|flipkart|myntra|store)/.test(s)) return 'Shopping';
  return 'General';
}

function newId() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function generatePassword(length = 16): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  const arr = typeof crypto !== 'undefined'
    ? crypto.getRandomValues(new Uint8Array(length))
    : Array.from({ length }, () => Math.floor(Math.random() * 256));
  return Array.from(arr).map((b) => chars[b % chars.length]).join('');
}

function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { cur += '"'; i++; } else inQuotes = !inQuotes;
      continue;
    }
    if (ch === ',' && !inQuotes) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

function parseCsv(text: string): Array<Record<string, string>> {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length < 2) return [];
  const headers = parseCsvLine(lines[0]!).map((h) => h.replace(/^"|"$/g, ''));
  return lines.slice(1).map((line) => {
    const cols = parseCsvLine(line);
    const row: Record<string, string> = {};
    headers.forEach((k, j) => { row[k] = cols[j] ?? ''; });
    return row;
  });
}

function csvEscape(value: string): string {
  const s = value ?? '';
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function buildLoginsCsv(items: VaultItem[]): string {
  const headers = ['Title', 'Username', 'Password', 'Host', 'Login URL'];
  const rows = items
    .filter((i) => i.type === 'login')
    .map((i) => [i.title ?? '', i.username ?? '', i.password ? '********' : '', i.host ?? '', i.url ?? '']);
  const lines = [headers, ...rows].map((row) => row.map((v) => csvEscape(String(v ?? ''))).join(','));
  return lines.join('\n') + '\n';
}

function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function downloadZipCsv(filename: string, csvFilename: string, csvText: string, password: string): Promise<void> {
  const writer = new ZipWriter(new BlobWriter('application/zip'), { password });
  await writer.add(csvFilename, new TextReader(csvText));
  const blob = await writer.close();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function getStrength(pw: string): { score: number; label: string; color: string } {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (score <= 1) return { score, label: 'Weak', color: 'bg-red-500' };
  if (score <= 2) return { score, label: 'Fair', color: 'bg-orange-400' };
  if (score <= 3) return { score, label: 'Good', color: 'bg-yellow-400' };
  if (score <= 4) return { score, label: 'Strong', color: 'bg-emerald-500' };
  return { score, label: 'Very Strong', color: 'bg-emerald-600' };
}

function useCopy() {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = useCallback((text: string, key: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    });
  }, []);
  return { copied, copy };
}

function avatarColor(title: string) {
  const colors = [
    'bg-violet-500', 'bg-blue-500', 'bg-emerald-500', 'bg-orange-500',
    'bg-pink-500', 'bg-cyan-500', 'bg-rose-500', 'bg-indigo-500',
  ];
  let hash = 0;
  for (let i = 0; i < title.length; i++) hash = title.charCodeAt(i) + ((hash << 5) - hash);
  return colors[Math.abs(hash) % colors.length]!;
}

// ── Icons ──────────────────────────────────────────────────────────────────

function IconShield() {
  return (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function IconLock() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

function IconEye({ off }: { off?: boolean }) {
  return off ? (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </svg>
  ) : (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

function IconCopy({ done }: { done?: boolean }) {
  return done ? (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  ) : (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function IconTrash() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <path d="M10 11v6" /><path d="M14 11v6" />
      <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
    </svg>
  );
}

function IconExternalLink() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  );
}

function IconChevronDown({ className }: { className?: string }) {
  return (
    <svg className={className} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

function IconSearch() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

function IconPlus() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  );
}

function IconWand() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M15 4V2" /><path d="M15 8V6" /><path d="M19 6h2" /><path d="M15 6h-2" />
      <path d="M5 20l14-14" />
      <path d="M7 18l-2 2" />
      <path d="M6 13l5 5" />
    </svg>
  );
}

function IconSun() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" /><path d="M12 20v2" /><path d="M4.93 4.93l1.41 1.41" /><path d="M17.66 17.66l1.41 1.41" />
      <path d="M2 12h2" /><path d="M20 12h2" /><path d="M4.93 19.07l1.41-1.41" /><path d="M17.66 6.34l1.41-1.41" />
    </svg>
  );
}

function IconMoon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z" />
    </svg>
  );
}

function IconDownload() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="M7 10l5 5 5-5" />
      <path d="M12 15V3" />
    </svg>
  );
}

function IconUpload() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="M17 8l-5-5-5 5" />
      <path d="M12 3v12" />
    </svg>
  );
}

function IconLogOut() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <path d="M16 17l5-5-5-5" />
      <path d="M21 12H9" />
    </svg>
  );
}

function IconPencil() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 20h9" />
      <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z" />
    </svg>
  );
}

// ── Auth Screen ────────────────────────────────────────────────────────────

function AuthScreen(props: {
  mode: 'login' | 'register';
  setMode: (m: 'login' | 'register') => void;
  email: string;
  setEmail: (v: string) => void;
  password: string;
  setPassword: (v: string) => void;
  error: string | null;
  busy: boolean;
  onSubmit: () => void;
  onToken: (token: string) => void;
}) {
  const [showPw, setShowPw] = useState(false);
  const [fpOpen, setFpOpen] = useState(false);
  const [fpStep, setFpStep] = useState<'request' | 'reset'>('request');
  const [fpEmail, setFpEmail] = useState('');
  const [fpCode, setFpCode] = useState('');
  const [fpNewPw, setFpNewPw] = useState('');
  const [fpBusy, setFpBusy] = useState(false);
  const [fpError, setFpError] = useState<string | null>(null);
  const [theme, setThemeState] = useState<'light' | 'dark'>(() => (typeof document === 'undefined' ? 'dark' : getTheme()));

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    setThemeState(next);
  }

  async function handleForgotRequest() {
    setFpError(null);
    if (!fpEmail.trim()) { setFpError('Email required.'); return; }
    setFpBusy(true);
    try {
      await apiForgotPassword(fpEmail.trim());
      setFpStep('reset');
    } catch (e) {
      setFpError(e instanceof Error ? e.message : 'Request failed');
    } finally {
      setFpBusy(false);
    }
  }

  async function handleForgotReset() {
    setFpError(null);
    if (!fpEmail.trim() || !fpCode.trim() || !fpNewPw) { setFpError('Email, code and new password required.'); return; }
    setFpBusy(true);
    try {
      const resp = await apiResetPassword(fpEmail.trim(), fpCode.trim(), fpNewPw);
      window.localStorage.setItem(TOKEN_KEY, resp.token);
      props.onToken(resp.token);
      setFpOpen(false);
      setFpStep('request');
      setFpEmail(''); setFpCode(''); setFpNewPw('');
    } catch (e) {
      setFpError(e instanceof Error ? e.message : 'Reset failed');
    } finally {
      setFpBusy(false);
    }
  }

  if (fpOpen) {
    return (
      <div className="min-h-screen bg-[var(--vc-bg)] text-[var(--vc-text)] flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="mb-8 flex flex-col items-center">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-500 text-white shadow-lg shadow-indigo-500/30">
              <IconShield />
            </div>
            <h1 className="mt-4 text-2xl font-bold text-white">VaultCode</h1>
            <p className="mt-1 text-sm text-slate-400">Reset your account password</p>
          </div>

          <div className="rounded-2xl bg-[var(--vc-panel)] border border-[var(--vc-border)] p-6 shadow-2xl">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="font-semibold text-white">Reset password</div>
                <div className="mt-1 text-xs text-slate-500">
                  {fpStep === 'request' ? 'We will email you a 6-digit code.' : 'Enter the code and choose a new password.'}
                </div>
              </div>
              <button
                type="button"
                className="rounded-lg p-1 text-[var(--vc-muted)] hover:text-[var(--vc-text)] hover:bg-[var(--vc-panel-2)] transition"
                onClick={() => setFpOpen(false)}
                title="Close"
              >
                ✕
              </button>
            </div>

            {fpError && (
              <div className="mt-3 rounded-xl bg-red-500/10 border border-red-500/20 px-4 py-3 text-sm text-red-400">
                {fpError}
              </div>
            )}

            <div className="mt-3 space-y-3">
              <div>
                <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">Email</label>
                <input
                  className="mt-1.5 w-full rounded-xl bg-[var(--vc-panel-2)] border border-[var(--vc-border)] px-3 py-2.5 text-sm text-[var(--vc-text)] placeholder:text-[var(--vc-muted-2)] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
                  value={fpEmail}
                  onChange={(e) => setFpEmail(e.target.value)}
                  placeholder="you@example.com"
                  type="email"
                />
              </div>

              {fpStep === 'reset' && (
                <>
                  <div>
                    <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">Code</label>
                    <input
                      className="mt-1.5 w-full rounded-xl bg-[var(--vc-panel-2)] border border-[var(--vc-border)] px-3 py-2.5 text-sm text-[var(--vc-text)] placeholder:text-[var(--vc-muted-2)] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
                      value={fpCode}
                      onChange={(e) => setFpCode(e.target.value)}
                      placeholder="123456"
                      type="text"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">New password</label>
                    <input
                      className="mt-1.5 w-full rounded-xl bg-[var(--vc-panel-2)] border border-[var(--vc-border)] px-3 py-2.5 text-sm text-[var(--vc-text)] placeholder:text-[var(--vc-muted-2)] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
                      value={fpNewPw}
                      onChange={(e) => setFpNewPw(e.target.value)}
                      placeholder="New password"
                      type="password"
                    />
                  </div>
                </>
              )}

              {fpStep === 'request' ? (
                <button
                  type="button"
                  className="w-full rounded-xl bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white hover:bg-indigo-400 disabled:opacity-50 transition"
                  disabled={fpBusy}
                  onClick={() => void handleForgotRequest()}
                >
                  {fpBusy ? 'Sending…' : 'Send code'}
                </button>
              ) : (
                <div className="space-y-2">
                  <button
                    type="button"
                    className="w-full rounded-xl bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white hover:bg-indigo-400 disabled:opacity-50 transition"
                    disabled={fpBusy}
                    onClick={() => void handleForgotReset()}
                  >
                    {fpBusy ? 'Resetting…' : 'Reset password'}
                  </button>
                  <button
                    type="button"
                    className="w-full text-xs font-medium text-slate-400 hover:text-slate-200 transition"
                    disabled={fpBusy}
                    onClick={() => setFpStep('request')}
                  >
                    Back
                  </button>
                </div>
              )}

              <div className="pt-2 text-center">
                <button
                  type="button"
                  className="text-xs font-medium text-slate-400 hover:text-slate-200 transition"
                  onClick={() => { setFpOpen(false); props.setMode('login'); }}
                >
                  Back to Sign In
                </button>
                <div className="mt-2">
                  <button
                    type="button"
                    className="text-xs font-medium text-slate-400 hover:text-slate-200 transition"
                    onClick={() => { setFpOpen(false); props.setMode('register'); }}
                  >
                    Create Account
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[var(--vc-bg)] text-[var(--vc-text)] flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center relative">
          <div className="absolute right-0 top-0">
            <button
              type="button"
              className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-panel)] px-3 py-2 text-xs font-medium text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
              onClick={toggleTheme}
              title="Toggle theme"
            >
              {theme === 'dark' ? 'Light' : 'Dark'}
            </button>
          </div>
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-500 text-white shadow-lg shadow-indigo-500/30">
            <IconShield />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-[var(--vc-text)]">VaultCode</h1>
          <p className="mt-1 text-sm text-[var(--vc-muted)]">End-to-end encrypted password manager</p>
        </div>

        <div className="rounded-2xl bg-[var(--vc-panel)] border border-[var(--vc-border)] p-6 shadow-2xl">
          <div className="mb-5 flex rounded-xl bg-[var(--vc-panel-2)] p-1">
            {(['login', 'register'] as const).map((m) => (
              <button
                key={m}
                onClick={() => props.setMode(m)}
                className={`flex-1 rounded-lg py-2 text-sm font-medium transition-all ${
                  props.mode === m
                    ? 'bg-indigo-500 text-white shadow'
                    : 'text-[var(--vc-muted)] hover:text-[var(--vc-text)]'
                }`}
              >
                {m === 'login' ? 'Sign In' : 'Create Account'}
              </button>
            ))}
          </div>

          {props.error && (
            <div className="mb-4 flex items-center gap-2 rounded-xl bg-red-500/10 border border-red-500/20 px-4 py-3 text-sm text-red-400">
              <span className="text-red-400">!</span>
              {props.error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">Email</label>
              <input
                className="mt-1.5 w-full rounded-xl bg-[var(--vc-panel-2)] border border-[var(--vc-border)] px-3 py-2.5 text-sm text-[var(--vc-text)] placeholder:text-[var(--vc-muted-2)] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
                value={props.email}
                onChange={(e) => props.setEmail(e.target.value)}
                placeholder="you@example.com"
                type="email"
                onKeyDown={(e) => e.key === 'Enter' && props.onSubmit()}
              />
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">Password</label>
              <div className="relative mt-1.5">
                <input
                  className="w-full rounded-xl bg-[var(--vc-panel-2)] border border-[var(--vc-border)] px-3 py-2.5 pr-10 text-sm text-[var(--vc-text)] placeholder:text-[var(--vc-muted-2)] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
                  value={props.password}
                  onChange={(e) => props.setPassword(e.target.value)}
                  placeholder="••••••••"
                  type={showPw ? 'text' : 'password'}
                  onKeyDown={(e) => e.key === 'Enter' && props.onSubmit()}
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--vc-muted)] hover:text-[var(--vc-text)]"
                  onClick={() => setShowPw(!showPw)}
                >
                  <IconEye off={showPw} />
                </button>
              </div>
            </div>
            <button
              className="w-full rounded-xl bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white shadow hover:bg-indigo-400 disabled:cursor-not-allowed disabled:opacity-50 transition"
              disabled={props.busy}
              onClick={props.onSubmit}
            >
              {props.busy ? 'Please wait…' : props.mode === 'login' ? 'Sign In' : 'Create Account'}
            </button>

            {props.mode === 'login' && (
              <button
                type="button"
                className="w-full text-xs font-medium text-slate-400 hover:text-slate-200 transition"
                onClick={() => {
                  setFpOpen(true);
                  setFpStep('request');
                  setFpEmail(props.email || '');
                  setFpCode('');
                  setFpNewPw('');
                  setFpError(null);
                }}
              >
                Forgot password?
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Unlock Screen ──────────────────────────────────────────────────────────

function UnlockScreen(props: {
  hasVault: boolean;
  loading: boolean;
  password: string;
  setPassword: (v: string) => void;
  error: string | null;
  onUnlock: () => void;
  onCreate: () => void;
  onLogout: () => void;
}) {
  const [showPw, setShowPw] = useState(false);
  const strength = props.hasVault ? null : getStrength(props.password);
  const [theme, setThemeState] = useState<'light' | 'dark'>(() => (typeof document === 'undefined' ? 'dark' : getTheme()));

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    setThemeState(next);
  }

  return (
    <div className="min-h-screen bg-[var(--vc-bg)] text-[var(--vc-text)] flex items-center justify-center p-4">
      <div className="fixed right-4 top-4 z-20">
        <button
          type="button"
          className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-panel)] p-2 text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
          onClick={toggleTheme}
          title="Toggle theme"
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? <IconSun /> : <IconMoon />}
        </button>
      </div>
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-500 text-white shadow-lg shadow-indigo-500/30">
            <IconShield />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-[var(--vc-text)]">VaultCode</h1>
          <p className="mt-1 text-sm text-[var(--vc-muted)]">
            {props.hasVault ? 'Enter your master password to unlock' : 'Create a master password for your vault'}
          </p>
        </div>

        <div className="rounded-2xl bg-[var(--vc-panel)] border border-[var(--vc-border)] p-6 shadow-2xl">
          <div className="mb-5 flex items-center gap-3 rounded-xl bg-[var(--vc-panel-2)] px-4 py-3">
            <div className="text-indigo-400"><IconLock /></div>
            <div>
              <div className="text-sm font-semibold text-[var(--vc-text)]">
                {props.hasVault ? 'Vault Locked' : 'New Vault'}
              </div>
              <div className="text-xs text-[var(--vc-muted-2)]">
                {props.hasVault ? 'Encrypted on server' : 'Will be encrypted with your master password'}
              </div>
            </div>
          </div>

          {!props.hasVault && !props.loading && (
            <div className="mb-4 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3">
              <div className="flex items-start gap-2">
                <span className="mt-0.5 text-amber-400 text-base leading-none">⚠️</span>
                <div>
                  <div className="text-sm font-semibold text-amber-400">Important Warning</div>
                  <div className="mt-1 text-xs text-amber-300/80 leading-relaxed">
                    Your master password <span className="font-bold text-amber-300">cannot be recovered</span> if forgotten.
                    It is never sent to our servers — your vault can only be decrypted by you.
                    <br /><br />
                    <span className="font-semibold text-amber-300">Please write it down and keep it in a safe place.</span>
                    If you lose it, all your saved passwords will be permanently inaccessible.
                  </div>
                </div>
              </div>
            </div>
          )}

          {props.error && (
            <div className="mb-4 rounded-xl bg-red-500/10 border border-red-500/20 px-4 py-3 text-sm text-red-400">
              {props.error}
            </div>
          )}

          {props.loading ? (
            <div className="py-6 text-center text-sm text-[var(--vc-muted-2)]">Loading vault…</div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="text-xs font-semibold uppercase tracking-wide text-[var(--vc-muted)]">
                  Master Password
                </label>
                <div className="relative mt-1.5">
                  <input
                    autoFocus
                    className="w-full rounded-xl bg-[var(--vc-panel-2)] border border-[var(--vc-border)] px-3 py-2.5 pr-10 text-sm text-[var(--vc-text)] placeholder:text-[var(--vc-muted-2)] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
                    type={showPw ? 'text' : 'password'}
                    value={props.password}
                    onChange={(e) => props.setPassword(e.target.value)}
                    placeholder="Enter master password"
                    onKeyDown={(e) => e.key === 'Enter' && (props.hasVault ? props.onUnlock() : props.onCreate())}
                  />
                  <button
                    type="button"
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--vc-muted)] hover:text-[var(--vc-text)]"
                    onClick={() => setShowPw(!showPw)}
                  >
                    <IconEye off={showPw} />
                  </button>
                </div>
                {!props.hasVault && props.password && strength && (
                  <div className="mt-2">
                    <div className="flex gap-1">
                      {[1, 2, 3, 4, 5].map((i) => (
                        <div key={i} className={`h-1 flex-1 rounded-full transition-all ${i <= strength.score ? strength.color : 'bg-[var(--vc-border)]'}`} />
                      ))}
                    </div>
                    <div className="mt-1 text-xs text-[var(--vc-muted-2)]">{strength.label}</div>
                  </div>
                )}
              </div>
              <button
                className="w-full rounded-xl bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white shadow hover:bg-indigo-400 transition"
                onClick={props.hasVault ? props.onUnlock : props.onCreate}
              >
                {props.hasVault ? 'Unlock Vault' : 'Create Vault'}
              </button>
              <button
                className="w-full rounded-xl border border-[var(--vc-border)] bg-[var(--vc-panel-2)] px-4 py-2.5 text-sm font-medium text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
                onClick={props.onLogout}
              >
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Vault Item Card ────────────────────────────────────────────────────────

function VaultCard(props: {
  item: VaultItem;
  onDelete: () => void;
  expanded: boolean;
  onToggle: () => void;
  onEdit: () => void;
  health?: {
    isWeak: boolean;
    reusedCount: number;
    autoCategory: string;
  };
}) {
  const [revealed, setRevealed] = useState(false);
  const { copied, copy } = useCopy();
  const initials = (props.item.title || '?').slice(0, 2).toUpperCase();
  const color = avatarColor(props.item.title);
  const effectiveCategory = (props.item.category && props.item.category.trim()) ? props.item.category.trim() : props.health?.autoCategory;

  return (
    <div className="group rounded-xl bg-[var(--vc-panel)] border border-[var(--vc-border)] px-3 py-2.5 hover:border-[var(--vc-border-2)] transition">
      <div className="flex items-start gap-2.5">
        <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-xs font-bold text-white ${color}`}>
          {initials}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <div className="truncate font-semibold text-[var(--vc-text)]">{props.item.title}</div>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1">
                {props.item.username && (
                  <div className="text-xs text-[var(--vc-muted)] truncate">{props.item.username}</div>
                )}
                {props.item.host && (
                  <div className="text-[11px] text-[var(--vc-muted)] truncate">{props.item.host}</div>
                )}
                {effectiveCategory && (
                  <div className="text-[11px] rounded-full bg-[var(--vc-panel-2)] px-2 py-0.5 text-[var(--vc-muted)]">
                    {effectiveCategory}
                  </div>
                )}
                {props.health?.isWeak && (
                  <div className="text-[11px] rounded-full bg-red-500/10 px-2 py-0.5 text-red-500">
                    Weak
                  </div>
                )}
                {!!props.health?.reusedCount && props.health.reusedCount > 1 && (
                  <div className="text-[11px] rounded-full bg-amber-500/10 px-2 py-0.5 text-amber-500">
                    Similar x{props.health.reusedCount}
                  </div>
                )}
              </div>
            </div>
            <div className="shrink-0 flex items-center gap-1">
              {props.item.url && (
                <button
                  onClick={() => {
                    window.open(props.item.url!, '_blank', 'noopener,noreferrer');
                  }}
                  className="rounded-lg p-1 text-[var(--vc-muted)] hover:text-[var(--vc-text)] hover:bg-[var(--vc-panel-2)] transition"
                  title="Open"
                  type="button"
                >
                  <IconExternalLink />
                </button>
              )}
              <button
                onClick={props.onEdit}
                className="rounded-lg p-1 text-[var(--vc-muted)] hover:text-[var(--vc-text)] hover:bg-[var(--vc-panel-2)] transition"
                title="Edit"
                type="button"
              >
                <IconPencil />
              </button>
              <button
                onClick={() => {
                  props.onToggle();
                }}
                className="rounded-lg p-1 text-[var(--vc-muted)] hover:text-[var(--vc-text)] hover:bg-[var(--vc-panel-2)] transition"
                title={props.expanded ? 'Collapse' : 'Expand'}
                type="button"
              >
                <IconChevronDown className={props.expanded ? 'rotate-180 transition-transform' : 'transition-transform'} />
              </button>
              <button
                onClick={props.onDelete}
                className="rounded-lg p-1 text-[var(--vc-muted-2)] opacity-0 group-hover:opacity-100 hover:bg-red-500/10 hover:text-red-500 transition"
                title="Delete"
                type="button"
              >
                <IconTrash />
              </button>
            </div>
          </div>

          {props.expanded && (
            <div className="mt-2 space-y-1.5">
            {props.item.username && (
              <div className="flex items-center justify-between rounded-lg bg-[var(--vc-panel-2)] px-2.5 py-1.5">
                <div className="min-w-0">
                  <div className="text-[11px] text-[var(--vc-muted)]">Username</div>
                  <div className="text-xs text-[var(--vc-text)] truncate">{props.item.username}</div>
                </div>
                <button
                  onClick={() => copy(props.item.username!, `${props.item.id}-user`)}
                  className={`ml-2 shrink-0 rounded-lg p-1 transition ${copied === `${props.item.id}-user` ? 'text-emerald-500' : 'text-[var(--vc-muted)] hover:text-[var(--vc-text)] hover:bg-[var(--vc-panel)]'}`}
                  type="button"
                >
                  <IconCopy done={copied === `${props.item.id}-user`} />
                </button>
              </div>
            )}

            {props.item.password && (
              <div className="flex items-center justify-between rounded-lg bg-[var(--vc-panel-2)] px-2.5 py-1.5">
                <div className="min-w-0 flex-1">
                  <div className="text-[11px] text-[var(--vc-muted)]">Password</div>
                  <div className="font-mono text-xs text-[var(--vc-text)] truncate">
                    {revealed ? props.item.password : '••••••••••••'}
                  </div>
                  <div className="mt-0.5 text-[11px] text-[var(--vc-muted-2)]">
                    Updated {formatDateShort(props.item.updatedAt)}
                  </div>
                </div>
                <div className="ml-2 flex shrink-0 items-center gap-1">
                  <button
                    onClick={() => setRevealed(!revealed)}
                    className="rounded-lg p-1 text-[var(--vc-muted)] hover:text-[var(--vc-text)] hover:bg-[var(--vc-panel)] transition"
                    type="button"
                  >
                    <IconEye off={revealed} />
                  </button>
                  <button
                    onClick={() => copy(props.item.password!, `${props.item.id}-pw`)}
                    className={`rounded-lg p-1 transition ${copied === `${props.item.id}-pw` ? 'text-emerald-500' : 'text-[var(--vc-muted)] hover:text-[var(--vc-text)] hover:bg-[var(--vc-panel)]'}`}
                    type="button"
                  >
                    <IconCopy done={copied === `${props.item.id}-pw`} />
                  </button>
                </div>
              </div>
            )}

            {props.item.url && (
              <a
                href={props.item.url}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-2 rounded-lg bg-[var(--vc-panel-2)] px-2.5 py-1.5 text-[11px] text-indigo-500 hover:text-indigo-600 transition truncate"
              >
                <span className="truncate">{props.item.url}</span>
              </a>
            )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Add Login Form ─────────────────────────────────────────────────────────

function AddLoginForm(props: {
  onSave: (form: { id?: string; title: string; host: string; username: string; password: string; url: string; category: string }) => void;
  prefill?: Partial<{ title: string; host: string; username: string; password: string; url: string; category: string }> | null;
  editingId?: string | null;
  onCancel?: () => void;
}) {
  const [title, setTitle] = useState('');
  const [host, setHost] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');
  const [category, setCategory] = useState('');
  const [showPw, setShowPw] = useState(false);
  const strength = password ? getStrength(password) : null;

  useEffect(() => {
    if (!props.prefill) return;
    if (typeof props.prefill.title === 'string') setTitle(props.prefill.title);
    if (typeof props.prefill.host === 'string') setHost(props.prefill.host);
    if (typeof props.prefill.username === 'string') setUsername(props.prefill.username);
    if (typeof props.prefill.password === 'string') { setPassword(props.prefill.password); setShowPw(false); }
    if (typeof props.prefill.url === 'string') setUrl(props.prefill.url);
    if (typeof props.prefill.category === 'string') setCategory(props.prefill.category);
  }, [props.prefill]);

  useEffect(() => {
    if (props.editingId) return;
    if (category.trim()) return;
    setCategory(autoCategoryFor({ title, url, host }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [title, url, host]);

  function handleSave() {
    if (!title.trim()) return;
    props.onSave({ id: props.editingId ?? undefined, title, host, username, password, url, category });
    setTitle(''); setHost(''); setUsername(''); setPassword(''); setUrl(''); setCategory('');
  }

  return (
    <div className="rounded-2xl bg-[var(--vc-panel)] border border-[var(--vc-border)] p-5">
      <div className="mb-4 flex items-center justify-between gap-2">
        <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-500/20 text-indigo-400">
          <IconPlus />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="font-semibold text-[var(--vc-text)] truncate">{props.editingId ? 'Edit Login' : 'Add New Login'}</h2>
          <div className="text-xs text-[var(--vc-muted)] truncate">{props.editingId ? 'Update your saved credential' : 'Save a new credential into your vault'}</div>
        </div>
        {props.onCancel && (
          <button
            type="button"
            onClick={props.onCancel}
            className="shrink-0 rounded-xl border border-[var(--vc-border)] bg-[var(--vc-panel-2)] px-3 py-2 text-xs font-medium text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
          >
            Close
          </button>
        )}
      </div>
      <div className="space-y-3">
        <FormField label="Title" value={title} onChange={setTitle} placeholder="e.g. Gmail" />
        <FormField label="Category" value={category} onChange={setCategory} placeholder="e.g. Banking" />
        <FormField label="Username / Email" value={username} onChange={setUsername} placeholder="e.g. admin" />
        <div>
          <label className="text-xs font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Password</label>
          <div className="relative mt-1.5">
            <input
              className="w-full rounded-xl bg-[var(--vc-panel-2)] border border-[var(--vc-border)] px-3 py-2.5 pr-16 text-sm text-[var(--vc-text)] placeholder:text-[var(--vc-muted-2)] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition font-mono"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              type={showPw ? 'text' : 'password'}
            />
            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-0.5">
              <button
                type="button"
                title="Generate password"
                onClick={() => { setPassword(generatePassword()); setShowPw(true); }}
                className="rounded-lg p-1.5 text-[var(--vc-muted)] hover:text-indigo-500 transition"
              >
                <IconWand />
              </button>
              <button
                type="button"
                onClick={() => setShowPw(!showPw)}
                className="rounded-lg p-1.5 text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
              >
                <IconEye off={showPw} />
              </button>
            </div>
          </div>
          {strength && password && (
            <div className="mt-2">
              <div className="flex gap-1">
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className={`h-1 flex-1 rounded-full transition-all ${i <= strength.score ? strength.color : 'bg-[var(--vc-border)]'}`} />
                ))}
              </div>
              <div className="mt-1 text-xs text-[var(--vc-muted-2)]">{strength.label}</div>
            </div>
          )}
        </div>
        <FormField label="Host / IP" value={host} onChange={setHost} placeholder="e.g. 192.168.1.1" />
        <FormField label="Login URL" value={url} onChange={setUrl} placeholder="https://example.com/login" />
        <button
          className="w-full rounded-xl bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white hover:bg-indigo-400 disabled:opacity-40 disabled:cursor-not-allowed transition"
          disabled={!title.trim()}
          onClick={handleSave}
        >
          {props.editingId ? 'Update Login' : 'Save Login'}
        </button>
      </div>
    </div>
  );
}

function FormField({ label, value, onChange, placeholder }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string;
}) {
  return (
    <div>
      <label className="text-xs font-semibold uppercase tracking-wide text-[var(--vc-muted)]">{label}</label>
      <input
        className="mt-1.5 w-full rounded-xl bg-[var(--vc-panel-2)] border border-[var(--vc-border)] px-3 py-2.5 text-sm text-[var(--vc-text)] placeholder:text-[var(--vc-muted-2)] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        type="text"
      />
    </div>
  );
}

function VaultScreen(props: {
  vault: VaultBlobV1;
  onUpsert: (form: { id?: string; title: string; host: string; username: string; password: string; url: string; category: string }) => void;
  onDelete: (id: string) => void;
  onImportCsv: (file: File) => Promise<void>;
  onLock: () => void;
  onLogout: () => void;
}) {
  const [search, setSearch] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [importOk, setImportOk] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [prefill, setPrefill] = useState<Partial<{ title: string; host: string; username: string; password: string; url: string; category: string }> | null>(null);
  const [theme, setThemeState] = useState<'light' | 'dark'>(() => (typeof document === 'undefined' ? 'dark' : getTheme()));

  const reuseMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const it of props.vault.items) {
      const pw = it.password;
      if (!pw) continue;
      map.set(pw, (map.get(pw) ?? 0) + 1);
    }
    return map;
  }, [props.vault.items]);

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    setThemeState(next);
  }

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return props.vault.items;
    return props.vault.items.filter((i) =>
      [i.title, i.username, i.url, i.host].some((f) => f?.toLowerCase().includes(q))
    );
  }, [props.vault.items, search]);

  return (
    <div className="min-h-screen bg-[var(--vc-bg)] text-[var(--vc-text)]">
      <header className="sticky top-0 z-10 border-b border-[var(--vc-border-2)] bg-[var(--vc-bg)]/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center gap-3 px-4 py-2.5">
          <div className="flex items-center gap-2 mr-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500 text-white">
              <IconShield />
            </div>
            <span className="font-bold text-[var(--vc-text)] hidden sm:block">VaultCode</span>
          </div>

          <div className="relative flex-1 max-w-sm">
            <div className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">
              <IconSearch />
            </div>
            <input
              className="w-full rounded-xl bg-[var(--vc-panel)] border border-[var(--vc-border)] pl-9 pr-3 py-2 text-sm text-[var(--vc-text)] placeholder:text-[var(--vc-muted-2)] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search logins…"
            />
          </div>

          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-panel)] p-2 text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
              onClick={toggleTheme}
              title="Toggle theme"
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? <IconSun /> : <IconMoon />}
            </button>
            <button
              type="button"
              className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-panel)] p-2 text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
              onClick={async () => {
                const csv = buildLoginsCsv(props.vault.items);
                const stamp = new Date().toISOString().slice(0, 10);
                const suggested = (typeof window !== 'undefined' && window.localStorage.getItem('pm_master_pw_hint')) || '';
                const pw = window.prompt('Set a password for the ZIP file (keep it safe).', suggested) ?? '';
                if (!pw) return;
                await downloadZipCsv(`vaultcode-logins-${stamp}.zip`, `vaultcode-logins-${stamp}.csv`, csv, pw);
              }}
              title="Export ZIP (Password)"
              aria-label="Export ZIP (Password)"
            >
              <IconDownload />
            </button>
            <label
              className="cursor-pointer rounded-xl border border-[var(--vc-border)] bg-[var(--vc-panel)] p-2 text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
              title="Import CSV"
              aria-label="Import CSV"
            >
              <IconUpload />
              <input
                type="file" accept="text/csv,.csv" className="hidden"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  setImportError(null); setImportOk(false);
                  try {
                    await props.onImportCsv(f);
                    e.target.value = '';
                    setImportOk(true);
                    setTimeout(() => setImportOk(false), 2500);
                  } catch {
                    setImportError('CSV import failed.');
                  }
                }}
              />
            </label>
            <button
              onClick={props.onLock}
              className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-panel)] px-3 py-2 text-xs font-medium text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
              title="Lock"
              aria-label="Lock"
            >
              Lock
            </button>
            <button
              onClick={props.onLogout}
              className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-panel)] p-2 text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition"
              title="Sign Out"
              aria-label="Sign Out"
            >
              <IconLogOut />
            </button>
          </div>
        </div>
      </header>

      {(importError || importOk) && (
        <div className={`mx-auto max-w-6xl px-4 pt-3`}>
          <div className={`rounded-xl px-4 py-3 text-sm ${importError ? 'bg-red-500/10 border border-red-500/20 text-red-400' : 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'}`}>
            {importError ?? `CSV imported successfully — ${props.vault.items.length} items total`}
          </div>
        </div>
      )}

      <main className={`mx-auto max-w-6xl px-4 py-6 ${editorOpen ? 'lg:pr-[420px]' : ''}`}>
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="font-semibold text-[var(--vc-text)]">
            Saved Logins
            <span className="ml-2 rounded-full bg-[var(--vc-panel-2)] px-2 py-0.5 text-xs text-[var(--vc-muted)]">
              {filtered.length}
            </span>
          </h2>

          <div className="flex items-center gap-2">
            {search && (
              <button onClick={() => setSearch('')} className="text-xs text-[var(--vc-muted)] hover:text-[var(--vc-text)] transition">
                Clear search
              </button>
            )}
            <button
              type="button"
              onClick={() => { setEditorOpen(true); setEditingId(null); setPrefill(null); }}
              className="rounded-xl bg-indigo-500 px-3 py-2 text-xs font-semibold text-white hover:bg-indigo-400 transition"
            >
              Add Login
            </button>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-[var(--vc-border)] py-16 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--vc-panel)] text-[var(--vc-muted)] mb-3">
              <IconLock />
            </div>
            <div className="text-sm font-medium text-[var(--vc-muted)]">
              {search ? 'No logins match your search' : 'No logins saved yet'}
            </div>
            <div className="mt-1 text-xs text-[var(--vc-muted-2)]">
              {search ? 'Try a different search term' : 'Add your first login using the button above'}
            </div>
          </div>
        ) : (
          <div className="space-y-1.5">
            {filtered.map((item) => (
              <VaultCard
                key={item.id}
                item={item}
                expanded={expandedId === item.id}
                onToggle={() => setExpandedId((cur) => (cur === item.id ? null : item.id))}
                onEdit={() => {
                  setEditorOpen(true);
                  setEditingId(item.id);
                  setPrefill({
                    title: item.title ?? '',
                    host: item.host ?? '',
                    username: item.username ?? '',
                    password: item.password ?? '',
                    url: item.url ?? '',
                    category: item.category ?? '',
                  });
                  if (expandedId !== item.id) setExpandedId(item.id);
                }}
                onDelete={() => props.onDelete(item.id)}
                health={{
                  isWeak: Boolean(item.password && (getStrength(item.password).score <= 2)),
                  reusedCount: item.password ? (reuseMap.get(item.password) ?? 0) : 0,
                  autoCategory: autoCategoryFor(item),
                }}
              />
            ))}
          </div>
        )}
      </main>

      {editorOpen && (
        <div className="fixed inset-0 z-20 lg:hidden">
          <button
            type="button"
            className="absolute inset-0 bg-black/40"
            onClick={() => { setEditorOpen(false); setEditingId(null); setPrefill(null); }}
            aria-label="Close editor"
          />
          <div className="absolute right-0 top-0 h-full w-[92%] max-w-md border-l border-[var(--vc-border)] bg-[var(--vc-bg)] p-4 overflow-y-auto">
            <AddLoginForm
              onSave={(form) => {
                props.onUpsert(form);
                setEditorOpen(false);
                setEditingId(null);
                setPrefill(null);
              }}
              prefill={prefill}
              editingId={editingId}
              onCancel={() => { setEditorOpen(false); setEditingId(null); setPrefill(null); }}
            />
          </div>
        </div>
      )}

      {editorOpen && (
        <div className="hidden lg:block fixed right-0 top-14 z-20 h-[calc(100vh-3.5rem)] w-[420px] border-l border-[var(--vc-border)] bg-[var(--vc-bg)] p-4 overflow-y-auto">
          <AddLoginForm
            onSave={(form) => {
              props.onUpsert(form);
              setEditorOpen(false);
              setEditingId(null);
              setPrefill(null);
            }}
            prefill={prefill}
            editingId={editingId}
            onCancel={() => { setEditorOpen(false); setEditingId(null); setPrefill(null); }}
          />
        </div>
      )}
    </div>
  );
}

// ── Root ───────────────────────────────────────────────────────────────────

export default function Home() {
  const [token, setToken] = useState<string | null>(null);
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authBusy, setAuthBusy] = useState(false);

  const [masterPassword, setMasterPassword] = useState('');
  const [unlockPassword, setUnlockPassword] = useState('');
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [vault, setVault] = useState<VaultBlobV1 | null>(null);
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [remoteEncryptedVault, setRemoteEncryptedVault] = useState<EncryptedVaultV1 | null>(null);
  const [loadingVault, setLoadingVault] = useState(false);

  const hasRemoteVault = useMemo(() => Boolean(remoteEncryptedVault), [remoteEncryptedVault]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const t = window.localStorage.getItem(TOKEN_KEY);
    if (t) setToken(t);
  }, []);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    setLoadingVault(true);
    apiGetVault(token)
      .then((v) => {
        if (cancelled) return;
        setRemoteEncryptedVault(v?.encryptedVault ? v.encryptedVault as EncryptedVaultV1 : null);
      })
      .catch(() => { if (!cancelled) setRemoteEncryptedVault(null); })
      .finally(() => { if (!cancelled) setLoadingVault(false); });
    return () => { cancelled = true; };
  }, [token]);

  async function persist(nextVault: VaultBlobV1, pwd: string) {
    if (!token) return;
    const payload = encryptVault({ ...nextVault, updatedAt: nowIso() }, pwd);
    setRemoteEncryptedVault(payload);
    await apiPutVault(token, payload, 1);
  }

  async function handleAuthSubmit() {
    setAuthError(null);
    if (!authEmail.trim() || !authPassword) { setAuthError('Email and password required.'); return; }
    setAuthBusy(true);
    try {
      const resp = authMode === 'register'
        ? await apiRegister(authEmail.trim(), authPassword)
        : await apiLogin(authEmail.trim(), authPassword);
      window.localStorage.setItem(TOKEN_KEY, resp.token);
      setToken(resp.token);
      setAuthPassword('');
    } catch (e) {
      setAuthError(e instanceof Error ? e.message : 'Auth failed');
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleCreateVault() {
    setUnlockError(null);
    if (!masterPassword || masterPassword.length < 4) { setUnlockError('Master password minimum 4 characters.'); return; }
    const empty = createEmptyVault();
    await persist(empty, masterPassword);
    setVault(empty);
    setIsUnlocked(true);
    setMasterPassword('');
  }

  function handleUnlock() {
    setUnlockError(null);
    if (!remoteEncryptedVault) { setUnlockError('No vault found. Create new vault.'); return; }
    try {
      const decrypted = decryptVault(remoteEncryptedVault, unlockPassword);
      setVault(decrypted);
      setMasterPassword(unlockPassword);
      setIsUnlocked(true);
      setUnlockPassword('');
    } catch {
      setUnlockError('Wrong master password.');
    }
  }

  function handleLock() {
    setIsUnlocked(false);
    setVault(null);
    setMasterPassword('');
  }

  function handleLogout() {
    window.localStorage.removeItem(TOKEN_KEY);
    setToken(null); setRemoteEncryptedVault(null); setIsUnlocked(false);
    setVault(null); setMasterPassword(''); setUnlockPassword('');
    setAuthEmail(''); setAuthPassword(''); setAuthError(null);
  }

  async function handleUpsertLogin(form: { id?: string; title: string; host: string; username: string; password: string; url: string; category: string }) {
    if (!vault) return;
    const t = nowIso();
    const nextItems = form.id
      ? vault.items.map((i) => i.id !== form.id ? i : ({
        ...i,
        title: form.title,
        host: form.host || undefined,
        username: form.username || undefined,
        password: form.password || undefined,
        url: form.url || undefined,
        category: form.category || undefined,
        updatedAt: t,
      }))
      : ([{
        id: newId(), type: 'login' as const, title: form.title,
        host: form.host || undefined, username: form.username || undefined,
        password: form.password || undefined, url: form.url || undefined,
        category: form.category || undefined,
        createdAt: t, updatedAt: t,
      }, ...vault.items]);
    const next = { ...vault, updatedAt: t, items: nextItems };
    setVault(next);
    await persist(next, masterPassword);
  }

  async function handleDelete(id: string) {
    if (!vault) return;
    const next = { ...vault, updatedAt: nowIso(), items: vault.items.filter((i) => i.id !== id) };
    setVault(next);
    await persist(next, masterPassword);
  }

  async function handleImportCsv(file: File) {
    if (!vault) return;
    const rows = parseCsv(await file.text());
    const items: VaultItem[] = rows.map((r) => {
      const title = r['Title'] ?? r['title'] ?? '';
      const host = r['Host'] ?? r['host'] ?? '';
      const username = r['Username'] ?? r['username'] ?? '';
      const password = r['Password'] ?? r['password'] ?? '';
      const url = r['Login URL'] ?? r['login url'] ?? r['url'] ?? '';
      if (!title && !username && !password && !url && !host) return null;
      const t = nowIso();
      const autoCat = autoCategoryFor({ title, host, url });
      return { id: newId(), type: 'login' as const, title: title || '(no title)', host: host || undefined, username: username || undefined, password: password || undefined, url: url || undefined, category: autoCat || undefined, createdAt: t, updatedAt: t };
    }).filter(Boolean) as VaultItem[];
    const next = { ...vault, updatedAt: nowIso(), items: [...items, ...vault.items] };
    setVault(next);
    await persist(next, masterPassword);
  }

  if (!token) {
    return (
      <AuthScreen
        mode={authMode} setMode={setAuthMode}
        email={authEmail} setEmail={setAuthEmail}
        password={authPassword} setPassword={setAuthPassword}
        error={authError} busy={authBusy}
        onSubmit={() => void handleAuthSubmit()}
        onToken={(t) => { setToken(t); setAuthPassword(''); }}
      />
    );
  }

  if (!isUnlocked) {
    return (
      <UnlockScreen
        hasVault={hasRemoteVault} loading={loadingVault}
        password={hasRemoteVault ? unlockPassword : masterPassword}
        setPassword={hasRemoteVault ? setUnlockPassword : setMasterPassword}
        error={unlockError}
        onUnlock={handleUnlock}
        onCreate={() => void handleCreateVault()}
        onLogout={handleLogout}
      />
    );
  }

  return (
    <VaultScreen
      vault={vault ?? createEmptyVault()}
      onLock={handleLock}
      onUpsert={(form) => void handleUpsertLogin(form)}
      onDelete={(id) => void handleDelete(id)}
      onImportCsv={handleImportCsv}
      onLogout={handleLogout}
    />
  );
}
