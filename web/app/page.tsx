"use client";

import { useEffect, useMemo, useState, useCallback } from 'react';
import { createEmptyVault, decryptVault, encryptVault } from '../lib/vault';
import type { EncryptedVaultV1, VaultBlobV1, VaultItem } from '../lib/vault';
import { apiGetVault, apiLogin, apiPutVault, apiRegister } from '../lib/api';

const TOKEN_KEY = 'pm_token_v1';

function nowIso() { return new Date().toISOString(); }

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
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M15 4V2M15 16v-2M8 9h2M20 9h2M17.8 11.8L19 13M17.8 6.2L19 5M3 21l9-9M12.2 6.2L11 5" />
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
}) {
  const [showPw, setShowPw] = useState(false);
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-500 text-white shadow-lg shadow-indigo-500/30">
            <IconShield />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-white">VaultCode</h1>
          <p className="mt-1 text-sm text-slate-400">End-to-end encrypted password manager</p>
        </div>

        <div className="rounded-2xl bg-slate-800 border border-slate-700 p-6 shadow-2xl">
          <div className="mb-5 flex rounded-xl bg-slate-900 p-1">
            {(['login', 'register'] as const).map((m) => (
              <button
                key={m}
                onClick={() => props.setMode(m)}
                className={`flex-1 rounded-lg py-2 text-sm font-medium transition-all ${
                  props.mode === m
                    ? 'bg-indigo-500 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
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
                className="mt-1.5 w-full rounded-xl bg-slate-900 border border-slate-700 px-3 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
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
                  className="w-full rounded-xl bg-slate-900 border border-slate-700 px-3 py-2.5 pr-10 text-sm text-white placeholder-slate-500 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
                  value={props.password}
                  onChange={(e) => props.setPassword(e.target.value)}
                  placeholder="••••••••"
                  type={showPw ? 'text' : 'password'}
                  onKeyDown={(e) => e.key === 'Enter' && props.onSubmit()}
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-500 text-white shadow-lg shadow-indigo-500/30">
            <IconShield />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-white">VaultCode</h1>
          <p className="mt-1 text-sm text-slate-400">
            {props.hasVault ? 'Enter your master password to unlock' : 'Create a master password for your vault'}
          </p>
        </div>

        <div className="rounded-2xl bg-slate-800 border border-slate-700 p-6 shadow-2xl">
          <div className="mb-5 flex items-center gap-3 rounded-xl bg-slate-900 px-4 py-3">
            <div className="text-indigo-400"><IconLock /></div>
            <div>
              <div className="text-sm font-semibold text-white">
                {props.hasVault ? 'Vault Locked' : 'New Vault'}
              </div>
              <div className="text-xs text-slate-500">
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
            <div className="py-6 text-center text-sm text-slate-500">Loading vault…</div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                  Master Password
                </label>
                <div className="relative mt-1.5">
                  <input
                    autoFocus
                    className="w-full rounded-xl bg-slate-900 border border-slate-700 px-3 py-2.5 pr-10 text-sm text-white placeholder-slate-500 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
                    type={showPw ? 'text' : 'password'}
                    value={props.password}
                    onChange={(e) => props.setPassword(e.target.value)}
                    placeholder="Enter master password"
                    onKeyDown={(e) => e.key === 'Enter' && (props.hasVault ? props.onUnlock() : props.onCreate())}
                  />
                  <button
                    type="button"
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                    onClick={() => setShowPw(!showPw)}
                  >
                    <IconEye off={showPw} />
                  </button>
                </div>
                {!props.hasVault && props.password && strength && (
                  <div className="mt-2">
                    <div className="flex gap-1">
                      {[1, 2, 3, 4, 5].map((i) => (
                        <div key={i} className={`h-1 flex-1 rounded-full transition-all ${i <= strength.score ? strength.color : 'bg-slate-700'}`} />
                      ))}
                    </div>
                    <div className="mt-1 text-xs text-slate-500">{strength.label}</div>
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
                className="w-full rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm font-medium text-slate-400 hover:text-slate-200 transition"
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
  onPrefill: () => void;
}) {
  const [revealed, setRevealed] = useState(false);
  const { copied, copy } = useCopy();
  const initials = (props.item.title || '?').slice(0, 2).toUpperCase();
  const color = avatarColor(props.item.title);

  return (
    <div className="group rounded-xl bg-slate-800 border border-slate-700 p-3 hover:border-slate-600 transition">
      <div className="flex items-start gap-2.5">
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-sm font-bold text-white ${color}`}>
          {initials}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <div className="truncate font-semibold text-white">{props.item.title}</div>
              {props.item.host && (
                <div className="text-xs text-slate-500 truncate">{props.item.host}</div>
              )}
            </div>
            <div className="shrink-0 flex items-center gap-1">
              {props.item.url && (
                <button
                  onClick={() => {
                    props.onPrefill();
                    window.open(props.item.url!, '_blank', 'noopener,noreferrer');
                  }}
                  className="rounded-lg p-1 text-slate-500 hover:text-slate-300 hover:bg-slate-700 transition"
                  title="Open"
                  type="button"
                >
                  <IconExternalLink />
                </button>
              )}
              <button
                onClick={() => {
                  props.onPrefill();
                  props.onToggle();
                }}
                className="rounded-lg p-1 text-slate-500 hover:text-slate-300 hover:bg-slate-700 transition"
                title={props.expanded ? 'Collapse' : 'Expand'}
                type="button"
              >
                <IconChevronDown className={props.expanded ? 'rotate-180 transition-transform' : 'transition-transform'} />
              </button>
              <button
                onClick={props.onDelete}
                className="rounded-lg p-1 text-slate-600 opacity-0 group-hover:opacity-100 hover:bg-red-500/10 hover:text-red-400 transition"
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
              <div className="flex items-center justify-between rounded-lg bg-slate-900 px-2.5 py-1.5">
                <div className="min-w-0">
                  <div className="text-[11px] text-slate-500">Username</div>
                  <div className="text-xs text-slate-300 truncate">{props.item.username}</div>
                </div>
                <button
                  onClick={() => copy(props.item.username!, `${props.item.id}-user`)}
                  className={`ml-2 shrink-0 rounded-lg p-1 transition ${copied === `${props.item.id}-user` ? 'text-emerald-400' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-700'}`}
                  type="button"
                >
                  <IconCopy done={copied === `${props.item.id}-user`} />
                </button>
              </div>
            )}

            {props.item.password && (
              <div className="flex items-center justify-between rounded-lg bg-slate-900 px-2.5 py-1.5">
                <div className="min-w-0 flex-1">
                  <div className="text-[11px] text-slate-500">Password</div>
                  <div className="font-mono text-xs text-slate-300 truncate">
                    {revealed ? props.item.password : '••••••••••••'}
                  </div>
                </div>
                <div className="ml-2 flex shrink-0 items-center gap-1">
                  <button
                    onClick={() => setRevealed(!revealed)}
                    className="rounded-lg p-1 text-slate-500 hover:text-slate-300 hover:bg-slate-700 transition"
                    type="button"
                  >
                    <IconEye off={revealed} />
                  </button>
                  <button
                    onClick={() => copy(props.item.password!, `${props.item.id}-pw`)}
                    className={`rounded-lg p-1 transition ${copied === `${props.item.id}-pw` ? 'text-emerald-400' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-700'}`}
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
                className="flex items-center gap-2 rounded-lg bg-slate-900 px-2.5 py-1.5 text-[11px] text-indigo-400 hover:text-indigo-300 transition truncate"
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
  onAdd: (form: { title: string; host: string; username: string; password: string; url: string }) => void;
  prefill?: Partial<{ title: string; host: string; username: string; password: string; url: string }> | null;
}) {
  const [title, setTitle] = useState('');
  const [host, setHost] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');
  const [showPw, setShowPw] = useState(false);
  const strength = password ? getStrength(password) : null;

  useEffect(() => {
    if (!props.prefill) return;
    if (typeof props.prefill.title === 'string') setTitle(props.prefill.title);
    if (typeof props.prefill.host === 'string') setHost(props.prefill.host);
    if (typeof props.prefill.username === 'string') setUsername(props.prefill.username);
    if (typeof props.prefill.password === 'string') { setPassword(props.prefill.password); setShowPw(true); }
    if (typeof props.prefill.url === 'string') setUrl(props.prefill.url);
  }, [props.prefill]);

  function handleSave() {
    if (!title.trim()) return;
    props.onAdd({ title, host, username, password, url });
    setTitle(''); setHost(''); setUsername(''); setPassword(''); setUrl('');
  }

  return (
    <div className="rounded-2xl bg-slate-800 border border-slate-700 p-5">
      <div className="mb-4 flex items-center gap-2">
        <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-500/20 text-indigo-400">
          <IconPlus />
        </div>
        <h2 className="font-semibold text-white">Add New Login</h2>
      </div>
      <div className="space-y-3">
        <FormField label="Title" value={title} onChange={setTitle} placeholder="e.g. Gmail" />
        <FormField label="Username / Email" value={username} onChange={setUsername} placeholder="e.g. admin" />
        <div>
          <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">Password</label>
          <div className="relative mt-1.5">
            <input
              className="w-full rounded-xl bg-slate-900 border border-slate-700 px-3 py-2.5 pr-16 text-sm text-white placeholder-slate-500 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition font-mono"
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
                className="rounded-lg p-1.5 text-slate-500 hover:text-indigo-400 transition"
              >
                <IconWand />
              </button>
              <button
                type="button"
                onClick={() => setShowPw(!showPw)}
                className="rounded-lg p-1.5 text-slate-500 hover:text-slate-300 transition"
              >
                <IconEye off={showPw} />
              </button>
            </div>
          </div>
          {strength && password && (
            <div className="mt-2">
              <div className="flex gap-1">
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className={`h-1 flex-1 rounded-full transition-all ${i <= strength.score ? strength.color : 'bg-slate-700'}`} />
                ))}
              </div>
              <div className="mt-1 text-xs text-slate-500">{strength.label}</div>
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
          Save Login
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
      <label className="text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</label>
      <input
        className="mt-1.5 w-full rounded-xl bg-slate-900 border border-slate-700 px-3 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        type="text"
      />
    </div>
  );
}

// ── Vault Screen ───────────────────────────────────────────────────────────

function VaultScreen(props: {
  vault: VaultBlobV1;
  onLock: () => void;
  onAdd: (form: { title: string; host: string; username: string; password: string; url: string }) => void;
  onDelete: (id: string) => void;
  onImportCsv: (file: File) => Promise<void>;
  onLogout: () => void;
}) {
  const [search, setSearch] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [importOk, setImportOk] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [prefill, setPrefill] = useState<Partial<{ title: string; host: string; username: string; password: string; url: string }> | null>(null);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return props.vault.items;
    return props.vault.items.filter((i) =>
      [i.title, i.username, i.url, i.host].some((f) => f?.toLowerCase().includes(q))
    );
  }, [props.vault.items, search]);

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      <header className="sticky top-0 z-10 border-b border-slate-700/60 bg-slate-900/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center gap-3 px-4 py-3">
          <div className="flex items-center gap-2 mr-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500 text-white">
              <IconShield />
            </div>
            <span className="font-bold text-white hidden sm:block">VaultCode</span>
          </div>

          <div className="relative flex-1 max-w-sm">
            <div className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">
              <IconSearch />
            </div>
            <input
              className="w-full rounded-xl bg-slate-800 border border-slate-700 pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search logins…"
            />
          </div>

          <div className="ml-auto flex items-center gap-2">
            <label className="cursor-pointer rounded-xl border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-medium text-slate-300 hover:border-slate-600 hover:text-white transition">
              Import CSV
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
              className="rounded-xl border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-medium text-slate-300 hover:border-slate-600 hover:text-white transition"
            >
              Lock
            </button>
            <button
              onClick={props.onLogout}
              className="rounded-xl border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-medium text-slate-300 hover:border-slate-600 hover:text-white transition"
            >
              Sign Out
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

      <main className="mx-auto max-w-6xl px-4 py-6">
        <div className="grid gap-6 lg:grid-cols-5">
          <div className="lg:col-span-2">
            <AddLoginForm onAdd={props.onAdd} prefill={prefill} />
          </div>

          <div className="lg:col-span-3">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="font-semibold text-white">
                Saved Logins
                <span className="ml-2 rounded-full bg-slate-700 px-2 py-0.5 text-xs text-slate-400">
                  {filtered.length}
                </span>
              </h2>
              {search && (
                <button onClick={() => setSearch('')} className="text-xs text-slate-500 hover:text-slate-300">
                  Clear search
                </button>
              )}
            </div>

            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-700 py-16 text-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-800 text-slate-500 mb-3">
                  <IconLock />
                </div>
                <div className="text-sm font-medium text-slate-400">
                  {search ? 'No logins match your search' : 'No logins saved yet'}
                </div>
                <div className="mt-1 text-xs text-slate-600">
                  {search ? 'Try a different search term' : 'Add your first login using the form'}
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                {filtered.map((item) => (
                  <VaultCard
                    key={item.id}
                    item={item}
                    expanded={expandedId === item.id}
                    onToggle={() => setExpandedId((cur) => (cur === item.id ? null : item.id))}
                    onPrefill={() => setPrefill({
                      title: item.title ?? '',
                      host: item.host ?? '',
                      username: item.username ?? '',
                      password: item.password ?? '',
                      url: item.url ?? '',
                    })}
                    onDelete={() => props.onDelete(item.id)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      </main>
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

  async function handleAddLogin(form: { title: string; host: string; username: string; password: string; url: string }) {
    if (!vault) return;
    const item: VaultItem = {
      id: newId(), type: 'login', title: form.title,
      host: form.host || undefined, username: form.username || undefined,
      password: form.password || undefined, url: form.url || undefined,
      createdAt: nowIso(), updatedAt: nowIso(),
    };
    const next = { ...vault, updatedAt: nowIso(), items: [item, ...vault.items] };
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
      return { id: newId(), type: 'login' as const, title: title || '(no title)', host: host || undefined, username: username || undefined, password: password || undefined, url: url || undefined, createdAt: t, updatedAt: t };
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
      onAdd={(form) => void handleAddLogin(form)}
      onDelete={(id) => void handleDelete(id)}
      onImportCsv={handleImportCsv}
      onLogout={handleLogout}
    />
  );
}
