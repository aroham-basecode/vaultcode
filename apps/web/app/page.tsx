"use client";

import { useEffect, useMemo, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { createEmptyVault, decryptVault, encryptVault } from '@pm/shared';
import type { EncryptedVaultV1, VaultBlobV1, VaultItem } from '@pm/shared';
import { apiGetVault, apiLogin, apiPutVault, apiRegister } from '../lib/api';

const TOKEN_KEY = 'pm_token_v1';

function safeJsonParse<T>(value: string | null): T | null {
  if (!value) return null;
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === ',' && !inQuotes) {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

function parseCsv(text: string): Array<Record<string, string>> {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length < 2) return [];

  const headers = parseCsvLine(lines[0]!).map((h) => h.replace(/^"|"$/g, ''));
  const rows: Array<Record<string, string>> = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = parseCsvLine(lines[i]!);
    const row: Record<string, string> = {};
    for (let j = 0; j < headers.length; j++) {
      const key = headers[j] ?? `col_${j}`;
      row[key] = cols[j] ?? '';
    }
    rows.push(row);
  }
  return rows;
}

function nowIso() {
  return new Date().toISOString();
}

function newId() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

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
  const [reveal, setReveal] = useState<Record<string, boolean>>({});
  const [remoteEncryptedVault, setRemoteEncryptedVault] = useState<EncryptedVaultV1 | null>(null);
  const [loadingVault, setLoadingVault] = useState(false);

  const hasRemoteVault = useMemo(() => Boolean(remoteEncryptedVault), [remoteEncryptedVault]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const existingToken = window.localStorage.getItem(TOKEN_KEY);
    if (existingToken) setToken(existingToken);
  }, []);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    setLoadingVault(true);
    setRemoteEncryptedVault(null);
    apiGetVault(token)
      .then((v) => {
        if (cancelled) return;
        if (v?.encryptedVault) setRemoteEncryptedVault(v.encryptedVault as EncryptedVaultV1);
        else setRemoteEncryptedVault(null);
      })
      .catch(() => {
        if (cancelled) return;
        setRemoteEncryptedVault(null);
      })
      .finally(() => {
        if (cancelled) return;
        setLoadingVault(false);
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  async function persist(nextVault: VaultBlobV1, pwd: string) {
    if (!token) return;
    const payload = encryptVault({ ...nextVault, updatedAt: nowIso() }, pwd);
    setRemoteEncryptedVault(payload);
    await apiPutVault(token, payload, 1);
  }

  async function handleCreateVault() {
    setUnlockError(null);
    if (!masterPassword || masterPassword.length < 4) {
      setUnlockError('Master password minimum 4 characters.');
      return;
    }
    const empty = createEmptyVault();
    await persist(empty, masterPassword);
    setVault(empty);
    setIsUnlocked(true);
    setMasterPassword('');
  }

  function handleUnlock() {
    setUnlockError(null);
    if (!remoteEncryptedVault) {
      setUnlockError('No vault found. Create new vault.');
      return;
    }
    try {
      const decrypted = decryptVault(remoteEncryptedVault, unlockPassword);
      setVault(decrypted);
      setIsUnlocked(true);
      setUnlockPassword('');
    } catch {
      setUnlockError('Wrong master password.');
    }
  }

  function handleLock() {
    setIsUnlocked(false);
    setVault(null);
    setReveal({});
  }

  async function handleAddLogin(form: { title: string; host: string; username: string; password: string; url: string }) {
    if (!vault) return;
    const item: VaultItem = {
      id: newId(),
      type: 'login',
      title: form.title,
      host: form.host || undefined,
      username: form.username || undefined,
      password: form.password || undefined,
      url: form.url || undefined,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };
    const next: VaultBlobV1 = {
      ...vault,
      updatedAt: nowIso(),
      items: [item, ...vault.items],
    };
    setVault(next);
    await persist(next, masterPassword);
  }

  async function handleDelete(id: string) {
    if (!vault) return;
    const next: VaultBlobV1 = {
      ...vault,
      updatedAt: nowIso(),
      items: vault.items.filter((i) => i.id !== id),
    };
    setVault(next);
    await persist(next, masterPassword);
    setReveal((r) => {
      const { [id]: _, ...rest } = r;
      return rest;
    });
  }

  async function handleImportCsv(file: File) {
    if (!vault) return;
    const text = await file.text();
    const rows = parseCsv(text);
    const items: VaultItem[] = rows
      .map((r) => {
        const title = r['Title'] ?? r['title'] ?? '';
        const host = r['Host'] ?? r['host'] ?? '';
        const username = r['Username'] ?? r['username'] ?? '';
        const password = r['Password'] ?? r['password'] ?? '';
        const url = r['Login URL'] ?? r['login url'] ?? r['url'] ?? '';
        if (!title && !username && !password && !url && !host) return null;
        const t = nowIso();
        return {
          id: newId(),
          type: 'login',
          title: title || '(no title)',
          host: host || undefined,
          username: username || undefined,
          password: password || undefined,
          url: url || undefined,
          createdAt: t,
          updatedAt: t,
        } as VaultItem;
      })
      .filter(Boolean) as VaultItem[];

    const next: VaultBlobV1 = {
      ...vault,
      updatedAt: nowIso(),
      items: [...items, ...vault.items],
    };
    setVault(next);
    await persist(next, masterPassword);
  }

  function handleLogout() {
    window.localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setRemoteEncryptedVault(null);
    setIsUnlocked(false);
    setVault(null);
    setReveal({});
    setMasterPassword('');
    setUnlockPassword('');
    setAuthEmail('');
    setAuthPassword('');
    setAuthError(null);
  }

  async function handleAuthSubmit() {
    setAuthError(null);
    if (!authEmail.trim() || !authPassword) {
      setAuthError('Email and password required.');
      return;
    }
    setAuthBusy(true);
    try {
      const resp =
        authMode === 'register'
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

  if (!token) {
    return (
      <div className="min-h-screen bg-zinc-50 text-zinc-900">
        <div className="mx-auto max-w-xl px-4 py-14">
          <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm">
            <div className="mb-6">
              <h1 className="text-2xl font-semibold tracking-tight">Password Manager</h1>
              <p className="mt-1 text-sm text-zinc-600">Login/Register to continue</p>
            </div>

            <div className="mb-4 grid grid-cols-2 gap-2">
              <button
                className={`rounded-xl px-4 py-2 text-sm font-medium ${
                  authMode === 'login' ? 'bg-zinc-900 text-white' : 'border border-zinc-200 bg-white text-zinc-900'
                }`}
                onClick={() => setAuthMode('login')}
              >
                Login
              </button>
              <button
                className={`rounded-xl px-4 py-2 text-sm font-medium ${
                  authMode === 'register'
                    ? 'bg-zinc-900 text-white'
                    : 'border border-zinc-200 bg-white text-zinc-900'
                }`}
                onClick={() => setAuthMode('register')}
              >
                Register
              </button>
            </div>

            {authError ? (
              <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                {authError}
              </div>
            ) : null}

            <div className="space-y-3">
              <div>
                <label className="text-sm font-medium">Email</label>
                <input
                  className="mt-1 w-full rounded-xl border border-zinc-200 px-3 py-2 outline-none focus:ring-2 focus:ring-zinc-900/10"
                  value={authEmail}
                  onChange={(e) => setAuthEmail(e.target.value)}
                  placeholder="you@example.com"
                  type="email"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Password</label>
                <input
                  className="mt-1 w-full rounded-xl border border-zinc-200 px-3 py-2 outline-none focus:ring-2 focus:ring-zinc-900/10"
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  placeholder="Password"
                  type="password"
                />
              </div>

              <button
                className="w-full rounded-xl bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-60"
                disabled={authBusy}
                onClick={() => void handleAuthSubmit()}
              >
                {authMode === 'login' ? 'Login' : 'Create Account'}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!isUnlocked) {
    return (
      <div className="min-h-screen bg-zinc-50 text-zinc-900">
        <div className="mx-auto max-w-xl px-4 py-14">
          <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm">
            <div className="mb-6">
              <h1 className="text-2xl font-semibold tracking-tight">Password Manager</h1>
              <p className="mt-1 text-sm text-zinc-600">Vault unlock (encrypted on server)</p>
            </div>

            {unlockError ? (
              <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                {unlockError}
              </div>
            ) : null}

            {loadingVault ? (
              <div className="text-sm text-zinc-600">Loading vault...</div>
            ) : !hasRemoteVault ? (
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium">Create master password</label>
                  <input
                    className="mt-1 w-full rounded-xl border border-zinc-200 px-3 py-2 outline-none focus:ring-2 focus:ring-zinc-900/10"
                    type="password"
                    value={masterPassword}
                    onChange={(e) => setMasterPassword(e.target.value)}
                    placeholder="Master password"
                  />
                </div>
                <button
                  className="w-full rounded-xl bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-zinc-800"
                  onClick={() => void handleCreateVault()}
                >
                  Create Vault
                </button>
                <button
                  className="w-full rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-900 hover:bg-zinc-50"
                  onClick={handleLogout}
                >
                  Logout
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium">Enter master password</label>
                  <input
                    className="mt-1 w-full rounded-xl border border-zinc-200 px-3 py-2 outline-none focus:ring-2 focus:ring-zinc-900/10"
                    type="password"
                    value={unlockPassword}
                    onChange={(e) => setUnlockPassword(e.target.value)}
                    placeholder="Master password"
                  />
                </div>
                <button
                  className="w-full rounded-xl bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-zinc-800"
                  onClick={() => {
                    setMasterPassword(unlockPassword);
                    handleUnlock();
                  }}
                >
                  Unlock
                </button>
                <button
                  className="w-full rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-900 hover:bg-zinc-50"
                  onClick={handleLogout}
                >
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <VaultScreen
      vault={vault ?? createEmptyVault()}
      onLock={() => void handleLock()}
      onAdd={(form) => void handleAddLogin(form)}
      onDelete={(id) => void handleDelete(id)}
      reveal={reveal}
      setReveal={setReveal}
      onImportCsv={(file) => handleImportCsv(file)}
      onLogout={handleLogout}
    />
  );
}

function VaultScreen(props: {
  vault: VaultBlobV1;
  onLock: () => void;
  onAdd: (form: { title: string; host: string; username: string; password: string; url: string }) => void;
  onDelete: (id: string) => void;
  reveal: Record<string, boolean>;
  setReveal: Dispatch<SetStateAction<Record<string, boolean>>>;
  onImportCsv: (file: File) => Promise<void>;
  onLogout: () => void;
}) {
  const [title, setTitle] = useState('');
  const [host, setHost] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');
  const [importError, setImportError] = useState<string | null>(null);

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900">
      <div className="mx-auto max-w-5xl px-4 py-10">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Vault</h1>
            <p className="mt-1 text-sm text-zinc-600">Items: {props.vault.items.length}</p>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <label className="inline-flex cursor-pointer items-center justify-center rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-medium hover:bg-zinc-50">
              Import CSV
              <input
                type="file"
                accept="text/csv,.csv"
                className="hidden"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  setImportError(null);
                  try {
                    await props.onImportCsv(f);
                    e.target.value = '';
                  } catch {
                    setImportError('CSV import failed.');
                  }
                }}
              />
            </label>
            <button
              className="rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-medium hover:bg-zinc-50"
              onClick={props.onLock}
            >
              Lock
            </button>
            <button
              className="rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-medium hover:bg-zinc-50"
              onClick={props.onLogout}
            >
              Logout
            </button>
          </div>
        </div>

        {importError ? (
          <div className="mt-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {importError}
          </div>
        ) : null}

        <div className="mt-6 grid gap-6 lg:grid-cols-5">
          <div className="lg:col-span-2">
            <div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
              <h2 className="text-lg font-semibold">Add Login</h2>
              <div className="mt-4 space-y-3">
                <Field label="Title" value={title} onChange={setTitle} placeholder="e.g. MS_Travall" />
                <Field label="Host" value={host} onChange={setHost} placeholder="e.g. 185.161.18.37" />
                <Field label="Username" value={username} onChange={setUsername} placeholder="e.g. admin" />
                <Field label="Password" value={password} onChange={setPassword} placeholder="" type="password" />
                <Field label="Login URL" value={url} onChange={setUrl} placeholder="e.g. https://example.com/login" />

                <button
                  className="w-full rounded-xl bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-60"
                  disabled={!title.trim()}
                  onClick={() => {
                    props.onAdd({ title, host, username, password, url });
                    setTitle('');
                    setHost('');
                    setUsername('');
                    setPassword('');
                    setUrl('');
                  }}
                >
                  Save
                </button>
              </div>
            </div>
          </div>

          <div className="lg:col-span-3">
            <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm">
              <div className="border-b border-zinc-200 px-5 py-4">
                <h2 className="text-lg font-semibold">Saved Logins</h2>
              </div>
              <div className="divide-y divide-zinc-200">
                {props.vault.items.length === 0 ? (
                  <div className="px-5 py-10 text-center text-sm text-zinc-600">No items yet.</div>
                ) : (
                  props.vault.items.map((item) => (
                    <div key={item.id} className="px-5 py-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate text-sm font-semibold">{item.title}</div>
                          <div className="mt-1 text-xs text-zinc-600">
                            {item.username ? `User: ${item.username}` : 'User: —'}
                          </div>
                          <div className="mt-1 text-xs text-zinc-600">
                            {item.url ? (
                              <a className="underline" href={item.url} target="_blank" rel="noreferrer">
                                {item.url}
                              </a>
                            ) : (
                              'URL: —'
                            )}
                          </div>
                        </div>

                        <div className="flex shrink-0 flex-col items-end gap-2">
                          <button
                            className="rounded-lg border border-zinc-200 bg-white px-3 py-1.5 text-xs font-medium hover:bg-zinc-50"
                            onClick={() =>
                              props.setReveal((r) => ({
                                ...r,
                                [item.id]: !r[item.id],
                              }))
                            }
                          >
                            {props.reveal[item.id] ? 'Hide' : 'Reveal'}
                          </button>
                          <button
                            className="rounded-lg border border-red-200 bg-white px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-50"
                            onClick={() => props.onDelete(item.id)}
                          >
                            Delete
                          </button>
                        </div>
                      </div>

                      <div className="mt-3">
                        <div className="text-xs text-zinc-600">Password</div>
                        <div className="mt-1 rounded-xl border border-zinc-200 bg-zinc-50 px-3 py-2 font-mono text-sm">
                          {props.reveal[item.id] ? item.password || '' : item.password ? '••••••••' : ''}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Field(props: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <div>
      <label className="text-sm font-medium">{props.label}</label>
      <input
        className="mt-1 w-full rounded-xl border border-zinc-200 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-900/10"
        value={props.value}
        onChange={(e) => props.onChange(e.target.value)}
        placeholder={props.placeholder}
        type={props.type ?? 'text'}
      />
    </div>
  );
}
