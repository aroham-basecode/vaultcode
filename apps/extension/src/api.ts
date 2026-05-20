import type { EncryptedVaultV1, VaultBlobV1 } from '@shared/vault/types';

export async function apiGetVault(apiBase: string, token: string): Promise<{ encryptedVault: EncryptedVaultV1 | null; version: number | null }> {
  const res = await fetch(`${apiBase.replace(/\/$/, '')}/vault`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`Get vault failed (${res.status})`);
  const data = (await res.json()) as any;
  return {
    encryptedVault: (data?.encryptedVault as EncryptedVaultV1 | undefined) ?? null,
    version: typeof data?.version === 'number' ? data.version : null,
  };
}

export async function apiPutVault(apiBase: string, token: string, encryptedVault: EncryptedVaultV1, version: number): Promise<void> {
  const res = await fetch(`${apiBase.replace(/\/$/, '')}/vault`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ encryptedVault, version }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Put vault failed (${res.status}) ${text}`);
  }
}

export function hostFromUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

export function titleFromHost(host: string): string {
  if (!host) return 'Login';
  const parts = host.split('.').filter(Boolean);
  if (parts.length === 0) return host;
  const core = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  return core ? core.charAt(0).toUpperCase() + core.slice(1) : host;
}

export function findLoginForHost(vault: VaultBlobV1, host: string): { username?: string; password?: string; url?: string; title?: string } | null {
  const norm = host.toLowerCase();
  const items = vault.items
    .filter((i) => i.type === 'login')
    .slice()
    .sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1));

  for (const it of items) {
    const h = (it.host ?? it.url ? (() => {
      try { return new URL(it.url ?? '').hostname; } catch { return ''; }
    })() : '') as string;
    if (typeof h === 'string' && h.toLowerCase() === norm) {
      return { username: it.username, password: it.password, url: it.url, title: it.title };
    }
  }
  return null;
}
