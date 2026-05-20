import type { PendingCredential, StoredConfig } from './types';
import { API_BASE } from './constants';

type StorageArea = {
  get(keys?: string | string[] | Record<string, unknown> | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
};

function extApi(): any {
  const g: any = globalThis as any;
  return g.browser ?? g.chrome;
}

function storageLocal(): StorageArea {
  const api = extApi()?.storage?.local;
  return {
    get: (keys) => new Promise((resolve) => api.get(keys as any, (res: any) => resolve(res ?? {}))),
    set: (items) => new Promise((resolve) => api.set(items as any, () => resolve())),
    remove: (keys) => new Promise((resolve) => api.remove(keys as any, () => resolve())),
  };
}

function storageSession(): StorageArea | null {
  const api = extApi()?.storage?.session;
  if (!api) return null;
  return {
    get: (keys) => new Promise((resolve) => api.get(keys as any, (res: any) => resolve(res ?? {}))),
    set: (items) => new Promise((resolve) => api.set(items as any, () => resolve())),
    remove: (keys) => new Promise((resolve) => api.remove(keys as any, () => resolve())),
  };
}

const CFG_KEY = 'vc_cfg';
const PENDING_KEY = 'vc_pending_credential';
const MASTER_KEY = 'vc_master_session';

export async function getConfig(): Promise<StoredConfig | null> {
  const res = await storageLocal().get(CFG_KEY);
  const v = (res[CFG_KEY] as StoredConfig | undefined) ?? null;
  const token = typeof v?.token === 'string' ? v.token : '';
  if (!token) return null;
  const apiBase = typeof v?.apiBase === 'string' && v.apiBase ? v.apiBase : API_BASE;
  return { apiBase, token };
}

export async function setConfig(cfg: StoredConfig): Promise<void> {
  await storageLocal().set({ [CFG_KEY]: cfg });
}

export async function setTokenOnly(token: string): Promise<void> {
  if (!token) return;
  const cur = (await storageLocal().get(CFG_KEY))[CFG_KEY] as any;
  await storageLocal().set({
    [CFG_KEY]: {
      apiBase: typeof cur?.apiBase === 'string' && cur.apiBase ? cur.apiBase : API_BASE,
      token,
    },
  });
}

export async function clearConfig(): Promise<void> {
  await storageLocal().remove(CFG_KEY);
}

export async function getPendingCredential(): Promise<PendingCredential | null> {
  const res = await storageLocal().get(PENDING_KEY);
  return (res[PENDING_KEY] as PendingCredential | undefined) ?? null;
}

export async function setPendingCredential(p: PendingCredential): Promise<void> {
  await storageLocal().set({ [PENDING_KEY]: p });
}

export async function clearPendingCredential(): Promise<void> {
  await storageLocal().remove(PENDING_KEY);
}

let masterInMemory: string | null = null;

export async function setMasterPasswordSession(pw: string | null): Promise<void> {
  masterInMemory = pw;
  const sess = storageSession();
  if (!sess) return;
  if (pw) await sess.set({ [MASTER_KEY]: pw });
  else await sess.remove(MASTER_KEY);
}

export async function getMasterPasswordSession(): Promise<string | null> {
  const sess = storageSession();
  if (!sess) return masterInMemory;
  const res = await sess.get(MASTER_KEY);
  const v = (res[MASTER_KEY] as string | undefined) ?? null;
  return typeof v === 'string' && v.length ? v : null;
}
