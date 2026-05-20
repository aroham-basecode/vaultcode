import { createEmptyVault, decryptVault, encryptVault } from '@shared/vault/crypto';
import type { VaultBlobV1, VaultItem } from '@shared/vault/types';
import { apiGetVault, apiPutVault, hostFromUrl, titleFromHost } from '../api';
import { APP_ORIGIN, API_BASE } from '../constants';
import {
  clearConfig,
  clearPendingCredential,
  getConfig,
  getMasterPasswordSession,
  getPendingCredential,
  setMasterPasswordSession,
  setConfig,
} from '../storage';

function extApi(): any {
  const g: any = globalThis as any;
  return g.browser ?? g.chrome;
}

type PageState = {
  hasPasswordField: boolean;
  hasUsernameField: boolean;
  host: string;
  url: string;
  title: string;
};

const api = extApi();

function el<T extends HTMLElement>(id: string): T {
  const n = document.getElementById(id);
  if (!n) throw new Error(`Missing element: ${id}`);
  return n as T;
}

const pageStatusEl = el<HTMLDivElement>('pageStatus');
const masterEl = el<HTMLInputElement>('master');
const resultsEl = el<HTMLDivElement>('results');
const msgEl = el<HTMLDivElement>('msg');
const errEl = el<HTMLDivElement>('err');
const autofillBtn = el<HTMLButtonElement>('autofill');
const savePendingBtn = el<HTMLButtonElement>('savePending');
const manualConnectEl = el<HTMLDivElement>('manualConnect');
const manualTokenEl = el<HTMLInputElement>('manualToken');
const connectManualBtn = el<HTMLButtonElement>('connectManual');

function showMsg(s: string) {
  msgEl.textContent = s;
  msgEl.style.display = 'block';
  errEl.style.display = 'none';
}

function showErr(s: string) {
  errEl.textContent = s;
  errEl.style.display = 'block';
  msgEl.style.display = 'none';
}

async function getPageState(): Promise<PageState | null> {
  const res = await new Promise<any>((resolve) => api.runtime.sendMessage({ type: 'VC_GET_PAGE_STATE' }, (v: any) => resolve(v)));
  if (!res?.ok || !res?.pageState) return null;
  return res.pageState as PageState;
}

function hostMatches(itemHost: string, pageHost: string): boolean {
  const a = itemHost.toLowerCase();
  const b = pageHost.toLowerCase();
  if (a === b) return true;
  if (b.endsWith(`.${a}`)) return true;
  return false;
}

function pickLoginsForHost(vault: VaultBlobV1, host: string): VaultItem[] {
  return vault.items
    .filter((i) => i.type === 'login')
    .filter((i) => typeof i.host === 'string' && i.host && hostMatches(i.host, host))
    .slice()
    .sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1));
}

async function ensureUnlocked(): Promise<string> {
  const mp = await getMasterPasswordSession();
  if (!mp) throw new Error('Locked. Enter master password and click Unlock.');
  return mp;
}

async function fetchAndDecryptVault(apiBase: string, token: string, masterPassword: string): Promise<VaultBlobV1> {
  const remote = await apiGetVault(apiBase, token);
  if (!remote.encryptedVault) return createEmptyVault();
  return decryptVault(remote.encryptedVault as any, masterPassword) as VaultBlobV1;
}

async function encryptAndSaveVault(apiBase: string, token: string, masterPassword: string, vault: VaultBlobV1): Promise<void> {
  const payload = encryptVault({ ...vault, updatedAt: new Date().toISOString() } as any, masterPassword) as any;
  await apiPutVault(apiBase, token, payload, 1);
}

function clearResults() {
  resultsEl.innerHTML = '';
}

function renderLogin(host: string, item: VaultItem) {
  const wrap = document.createElement('div');
  wrap.className = 'item';

  const title = document.createElement('div');
  title.textContent = item.title;
  title.style.fontWeight = '800';

  const meta = document.createElement('div');
  meta.className = 'muted small';
  meta.textContent = item.username ? `User: ${item.username}` : host;

  const btn = document.createElement('button');
  btn.className = 'primary';
  btn.textContent = 'Autofill';
  btn.addEventListener('click', async () => {
    try {
      const result = await new Promise<any>((resolve) =>
        api.runtime.sendMessage(
          {
            type: 'VC_FILL_ACTIVE_TAB',
            payload: { username: item.username ?? '', password: item.password ?? '' },
          },
          (v: any) => resolve(v),
        ),
      );
      if (!result?.ok) throw new Error(result?.error || 'Unable to fill current site');
      showMsg(`Filled ${host}`);
    } catch (e) {
      showErr(e instanceof Error ? e.message : 'Autofill failed');
    }
  });

  wrap.appendChild(title);
  wrap.appendChild(meta);
  wrap.appendChild(btn);
  resultsEl.appendChild(wrap);
}

async function refreshSiteList() {
  clearResults();
  const cfg = await getConfig();
  const pageState = await getPageState();

  if (!pageState?.host) {
    pageStatusEl.textContent = 'Open a website tab and try again.';
    autofillBtn.disabled = true;
    return;
  }

  pageStatusEl.textContent = pageState.hasPasswordField
    ? `Detected password field on ${pageState.host}`
    : `No password field detected on ${pageState.host}`;

  autofillBtn.disabled = !pageState.hasPasswordField;

  if (!cfg) {
    manualConnectEl.style.display = 'flex';
    showErr('Not connected. Open VaultCode web and login, or paste token below.');
    return;
  }

  manualConnectEl.style.display = 'none';
  const mp = await getMasterPasswordSession();
  if (!mp) return;

  const vault = await fetchAndDecryptVault(cfg.apiBase, cfg.token, mp);
  const matches = pickLoginsForHost(vault, pageState.host);
  for (const m of matches.slice(0, 6)) renderLogin(pageState.host, m);
}

async function runAutofillTop() {
  const cfg = await getConfig();
  if (!cfg) throw new Error('Not connected. Open VaultCode web and login once.');
  const mp = await ensureUnlocked();
  const pageState = await getPageState();
  if (!pageState?.host) throw new Error('No active host');

  const vault = await fetchAndDecryptVault(cfg.apiBase, cfg.token, mp);
  const matches = pickLoginsForHost(vault, pageState.host);
  const top = matches[0];
  if (!top?.password) throw new Error(`No saved login for ${pageState.host}`);

  const result = await new Promise<any>((resolve) =>
    api.runtime.sendMessage(
      {
        type: 'VC_FILL_ACTIVE_TAB',
        payload: { username: top.username ?? '', password: top.password ?? '' },
      },
      (v: any) => resolve(v),
    ),
  );
  if (!result?.ok) throw new Error(result?.error || 'Unable to fill current site');
  showMsg(`Filled ${pageState.host}`);
}

async function runSavePending() {
  const cfg = await getConfig();
  if (!cfg) throw new Error('Not connected. Open VaultCode web and login once.');
  const mp = await ensureUnlocked();
  const pending = await getPendingCredential();
  if (!pending) throw new Error('No detected login yet. Try logging in on a site first.');
  if (!pending.password) throw new Error('Detected item missing password');

  const vault = await fetchAndDecryptVault(cfg.apiBase, cfg.token, mp);
  const id = (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`).replace(/[^a-zA-Z0-9-]/g, '');
  const host = pending.host || hostFromUrl(pending.url);
  const title = pending.title?.trim() || titleFromHost(host);

  vault.items.unshift({
    id,
    type: 'login',
    title,
    host,
    username: pending.username,
    password: pending.password,
    url: pending.url,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  } as any);

  await encryptAndSaveVault(cfg.apiBase, cfg.token, mp, vault);
  await clearPendingCredential();
  showMsg('Saved login to vault');
  await refreshSiteList();
}

el<HTMLButtonElement>('openApp').addEventListener('click', () => {
  api.tabs.create({ url: APP_ORIGIN });
});

el<HTMLButtonElement>('disconnect').addEventListener('click', async () => {
  await clearConfig();
  showMsg('Disconnected');
  await refreshSiteList();
});

connectManualBtn.addEventListener('click', async () => {
  try {
    const token = manualTokenEl.value.trim();
    if (!token) throw new Error('Paste your token from the web app');
    await setConfig({ token, apiBase: API_BASE });
    manualTokenEl.value = '';
    showMsg('Connected! Now enter master password and click Unlock.');
    await refreshSiteList();
  } catch (e) {
    showErr(e instanceof Error ? e.message : 'Connect failed');
  }
});

el<HTMLButtonElement>('unlock').addEventListener('click', async () => {
  try {
    const v = masterEl.value;
    if (!v) throw new Error('Enter master password');
    await setMasterPasswordSession(v);
    showMsg('Unlocked (session only)');
    await refreshSiteList();
  } catch (e) {
    showErr(e instanceof Error ? e.message : 'Unlock failed');
  }
});

el<HTMLButtonElement>('lock').addEventListener('click', async () => {
  await setMasterPasswordSession(null);
  masterEl.value = '';
  showMsg('Locked');
  await refreshSiteList();
});

autofillBtn.addEventListener('click', async () => {
  try {
    await runAutofillTop();
  } catch (e) {
    showErr(e instanceof Error ? e.message : 'Autofill failed');
  }
});

savePendingBtn.addEventListener('click', async () => {
  try {
    await runSavePending();
  } catch (e) {
    showErr(e instanceof Error ? e.message : 'Save failed');
  }
});

(async () => {
  try {
    const cfg = await getConfig();
    const mp = await getMasterPasswordSession();
    if (mp) masterEl.value = mp;
    await refreshSiteList();
    if (!cfg) {
      manualConnectEl.style.display = 'flex';
    }
  } catch {
    pageStatusEl.textContent = 'Open a website tab and try again.';
    manualConnectEl.style.display = 'flex';
  }
})();
