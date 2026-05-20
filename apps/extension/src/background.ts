import { setPendingCredential, getPendingCredential, setTokenOnly } from './storage';
import type { PendingCredential } from './types';

function extApi(): any {
  const g: any = globalThis as any;
  return g.browser ?? g.chrome;
}

const api = extApi();

async function getActiveTabId(): Promise<number | null> {
  return new Promise((resolve) => {
    api.tabs.query({ active: true, currentWindow: true }, (tabs: any[]) => {
      const id = tabs?.[0]?.id;
      resolve(typeof id === 'number' ? id : null);
    });
  });
}

async function sendToActiveTab(message: any): Promise<any> {
  const tabId = await getActiveTabId();
  if (!tabId) return { ok: false, error: 'No active tab' };

  return new Promise((resolve) => {
    api.tabs.sendMessage(tabId, message, (res: any) => {
      const err = api.runtime?.lastError;
      if (err) resolve({ ok: false, error: err.message ?? String(err) });
      else resolve(res ?? { ok: true });
    });
  });
}

api.runtime.onMessage.addListener((msg: any, _sender: any, sendResponse: (v: any) => void) => {
  (async () => {
    if (msg?.type === 'VC_SET_TOKEN') {
      const t = typeof msg.token === 'string' ? msg.token : '';
      if (t) await setTokenOnly(t);
      sendResponse({ ok: true });
      return;
    }

    if (msg?.type === 'VC_STORE_PENDING') {
      const p = msg.payload as PendingCredential;
      await setPendingCredential(p);
      sendResponse({ ok: true });
      return;
    }

    if (msg?.type === 'VC_GET_PENDING') {
      const p = await getPendingCredential();
      sendResponse({ ok: true, pending: p });
      return;
    }

    if (msg?.type === 'VC_FILL_ACTIVE_TAB') {
      sendResponse(await sendToActiveTab({ type: 'VC_FILL', payload: msg.payload }));
      return;
    }

    if (msg?.type === 'VC_INSERT_PASSWORD') {
      sendResponse(await sendToActiveTab({ type: 'VC_INSERT_PASSWORD', payload: msg.payload }));
      return;
    }

    if (msg?.type === 'VC_GET_PAGE_STATE') {
      sendResponse(await sendToActiveTab({ type: 'VC_PAGE_STATE' }));
      return;
    }

    sendResponse({ ok: false, error: 'Unknown message' });
  })().catch((e) => sendResponse({ ok: false, error: e?.message ?? String(e) }));
  return true;
});
