import { APP_ORIGINS, WEB_TOKEN_KEY } from './constants';

type FillPayload = { username?: string; password?: string };

type PageState = {
  hasPasswordField: boolean;
  hasUsernameField: boolean;
  host: string;
  url: string;
  title: string;
};

function guessUsernameInput(): HTMLInputElement | null {
  const inputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
  const candidates = inputs
    .filter((i) => i.type !== 'password')
    .filter((i) => !i.disabled && !i.readOnly)
    .filter((i) => i.offsetParent !== null)
    .filter((i) => {
      const n = (i.name ?? '').toLowerCase();
      const id = (i.id ?? '').toLowerCase();
      const a = (i.getAttribute('autocomplete') ?? '').toLowerCase();
      return /email|user|login|username/.test(n) || /email|user|login|username/.test(id) || a === 'username' || a === 'email';
    });

  return candidates[0] ?? null;
}

function findPasswordInput(): HTMLInputElement | null {
  const inputs = Array.from(document.querySelectorAll('input[type="password"]')) as HTMLInputElement[];
  return inputs.find((i) => !i.disabled && !i.readOnly && i.offsetParent !== null) ?? null;
}

function setValue(el: HTMLInputElement, value: string) {
  el.focus();
  (el as any).value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

function extApi(): any {
  const g: any = globalThis as any;
  return g.browser ?? g.chrome;
}

const api = extApi();

function isAppOrigin(): boolean {
  try {
    return APP_ORIGINS.includes(window.location.origin);
  } catch {
    return false;
  }
}

function tryCaptureTokenFromPage() {
  if (!isAppOrigin()) return;

  const script = document.createElement('script');
  script.textContent = `(() => {
    try {
      const t = window.localStorage.getItem(${JSON.stringify(WEB_TOKEN_KEY)}) || '';
      window.postMessage({ source: 'vaultcode-page', type: 'VC_WEB_TOKEN', token: t }, '*');
    } catch {}
  })();`;
  (document.documentElement || document.head || document.body).appendChild(script);
  script.remove();
}

function hostFromLocation(): string {
  try {
    return window.location.hostname;
  } catch {
    return '';
  }
}

function getPageState(): PageState {
  const passwordInput = findPasswordInput();
  const usernameInput = guessUsernameInput();
  return {
    hasPasswordField: Boolean(passwordInput),
    hasUsernameField: Boolean(usernameInput),
    host: hostFromLocation(),
    url: window.location.href,
    title: document.title,
  };
}

let tokenCaptured = false;

window.addEventListener('message', (ev) => {
  const data: any = ev.data;
  if (!data || data.source !== 'vaultcode-page' || data.type !== 'VC_WEB_TOKEN') return;
  if (typeof data.token !== 'string' || !data.token) return;
  tokenCaptured = true;
  api.runtime.sendMessage({ type: 'VC_SET_TOKEN', token: data.token });
});

// Initial try
tryCaptureTokenFromPage();

// Retry every 3 seconds until token found (for when user logs in after page load)
if (isAppOrigin()) {
  const retryInterval = setInterval(() => {
    if (tokenCaptured) {
      clearInterval(retryInterval);
      return;
    }
    tryCaptureTokenFromPage();
  }, 3000);
  // Stop after 5 minutes (300 attempts) to prevent infinite polling
  setTimeout(() => clearInterval(retryInterval), 5 * 60 * 1000);
}

api.runtime.onMessage.addListener((msg: any, _sender: any, sendResponse: (v: any) => void) => {
  if (msg?.type === 'VC_FILL') {
    const p = msg.payload as FillPayload;
    const u = guessUsernameInput();
    const pw = findPasswordInput();
    if (u && typeof p.username === 'string') setValue(u, p.username);
    if (pw && typeof p.password === 'string') setValue(pw, p.password);
    sendResponse({ ok: true, pageState: getPageState() });
    return;
  }

  if (msg?.type === 'VC_INSERT_PASSWORD') {
    const pw = findPasswordInput();
    if (pw && typeof msg.payload?.password === 'string') {
      setValue(pw, msg.payload.password);
      sendResponse({ ok: true, pageState: getPageState() });
      return;
    }
    sendResponse({ ok: false, pageState: getPageState() });
    return;
  }

  if (msg?.type === 'VC_PAGE_STATE') {
    sendResponse({ ok: true, pageState: getPageState() });
    return;
  }
});

function extractCredentialFromForm(form: HTMLFormElement): { username?: string; password?: string } {
  const fd = new FormData(form);
  let username: string | undefined;
  let password: string | undefined;

  for (const [k, v] of fd.entries()) {
    const key = String(k).toLowerCase();
    const val = typeof v === 'string' ? v : '';
    if (!val) continue;
    if (!password && /pass/.test(key)) password = val;
    if (!username && /email|user|login|username/.test(key)) username = val;
  }

  if (!password) {
    const pw = findPasswordInput();
    if (pw?.value) password = pw.value;
  }
  if (!username) {
    const u = guessUsernameInput();
    if (u?.value) username = u.value;
  }

  return { username, password };
}

document.addEventListener(
  'submit',
  (e) => {
    const form = e.target as HTMLFormElement | null;
    if (!form || typeof form.querySelector !== 'function') return;
    const { username, password } = extractCredentialFromForm(form);
    if (!password) return;

    const payload = {
      host: hostFromLocation(),
      url: window.location.href,
      title: document.title,
      username,
      password,
      createdAt: new Date().toISOString(),
    };

    api.runtime.sendMessage({ type: 'VC_STORE_PENDING', payload });
  },
  true,
);
