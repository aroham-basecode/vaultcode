# VaultCode Browser Extension (Chrome + Firefox)

## Build

1. Install deps:

```bash
npm install
```

2. Build:

```bash
npm run build
```

Output folder: `dist/`

## Load in Chrome (Unpacked)

- Open `chrome://extensions/`
- Enable **Developer mode**
- Click **Load unpacked**
- Select `apps/extension/dist/`

## Load in Firefox (Temporary)

- Open `about:debugging#/runtime/this-firefox`
- Click **Load Temporary Add-on**
- Select `apps/extension/dist/manifest.json`

## First-time setup in popup

- Click **Open VaultCode**
- Login on the VaultCode web app once
- The extension auto-detects your web session token
- Enter **Master Password** and click **Unlock** (session-only)

## Usage

- **Autofill This Site**: looks up the current tab hostname inside your vault and fills username/password.
- **Save Detected Login**: after you submit a login form on a website, open the popup and click this to save it.
- **Password Generator**: generate/copy/insert password.

## Chrome Web Store publish

- Zip the contents of `apps/extension/dist/` (manifest.json must be at the ZIP root)
- Upload in Chrome Web Store developer dashboard
- Provide:
  - Privacy policy URL
  - Permission justification (`storage`, `tabs`, `activeTab`, and `<all_urls>`)

