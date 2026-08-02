# Scam Shield Browser Extension

Checks the site you're currently viewing against your own deployed
Scam Shield backend — right from the browser toolbar.

## Security model (read this first)

- This extension has **no hardcoded server** and **no API keys of any
  kind**. You configure it to point at your own deployed Scam Shield
  instance (e.g. your Render URL), and it only ever talks to that
  server.
- It requests exactly one permission: reading the URL of the active
  tab. It does not read page content, browsing history, or anything
  else.
- Nothing is sent anywhere except the single URL you're checking, to
  the single server you configured.

## Setup

1. Deploy the main Scam Shield app first (see the main project's
   README) and note its live URL.
2. Open Chrome → `chrome://extensions`
3. Turn on **Developer mode** (top right toggle)
4. Click **Load unpacked**
5. Select this folder (`scam-shield-extension/`)
6. Click the Scam Shield icon in your toolbar → click **⚙ configure
   your Scam Shield server** → paste your deployed URL (e.g.
   `https://your-scam-shield.onrender.com`) → it saves automatically
7. Visit any site, click the extension icon, click **Analyze this
   site**

## Publishing to the Chrome Web Store (optional)

This is unpacked/developer-mode only right now, which is fine for
personal use and for demoing in an interview. Publishing publicly
requires a one-time $5 Chrome Web Store developer registration fee and
a review process - worth doing later if you want "published Chrome
extension" as a resume line, but not required for this to work for you
personally today.
