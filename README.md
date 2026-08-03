# Scam Shield

A unified scam-detection platform. Paste an email, link, text message,
call transcript, or app listing — get an instant, fully-explained risk
verdict. Five analysis modules share one scoring engine:

- **Email** — real SPF/DKIM/DMARC verification (including actual
  cryptographic DKIM signature verification), lookalike-domain
  detection on every link, urgency-language scoring
- **Website** — domain age, SSL certificate validity, redirect chain
  length, scam-payment-language, optional Google Safe Browsing lookup,
  plus the same lookalike-domain detection reused from email
- **Text Message** — smishing phrase detection, OTP-forwarding-request
  detection (a specific, high-confidence scam pattern), shared link analysis
- **Phone Call** — works from a typed transcript (no audio/API
  dependency required): agency-impersonation language, remote-access
  software requests, scam payment demands
- **App Listing** — unrealistic financial claims, permission requests
  that don't match the app's own stated purpose, generic
  auto-generated developer names

A companion browser extension lets you check the current tab's URL
without leaving your browser.

**Live demo:** [Scam-Shield](https://scamshield-arsheri.onrender.com)

## Why I built this

This started as Email Forensics, a phishing-email analyzer. A scam
link doesn't stop being a scam link because it arrived via text
instead of email, and a scam script doesn't stop being manipulative
because it's spoken over the phone instead of written down. The
explainable, additive scoring engine — every point traceable to a
specific reason — turned out to generalize cleanly across all five of
these very different input types. That reuse is the part of this
project I'm most glad I got right early on, since it's what made
adding four more modules take a fraction of the time the first one did.

## What each module checks

**Email:** SPF, DKIM (real cryptographic verification), DMARC,
typosquatting/combosquatting on every link, Reply-To/From mismatch,
urgency/pressure language.

**Website:** domain age via WHOIS, SSL certificate presence, redirect
chain length, scam-payment language, optional Google Safe Browsing
threat lookup, typosquat/combosquat detection.

**Text Message:** smishing phrases ("your package is on hold," "claim
your prize"), OTP-forwarding requests specifically (the core mechanism
of one-time-code interception scams), shared link analysis.

**Phone Call:** government/company impersonation phrases, remote-access
software requests (AnyDesk, TeamViewer, etc. - a hallmark of
tech-support scams), scam payment demands, urgency language.

**App Listing:** too-good-to-be-true financial claims ("guaranteed
profit," "100% guaranteed"), permission requests mismatched against
the app's own stated purpose (a flashlight app asking for contacts and
SMS access), generic/auto-generated developer names.

## Optional: Google Safe Browsing integration

The Website module can optionally check URLs against Google's threat
database. This requires a free API key that **you provide yourself** -
see `.env.example` and `SECURITY.md` for exactly how this is handled.
Without a key configured, the app works fully - it just skips this one
extra signal.

## Tech stack

Python 3, Flask, `dnspython`, `dkimpy`, `python-whois`, `requests`,
vanilla HTML/CSS/JS frontend, `pytest`, `gunicorn`.

## How to run locally

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```
Open `http://localhost:5000`. Every tab has a "load a sample" button.

## Testing

```bash
python3 -m pytest -v
```
74 tests total, covering all five modules plus the Safe Browsing
integration. Network-dependent logic (DNS, DKIM, WHOIS, Safe Browsing)
is tested against mocked responses rather than live calls - this keeps
the suite fast, reliable, and independent of network conditions,
while still proving the actual scoring logic is correct.

## An honest limitation worth stating directly

The Website module's domain-age (WHOIS) and SSL checks depend on live
network calls to whatever site you paste in. On a normal internet
connection this works as designed. In restrictive network environments
(locked-down corporate networks, some sandboxes/CI environments with
intercepting proxies), these specific live checks may report
inaccurate results - the tool is built to fail closed in that case
(treating an unreachable/unverifiable signal as a reason for caution,
not as automatically safe), but it's worth knowing the
live-network-dependent checks are only as reliable as the network
they're running on. The Phone Call module works from a typed
transcript rather than live audio specifically to avoid a similar
dependency on a paid, unreliable third-party transcription service.

## Security

See `SECURITY.md` for the full breakdown of how API keys are handled,
what data this app does and doesn't store, and how the test suite
directly verifies secrets never leak into logs or error messages.

## Deployment

This is a standard Flask app, already configured to run via
`gunicorn` in production (see `Procfile`) rather than Flask's
development server, so it deploys cleanly to any platform that
supports Python web services.

**Deploying on Render (free tier):**

1. Push this repo to GitHub first (see below if you haven't yet)
2. Go to [render.com](https://render.com) and sign in with your GitHub account
3. **New +** → **Web Service** → select this repo
4. Settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Instance Type:** Free
5. **Create Web Service** and wait for "Your service is live" (2-5 minutes)
6. Copy the live URL Render gives you and update the "Live demo" line
   at the top of this README with it

Note: Render's free tier spins down after ~15 minutes of inactivity
and takes 30-60 seconds to wake back up on the next visit - expected
behavior, not a bug, if it feels slow on a cold start.

**Pushing this repo to GitHub, if you haven't yet:**
```bash
git init
git add .
git commit -m "Initial commit: Scam Shield unified scam-detection platform"
git remote add origin https://github.com/YOUR-USERNAME/scam-shield.git
git branch -M main
git push -u origin main
```

## What I'd add next

- Live audio transcription for the Phone Call module (once/if a
  reliable free-tier speech-to-text option is available)
- Full APK static analysis for the App Listing module, beyond listing
  text alone
- A shared "case history" view across all five modules in one session
- Publish the browser extension to the Chrome Web Store

---
*Built by Akshithreddy Sheri — [github.com/arsheri07](https://github.com/arsheri07)*
