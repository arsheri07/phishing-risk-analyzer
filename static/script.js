document.getElementById('case-number').textContent =
  String(Math.floor(Math.random() * 900000) + 100000);

// ---------- Tab switching ----------
const tabs = document.querySelectorAll('.tab');
const panels = document.querySelectorAll('.tab-panel');

tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    tabs.forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
    panels.forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    tab.setAttribute('aria-selected', 'true');
    document.querySelector(`.tab-panel[data-panel="${tab.dataset.tab}"]`).classList.add('active');
    document.getElementById('results').classList.add('hidden');
    document.getElementById('error-box').classList.add('hidden');
  });
});

// ---------- Sample data ----------
const SAMPLE_PHISHING_EMAIL = `From: PayPal Security <alerts@paypa1-security.com>
Reply-To: support@totally-different-domain.ru
Subject: Urgent: Your account will be suspended within 24 hours
Date: Mon, 20 Jul 2026 03:12:00 +0000
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=paypa1-security.com; dkim=none; dmarc=fail
Content-Type: text/plain

Dear Customer,

We have detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify immediately.

Click here to confirm your identity: http://paypa1-security.com/verify

Failure to respond will result in permanent account closure.

PayPal Security Team`;

document.getElementById('load-sample-email').addEventListener('click', () => {
  document.getElementById('email-input').value = SAMPLE_PHISHING_EMAIL;
});

document.getElementById('load-sample-website').addEventListener('click', () => {
  document.getElementById('url-input').value = 'https://github.com';
});

document.getElementById('load-sample-sms').addEventListener('click', () => {
  document.getElementById('sms-input').value =
    "Your package is on hold. Redeliver now: http://bit.ly/track99x2\nVerification code sent to your phone - forward this code to confirm delivery.";
});

document.getElementById('load-sample-phone').addEventListener('click', () => {
  document.getElementById('phone-number-input').value = '+1-202-555-0199';
  document.getElementById('phone-input').value =
    "This is the IRS calling. Your social security number has been suspended due to suspicious activity and there is an arrest warrant issued in your name. To resolve this immediately, you must pay using a Google Play gift card or you will be arrested within the hour.";
});

document.getElementById('load-sample-app').addEventListener('click', () => {
  document.getElementById('app-name-input').value = 'Super Bright Flashlight Pro';
  document.getElementById('app-developer-input').value = 'App9921';
  document.getElementById('app-description-input').value =
    "Simple flashlight app, just tap to turn on the light. Also unlocks guaranteed passive income guaranteed - start earning today!";
  document.getElementById('app-permissions-input').value = 'Camera, Contacts, SMS, Location, Microphone';
});

// ---------- Shared helpers ----------
const resultsSection = document.getElementById('results');
const errorBox = document.getElementById('error-box');

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove('hidden');
  resultsSection.classList.add('hidden');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

function renderVerdict(verdict, score) {
  const stamp = document.getElementById('stamp');
  const stampText = document.getElementById('stamp-text');
  stamp.className = 'stamp ' + verdict.toLowerCase();
  stampText.textContent = verdict;
  stamp.style.animation = 'none';
  stamp.offsetHeight;
  stamp.style.animation = '';
  document.getElementById('score-value').textContent = score;
}

function renderReasons(reasons) {
  const reasonsList = document.getElementById('reasons-list');
  if (reasons.length === 0) {
    reasonsList.innerHTML = '<li class="no-reasons">No suspicious signals found. This looks clean.</li>';
  } else {
    reasonsList.innerHTML = reasons.map(r => `
      <li class="reason-item">
        <span class="reason-points">+${r.points}</span>
        <span>${escapeHtml(r.reason)}</span>
      </li>
    `).join('');
  }
}

// ---------- Email analysis ----------
const analyzeEmailBtn = document.getElementById('analyze-email-btn');

analyzeEmailBtn.addEventListener('click', async () => {
  const rawEmail = document.getElementById('email-input').value;
  const liveChecks = document.getElementById('live-toggle').checked;

  errorBox.classList.add('hidden');
  resultsSection.classList.add('hidden');

  if (!rawEmail.trim()) {
    showError("Paste an email first — there's nothing to analyze yet.");
    return;
  }

  analyzeEmailBtn.disabled = true;
  analyzeEmailBtn.textContent = liveChecks ? 'Running deep scan…' : 'Analyzing…';

  try {
    const response = await fetch('/api/analyze/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_email: rawEmail, live_checks: liveChecks }),
    });
    const data = await response.json();
    if (!response.ok) { showError(data.error || 'Something went wrong.'); return; }
    renderEmailResults(data);
  } catch (err) {
    showError('Could not reach the analysis server. Is it running?');
  } finally {
    analyzeEmailBtn.disabled = false;
    analyzeEmailBtn.textContent = 'Analyze message';
  }
});

function renderEmailResults(data) {
  renderVerdict(data.verdict, data.score);

  document.getElementById('summary-title').textContent = '01 — Sender';
  document.getElementById('summary-fields').innerHTML = `
    <div><dt>From</dt><dd>${escapeHtml(data.email_summary.from_display_name || '(none)')} &lt;${escapeHtml(data.email_summary.from_address)}&gt;</dd></div>
    <div><dt>Domain</dt><dd>${escapeHtml(data.email_summary.sender_domain)}</dd></div>
    <div><dt>Reply-To</dt><dd>${escapeHtml(data.email_summary.reply_to || '(same as From)')}</dd></div>
    <div><dt>Subject</dt><dd>${escapeHtml(data.email_summary.subject)}</dd></div>
  `;

  const authCard = document.getElementById('auth-card');
  authCard.classList.remove('hidden');
  const pillClass = (v) => (v === 'pass' ? 'pass' : (v === 'fail' ? 'fail' : 'none'));
  document.getElementById('auth-fields').innerHTML = `
    <div><dt>SPF</dt><dd><span class="pill ${pillClass(data.auth.spf)}">${escapeHtml(data.auth.spf)}</span></dd></div>
    <div><dt>DKIM</dt><dd><span class="pill ${pillClass(data.auth.dkim)}">${escapeHtml(data.auth.dkim)}</span></dd></div>
    <div><dt>DMARC</dt><dd><span class="pill ${pillClass(data.auth.dmarc)}">${escapeHtml(data.auth.dmarc)}</span></dd></div>
    <div><dt>Source</dt><dd>${data.auth.source === 'live' ? 'Live verification' : 'Header only'}</dd></div>
  `;

  const linksCard = document.getElementById('links-card');
  linksCard.classList.remove('hidden');
  const linksList = document.getElementById('links-list');
  if (data.links.length === 0) {
    linksList.innerHTML = '<p class="no-links">No links found in this message.</p>';
  } else {
    linksList.innerHTML = data.links.map(link => {
      const flags = [];
      if (link.is_typosquat) flags.push(`<span class="pill fail">looks like ${escapeHtml(link.typosquat_target)}</span>`);
      if (link.is_combosquat) flags.push(`<span class="pill fail">contains "${escapeHtml(link.combosquat_target)}"</span>`);
      if (link.is_ip_address) flags.push(`<span class="pill fail">raw IP address</span>`);
      if (link.uses_url_shortener) flags.push(`<span class="pill none">shortened URL</span>`);
      return `<div class="link-item"><div class="link-url">${escapeHtml(link.url)}</div><div class="link-flags">${flags.length ? flags.join('') : '<span class="link-clean">no issues found</span>'}</div></div>`;
    }).join('');
  }

  renderReasons(data.reasons);
  resultsSection.classList.remove('hidden');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---------- Website analysis ----------
const analyzeWebsiteBtn = document.getElementById('analyze-website-btn');

analyzeWebsiteBtn.addEventListener('click', async () => {
  const url = document.getElementById('url-input').value.trim();

  errorBox.classList.add('hidden');
  resultsSection.classList.add('hidden');

  if (!url) {
    showError("Paste a URL first — there's nothing to analyze yet.");
    return;
  }

  analyzeWebsiteBtn.disabled = true;
  analyzeWebsiteBtn.textContent = 'Analyzing…';

  try {
    const response = await fetch('/api/analyze/website', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await response.json();
    if (!response.ok) { showError(data.error || 'Something went wrong.'); return; }
    renderWebsiteResults(data);
  } catch (err) {
    showError('Could not reach the analysis server. Is it running?');
  } finally {
    analyzeWebsiteBtn.disabled = false;
    analyzeWebsiteBtn.textContent = 'Analyze site';
  }
});

function renderWebsiteResults(data) {
  renderVerdict(data.verdict, data.score);

  document.getElementById('summary-title').textContent = '01 — Site';
  const ageText = data.site_summary.domain_age_days === -1
    ? 'Unknown' : `${data.site_summary.domain_age_days} days`;
  document.getElementById('summary-fields').innerHTML = `
    <div><dt>URL</dt><dd>${escapeHtml(data.site_summary.url)}</dd></div>
    <div><dt>Domain</dt><dd>${escapeHtml(data.site_summary.domain)}</dd></div>
    <div><dt>Domain age</dt><dd>${ageText}</dd></div>
    <div><dt>SSL</dt><dd><span class="pill ${data.site_summary.has_valid_ssl ? 'pass' : 'fail'}">${data.site_summary.has_valid_ssl ? 'valid' : 'missing/invalid'}</span></dd></div>
    <div><dt>Redirects</dt><dd>${data.site_summary.redirect_count}</dd></div>
    ${data.site_summary.fetch_error ? `<div><dt>Fetch error</dt><dd>${escapeHtml(data.site_summary.fetch_error)}</dd></div>` : ''}
  `;

  document.getElementById('auth-card').classList.add('hidden');
  document.getElementById('links-card').classList.add('hidden');

  renderReasons(data.reasons);
  resultsSection.classList.remove('hidden');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---------- SMS analysis ----------
const analyzeSmsBtn = document.getElementById('analyze-sms-btn');

analyzeSmsBtn.addEventListener('click', async () => {
  const message = document.getElementById('sms-input').value;
  errorBox.classList.add('hidden');
  resultsSection.classList.add('hidden');

  if (!message.trim()) { showError("Paste a text message first — there's nothing to analyze yet."); return; }

  analyzeSmsBtn.disabled = true;
  analyzeSmsBtn.textContent = 'Analyzing…';
  try {
    const response = await fetch('/api/analyze/sms', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    });
    const data = await response.json();
    if (!response.ok) { showError(data.error || 'Something went wrong.'); return; }

    renderVerdict(data.verdict, data.score);
    document.getElementById('summary-title').textContent = '01 — Message';
    document.getElementById('summary-fields').innerHTML = `
      <div><dt>Links found</dt><dd>${data.summary.link_count}</dd></div>
      <div><dt>OTP forward request</dt><dd><span class="pill ${data.summary.requests_otp_forwarding ? 'fail' : 'pass'}">${data.summary.requests_otp_forwarding ? 'detected' : 'none'}</span></dd></div>
    `;
    document.getElementById('auth-card').classList.add('hidden');
    document.getElementById('links-card').classList.add('hidden');
    renderReasons(data.reasons);
    resultsSection.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    showError('Could not reach the analysis server. Is it running?');
  } finally {
    analyzeSmsBtn.disabled = false;
    analyzeSmsBtn.textContent = 'Analyze message';
  }
});

// ---------- Phone call analysis ----------
const analyzePhoneBtn = document.getElementById('analyze-phone-btn');

analyzePhoneBtn.addEventListener('click', async () => {
  const transcript = document.getElementById('phone-input').value;
  const phoneNumber = document.getElementById('phone-number-input').value;
  errorBox.classList.add('hidden');
  resultsSection.classList.add('hidden');

  if (!transcript.trim()) { showError("Paste a call transcript first — there's nothing to analyze yet."); return; }

  analyzePhoneBtn.disabled = true;
  analyzePhoneBtn.textContent = 'Analyzing…';
  try {
    const response = await fetch('/api/analyze/phone', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ transcript, phone_number: phoneNumber }),
    });
    const data = await response.json();
    if (!response.ok) { showError(data.error || 'Something went wrong.'); return; }

    renderVerdict(data.verdict, data.score);
    document.getElementById('summary-title').textContent = '01 — Call';
    document.getElementById('summary-fields').innerHTML = `
      <div><dt>Caller number</dt><dd>${escapeHtml(data.summary.phone_number || '(not provided)')}</dd></div>
      <div><dt>Agency impersonation</dt><dd>${data.summary.matched_agency_phrases.length ? escapeHtml(data.summary.matched_agency_phrases.join(', ')) : 'none detected'}</dd></div>
      <div><dt>Remote access request</dt><dd>${data.summary.matched_remote_access.length ? escapeHtml(data.summary.matched_remote_access.join(', ')) : 'none detected'}</dd></div>
    `;
    document.getElementById('auth-card').classList.add('hidden');
    document.getElementById('links-card').classList.add('hidden');
    renderReasons(data.reasons);
    resultsSection.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    showError('Could not reach the analysis server. Is it running?');
  } finally {
    analyzePhoneBtn.disabled = false;
    analyzePhoneBtn.textContent = 'Analyze call';
  }
});

// ---------- App listing analysis ----------
const analyzeAppBtn = document.getElementById('analyze-app-btn');

analyzeAppBtn.addEventListener('click', async () => {
  const app_name = document.getElementById('app-name-input').value;
  const developer_name = document.getElementById('app-developer-input').value;
  const description = document.getElementById('app-description-input').value;
  const permissions = document.getElementById('app-permissions-input').value;

  errorBox.classList.add('hidden');
  resultsSection.classList.add('hidden');

  if (!description.trim()) { showError("Paste the app's description first — there's nothing to analyze yet."); return; }

  analyzeAppBtn.disabled = true;
  analyzeAppBtn.textContent = 'Analyzing…';
  try {
    const response = await fetch('/api/analyze/app', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ app_name, developer_name, description, permissions }),
    });
    const data = await response.json();
    if (!response.ok) { showError(data.error || 'Something went wrong.'); return; }

    renderVerdict(data.verdict, data.score);
    document.getElementById('summary-title').textContent = '01 — App';
    document.getElementById('summary-fields').innerHTML = `
      <div><dt>App name</dt><dd>${escapeHtml(data.summary.app_name || '(not provided)')}</dd></div>
      <div><dt>Developer</dt><dd>${escapeHtml(data.summary.developer_name || '(not provided)')} ${data.summary.generic_developer_name ? '<span class="pill fail">generic pattern</span>' : ''}</dd></div>
      <div><dt>Permissions</dt><dd>${data.summary.permissions.length ? escapeHtml(data.summary.permissions.join(', ')) : '(none listed)'}</dd></div>
    `;
    document.getElementById('auth-card').classList.add('hidden');
    document.getElementById('links-card').classList.add('hidden');
    renderReasons(data.reasons);
    resultsSection.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    showError('Could not reach the analysis server. Is it running?');
  } finally {
    analyzeAppBtn.disabled = false;
    analyzeAppBtn.textContent = 'Analyze listing';
  }
});
