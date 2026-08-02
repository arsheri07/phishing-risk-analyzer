# Security Notes

## API keys / secrets

- The only secret this project ever uses is an optional
  `GOOGLE_SAFE_BROWSING_API_KEY`.
- It is read exclusively via `os.environ.get(...)` in `safe_browsing.py`
  - never hardcoded, never logged, never included in any API response
    sent to the browser.
- `.env` is git-ignored. Only `.env.example` (which contains no real
  values) is committed.
- If a Safe Browsing API call fails, the error message is scrubbed to
  remove the key before being returned or logged (see
  `test_safe_browsing.py::test_api_key_never_appears_in_error_message`
  for a test that verifies this directly).
- **When deploying**, set the real key as an environment variable in
  your host's dashboard (e.g. Render → your service → Environment),
  never in a committed file.

## What data this app handles

- Email/SMS/call-transcript/app-listing text you paste is processed
  in memory for the single request and is never written to disk or a
  database. There is no persistent storage anywhere in this project.
- Website URLs you check are fetched live (to check domain age, SSL,
  redirects) - only the URL you provide is contacted, nothing else.
- No user accounts, no cookies, no tracking, no analytics.

## Personal information

- No personal information about the developer or any user is embedded
  in the codebase itself. Contact information that appears in the
  README/footer (email, GitHub handle) is intentionally public,
  the same way it would be on any project README.
- IP addresses are not logged or stored by this application's own
  code. Note that any hosting provider (Render, etc.) may log request
  IPs as part of their own standard infrastructure logging - this is
  normal for any web host and outside this application's control, but
  worth knowing.

## Reporting a concern

If you find a real security issue in this code, please open a GitHub
issue describing it - this is a portfolio/learning project, not
production infrastructure handling real user data at scale, but
correctness still matters.
