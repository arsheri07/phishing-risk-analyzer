# Changelog

## 2026-11-20

### Added
- **IDN homograph detection** (`link_analysis.check_homograph`). Punycode labels are decoded, Cyrillic/Greek lookalike letters are mapped to a Latin confusable skeleton (Unicode TR39 idea), and the skeleton is matched exactly against the brand list. Scores 40 in the Email, Text Message and Website modules; a domain that only mixes alphabets scores 15.
- **Deceptive link text** (`link_analysis.find_deceptive_anchors`). Flags `<a>` tags whose visible text names one domain while the href opens another (25 points).
- **Case log.** Every analysis in the session is listed with time, type, subject, verdict and score; click to reopen. Stored in `sessionStorage` only, subject lines only (see `SECURITY.md`).
- **Copy report.** Plain-text verdict and findings for an IT ticket or a reply to whoever forwarded the message.
- API: link objects include `is_homograph`, `homograph_target`, `unicode_domain`, `is_mixed_script`, `display_domain`.
- 17 tests (101 total) in `test_homograph.py`.

### Changed
- Project named **Phishing Risk Analyzer** everywhere (formerly Scam Shield): app header, repo `arsheri07/phishing-risk-analyzer`, live demo https://phishing-risk-analyzer-suk0.onrender.com.
- A homograph link is not also scored as a one-letter typosquat (no double counting).

### Fixed
- `email_parser` turned non-ASCII body text into literal `\uXXXX` escapes for 7bit/8bit messages, hiding lookalike letters from detection. 7bit/8bit bodies are now read as text directly.
