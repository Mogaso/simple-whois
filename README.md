# WHOIS & DNS Lookup

A lightweight, **private WHOIS + DNS lookup** tool implemented as a single PHP file (no frameworks, no Composer, no CLI tools). Modern, responsive UI (dark-mode first), with file-based caching and simple rate limiting. Ideal for shared hosting.

---

## ✨ Features

- **Input**: Domain/hostname (IDN supported) or IP (v4/v6)
- **Deep linking**: `?q=example.com` loads results directly
- **Quick Mode**: optional, resolves only A/AAAA + short WHOIS
- **WHOIS (Port 43)**:
  - TLD discovery via **IANA** → then query the proper registry WHOIS
  - Follows **referrals** (Registrar WHOIS) when provided
  - IDN: Unicode input → Punycode (ACE) with a visible note
  - Best-effort parsing (Registrar, Status, Dates, Nameservers, Contacts)
  - Privacy note: acknowledges redaction/DSGVO limitations
- **DNS** (read-only via `dns_get_record`):
  - A, AAAA, CNAME, NS, MX, TXT, SOA, SRV, CAA
  - Reverse-DNS attempts (PTR) for resolved A/AAAA
  - DNSSEC hint if DS/RRSIG records are present
- **UI/UX**:
  - Single-page app, tabs: **Overview / WHOIS / DNS / Network / Raw**
  - Copy buttons + subtle toasts, shareable link button
  - Mobile-first, dark-mode first, accessible (labels, ARIA, focus styles)
  - Print stylesheet (prints Overview + core WHOIS)
- **Operational**:
  - **File cache** (JSON + raw WHOIS) for 15 minutes
  - **Rate limiting**: 30 requests / 5 minutes per IP
  - **Timeouts**: WHOIS socket ≤ 5s; overall script ≤ 10s
  - No CLI (`whois`, `dig`) and no external paid APIs required
- **Export**:
  - `?format=json` returns structured JSON (WHOIS+DNS+meta)

---

## ✅ Requirements

- **PHP 8.1+** (tested on 8.3)
- Extensions:
  - `intl` (recommended for IDN support; falls back gracefully)
  - `sockets` (enabled by default on many builds)
  - `dns_get_record` must be available (standard in PHP)
- Web server: Apache or Nginx (Plesk works great)
- File system:
  - `whois/cache/` must be writable by PHP (app creates it if missing)

---

## 🚀 Quick Start

1. Copy the folder to your web root:

   ```
   /httpdocs/whois/
     index.php
     cache/          # leave empty; writable
   /httpdocs/logo.png
   /httpdocs/favicon.ico
   ```

2. Ensure PHP version for the domain is **8.1+** and **`dns_get_record`** is allowed.

3. Make sure `whois/cache/` is writable (e.g., `0755` dir, web user owner).

4. Visit:

   - UI: `https://your-domain.tld/whois/`
   - Deep link: `https://your-domain.tld/whois/?q=example.com`

---

## 🔧 Configuration & Behavior

### Query parameters

- `?q=example.com` — query a domain/host/IP
- `&fast=1` — Quick Mode (A/AAAA + short WHOIS)
- `&force=1` — bypass cache (force fresh lookups)
- `&format=json` — JSON export (suitable for scripting)

**Example**  
`/whois/?q=bücher.de&fast=1` (IDN accepted; shows ACE alongside)

### Caching

- Files are written to `whois/cache/`:
  - `*.json` — structured result (WHOIS+DNS+meta)
  - `*.whois.txt` — raw WHOIS dump
- TTL: **15 minutes**
- UI shows whether data is **Live** or from **Cache** and the timestamp
- “Neu laden” button sets `force=1` to skip cache once

### Rate limiting

- Per-IP: **30 requests / 5 minutes**
- Stored in `whois/cache/ratelimit_<ip>.json`

### Timeouts

- WHOIS socket: **≤ 5s** (`default_socket_timeout`)
- Global script: **≤ 10s** (`set_time_limit(10)`)
- DNS queries use PHP’s resolver (timeout governed by system resolver)

---

## 🔒 Security

- **CSP** (Content-Security-Policy): self-only, inline CSS/JS allowed for single-file app
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: same-origin`
- **SSRF hardening**:
  - WHOIS server is discovered via **IANA** (plus a small fallback map)
  - WHOIS connections only to **publicly resolvable** hosts (no private IPs)
- **Output escaping**: all dynamic output is HTML-escaped
- Input validation:
  - Accepts only FQDN/IDN/IPv4/IPv6 (rejects URLs and invalid labels)
  - Enforces FQDN length and label rules

> **Note:** WHOIS referrals to registrar servers are followed **only** if the host resolves publicly. Some TLD registries limit Port-43 WHOIS output or block personal data for privacy.

---

## 🖼️ Branding (logo & favicon)

- Place your **logo** at the web root as `/logo.png`
- Place your **favicon** at the web root as `/favicon.ico`

Both are referenced automatically by the UI:

```html
<img class="logo" src="/logo.png" alt="Site logo" width="28" height="28">
<link rel="icon" href="/favicon.ico" sizes="any">
```

> Prefer to keep assets inside `whois/`? Put them there and update the paths in `index.php` accordingly.

---

## 🖥️ Deployment notes (Apache / Nginx)

- Ensure `open_basedir` includes the site root (Plesk default is fine)
- Directory permissions: `whois/cache/` must be writable by the PHP process
- No .htaccess rules are required; the app is a single `index.php`

**Nginx proxy** (typical): nothing special needed—static `/logo.png` and `/favicon.ico` are served from the docroot.

---

## 🧪 Test cases

Try these to validate behavior:

- `example.com` (always works; ICANN WHOIS)
- `heise.de` (DENIC formatting)
- `mogaso.eu` (EU registry)
- `bücher.de` (IDN)
- `www.heise.de` (subdomain)
- `1.1.1.1` (IP – reverse lookup only, WHOIS for IP intentionally not implemented)

---

## 🧩 JSON API

Append `&format=json` for machine-readable output.

**Example**

```
/whois/?q=example.com&fast=1&format=json
```

**Response shape (simplified)**

```json
{
  "ok": true,
  "data": {
    "meta": {
      "input": "example.com",
      "type": "domain",
      "fast": true,
      "timestamp": "2025-08-26T10:15:00+02:00",
      "cache": "fresh",
      "cached_at": "2025-08-26T10:15:00+02:00",
      "idn_note": null
    },
    "overview": {
      "domain_or_ip": "example.com",
      "canonical_ascii": "example.com",
      "registrable": "example.com",
      "tld": "com",
      "registrar": "Example Registrar, Inc.",
      "status": ["clientTransferProhibited"],
      "dates": { "created": "...", "updated": "...", "expiry": "..." },
      "nameservers": ["ns1.example.net", "ns2.example.net"],
      "ips": ["93.184.216.34"],
      "dnssec": { "has_ds": false, "has_rrsig": false }
    },
    "whois": {
      "parsed": { /* structured fields */ },
      "raw": ["## WHOIS Server: whois.verisign-grs.com\n...", "..."],
      "meta": { "tld": "com", "iana_server": "whois.iana.org", "registry_server": "...", "registrar_server": "..." }
    },
    "dns": {
      "A": [ { "host": "example.com", "ttl": 3600, "type": "A", "ip": "93.184.216.34" } ],
      "AAAA": [],
      "NS": [ ... ],
      "MX": [ ... ],
      "TXT": [ ... ],
      "SOA": [ ... ],
      "SRV": [],
      "CAA": [],
      "PTR": [ { "ip": "93.184.216.34", "ptr": "..." } ],
      "dnssec": { "has_ds": false, "has_rrsig": false }
    },
    "network": { "ptr": [ ... ] }
  }
}
```

---

## 🛠️ Customization

- **UI styling**: tweak CSS variables (colors, radii, shadows) at the top of `<style>`
- **Defaults**: change the page title, header text, or footer notice directly in `index.php`
- **WHOIS fallback map**: extend `ianaWhoisServer()` with more TLDs if desired
- **Cache TTL**: adjust the `900` seconds check where the JSON cache file’s `filemtime` is compared

---

## 🧯 Troubleshooting

- **HTTP 500** on first run:
  - Ensure `whois/cache/` exists and is writable by PHP
  - Confirm PHP is **8.1+** and `dns_get_record` is available
  - If you need to debug temporarily, uncomment at the top of the file:
    ```php
    // ini_set('display_errors','1'); error_reporting(E_ALL);
    ```
    *(Remember to disable again for production.)*

- **Empty WHOIS** for some TLDs:
  - Some registries restrict Port-43 WHOIS or require specific flags
  - The app already queries IANA and follows referrals if present

- **IDN issues**:
  - Install/enable the `intl` extension to ensure robust IDN conversion
  - Without `intl`, the app still runs but may show a conversion note or reduced IDN handling

- **Slow DNS**:
  - PHP uses the system resolver; timeouts depend on OS resolver settings
  - Overall script timeout is limited to 10s

---

## 🔎 Accessibility

- Proper labels, roles (`role="tablist"`, `role="tabpanel"`), `aria-selected`
- Keyboard navigation for tabs (Left/Right arrow)
- Focus outlines and high-contrast tokens
- Mobile: large touch targets; tables scroll horizontally

---

## 📄 License

Choose a license appropriate for your project (e.g., MIT):

```
MIT License — Copyright (c) <year> <your name>
```

---

## 🤝 Contributing

This is a single-file utility; feel free to open issues/PRs with:
- Additional TLD fallback WHOIS servers
- Parsing improvements for specific registries
- UI refinements or accessibility enhancements

---

## ✅ Checklist (before going live)

- [ ] PHP 8.1+ selected for the domain
- [ ] `whois/cache/` is writable
- [ ] `/logo.png` and `/favicon.ico` placed at web root
- [ ] `intl` extension enabled (optional, improves IDN)
- [ ] Verified with test cases (see above)
- [ ] Debug output disabled in production

---

### Enjoy your fast, private WHOIS & DNS lookup!
