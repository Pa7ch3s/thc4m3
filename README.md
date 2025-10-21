# THC4M3 — Thick Client Helper for Burp
![Build](https://github.com/Pa7ch3s/THC4me/actions/workflows/build.yml/badge.svg?branch=main)
[![Release workflow](https://github.com/Pa7ch3s/THC4me/actions/workflows/release.yml/badge.svg)](https://github.com/Pa7ch3s/THC4me/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **Status:** MVP (pre-release). Tested on macOS with Burp Suite Pro/Community and Java 17.
> THC4M3 is a minimal Burp extension that helps you test thick-client apps without drowning in noise: label/annotate only the traffic you care about, and generate a quick PAC file.
---

## ✨ What it does

- **Events table** that logs/labels interesting requests & responses  
- **Allow-lists** for **Host (regex)**, **Port (CSV)**, **MIME (regex)**  
- **Show/annotate only matching traffic** to reduce noise  
- **PAC generator** to route only your target domains via Burp  
- **Checklist sub-tab** for thick-client test setup (save/load/export)

No telemetry. Everything runs inside Burp.

<img width="150" height="170" alt="image" src="https://github.com/user-attachments/assets/41c58eee-93d4-446c-9b15-9396bd3f183c" />

---

## 🔧 Install

1. Download the latest `thc4m3.jar` from **[Releases](../../releases)**.  
2. In Burp: **Extensions → Installed → Add → Java** and select the JAR.  
3. Confirm the **THC4M3** tab appears.

> If you’re on macOS and running Burp from a mounted **.dmg**, copy it to `/Applications` first.  
> If HTTPS fails due to TLS interception, install Burp’s CA certificate in your OS trust store or use `curl -k` during smoke tests.

---

## ⚡ Quick start (MVP)

1. In the **THC4M3** tab, set:
   - **Host allow (regex):** e.g. `.*(api|login|auth|gateway).*|localhost|127\.0\.0\.1`
   - **Port allow (comma):** `80,443,8080,8443`
   - **MIME allow (regex):** `^(application/json|application/xml|text/.*|application/octet-stream)$`
2. Click **Apply Filters**.
3. (Optional) Click **Generate PAC…** and use it in your app/OS to only proxy target hosts via Burp.

**Smoke tests**

```bash
# Send traffic through Burp on 127.0.0.1:8080
curl --proxy http://127.0.0.1:8080 -k https://postman-echo.com/get -I
curl --proxy http://127.0.0.1:8080 -k https://postman-echo.com/post \
  -H "Content-Type: application/json" --data '{"hello":"world"}'
