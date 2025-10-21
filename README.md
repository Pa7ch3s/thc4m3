# THC4M3 — Thick Client Helper for Burp

> **Status:** MVP • Works on macOS with Burp Suite Pro/Community and Java 17.

THC4M3 is a minimal Burp extension that helps you test thick-client apps without drowning in noise. It lets you:

- **Label/annotate** only the traffic you care about (host/port/MIME filters)
- **Generate a PAC** so only app domains are proxied
- **Quick-start** instructions baked into the tab

<img alt="THC4M3 tab screenshot" src="docs/screenshot-tab.png" width="800"/>

---

## Quick start

### Requirements
- Burp Suite (Pro or Community), installed in `/Applications` on macOS
- Java 17 (Temurin recommended)

### Install

1. Build the JAR
   ```bash
   ./gradlew clean jar
   # Output: build/libs/thc4m3.jar
   
2. Burp → Extensions → Installed → Add
-  Extension type: Java
-  Extension file: build/libs/thc4m3.jar

3. Open the THC4M3 tab and set filters:
- Host allow (regex): .*(api|login|auth|gateway).*|localhost|127\.0\.0\.1
- Port allow (comma): 80,443,8080,8443
- MIME allow (regex): ^(application/json|application/xml|text/.*|application/octet-stream)$
- Click Apply Filters (or Quick Start)

Route a test request through Burp
curl --proxy http://127.0.0.1:8080 https://httpbin.org/post \
  -H "Content-Type: application/json" \
  --data '{"hello":"world"}' -v

You should see annotated rows in the THC4M3 tab and the request/response in Proxy → HTTP history.
Tip: Export Burp CA (Proxy → Proxy settings → Import/export CA) and trust in Keychain to avoid -k.


Using with your app
-  System proxy: macOS → Network → Proxies → set HTTP/HTTPS to 127.0.0.1:8080
-  PAC: In THC4M3 click Generate PAC… and use the file via Automatic Proxy Configuration
-  Java apps: launch with
-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080 -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080


