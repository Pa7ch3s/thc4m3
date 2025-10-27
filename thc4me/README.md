## Supported formats and limits

- macOS
  - `.dmg`: mount via `hdiutil`, enumerate `.app` and `.pkg`.
  - `.app`: `Info.plist`, codesign info, Gatekeeper assess, optional entropy, embedded `.zip/.jar` sample, optional Java keyword scan.
  - `.pkg`: identifier/version from `Distribution` and `PackageInfo` with `xar` fallback; payload sample; Gatekeeper `--type install`.

- Windows
  - `.exe`: PE presence flag and file entropy. No Authenticode verification yet.
  - `.msi`: CFB/Microsoft OLE magic check and entropy. No property-table parsing yet.

- Scripts
  - `.bat`/`.cmd`: first 80 lines plus primitive indicator hits.

- Mobile
  - `.apk`: ZIP structure, manifest presence, dex count, entry sample, entropy.
  - `.ipa`: ZIP structure, `Payload/*/*.app/Info.plist` for bundle id and version, provisioning presence, entry sample.

### Exit codes

- `0` success
- `2` no paths matched
- `>0` other failures

### Schema

Each top-level item includes `"schema_version": <int>`. Current default: `1`.
