# Anti-wiew 3.0

Browser file scanner. Standalone repository: https://github.com/fomtimaz3-coder/antivirus-next

## Implemented

- Actual libyara 4.5.8 compiled to WASM by `.github/workflows/yara-wasm.yml`; native wrapper and smoke test included. Browser scans run in isolated workers with a 15-second deadline and a 32 MiB file limit. Files above that limit still receive streaming SHA-256, with skipped coverage clearly reported.
- Eight selected community rules: EICAR (test), WannaCry and Petya. This is a small historical starter corpus, **not a comprehensive or current antivirus database**. Rules preserve their authors/metadata and GPL-2.0 license in `rules/`. Native YARA license in `vendor/YARA-LICENSE`. Rules using optional native modules are not supported by this browser integration.
- Opt-in VirusTotal SHA-256 lookup through a same-origin Vercel endpoint, before local scanning. File bytes never go to that endpoint. Bring your own API key, kept in page memory only. Hash and key pass through the relay; the hash is disclosed to VirusTotal. IndexedDB verdict cache: six hours. Requests serialized at 16-second intervals per tab. Provider quotas/terms still apply; multiple tabs/devices can exceed them. No shared API credentials are deployed.
- No-detection and unknown reputation results never bypass local analysis. A negative Bloom test only excludes membership in the imported hash set, not malware.
- Bounded DEX header/string/type/method-reference parsing, PE sections/imports/TLS callback addresses/resource directory location, ELF sections/dynamic imports, executable section entropy, contextual script text indicators. These are static indicators, not execution traces or proof of malware.
- Bounded ZIP extraction, CRC verification, APK binary manifest and per-entry YARA/static analysis; no recursive extraction. Limits: 500 entries, 32 MiB/entry, 128 MiB total, compression ratio 200.
- Separate signature manifest version, SHA-256 integrity checks, compilation validation before activating a downloaded pack, cached last working pack. Update on reconnect and every six hours while open; closed-tab updates are not guaranteed.
- Empirical SHA-256 benchmark replaces `deviceMemory`; adaptive concurrency responds to measured throughput and UI lag.
- Detailed persisted reports, selective removal, JSON export, dark/light themes, installable offline UI.

## Explicitly unfinished

ClamAV CVD/CLD signature semantics and authenticity validation, Hybrid Analysis, VBA extraction/decompression, Mach-O structural parsing, APK cryptographic signature verification, real quarantine and durable feedback backend. There is no device-wide protection, system scanning, execution sandbox, or claim that a no-match file is safe. Unknown formats and skipped steps remain visible in reports.

## Run and verify

`npm test` exercises the real WASM with the selected rule corpus, SHA-256 boundaries, hash lookup, malformed containers, ZIP/CRC limits, APK manifest, basic structural fixtures and scheduler behavior.

`npm start` serves the static UI locally. The `/api/reputation` route requires Vercel; it is not provided by the Python static server. Deployment uses the repository root, with `api/reputation.mjs` as a Node function. No framework build is required.

WASM rebuild: trigger the GitHub Actions workflow. It compiles a pinned YARA tag with pinned Emscripten, runs the native smoke test and commits the engine artifacts. Full app tests must also pass before release. Source: https://github.com/VirusTotal/yara/tree/v4.5.8

Community provenance: https://github.com/Yara-Rules/rules ; EICAR blob dad545a504447795ea7c12487fb8c0ca859e383f, WannaCry source blob ac2f175f9c704d0525c0fcb06952dd9944e6c5f7, Petya blob 61cbcc7795c67bc462797cc3509f50a97d6f7863. The selected WannaCry subset is documented in its file header. Publication date of our pack is not the age of the original rules (2016–2017).
