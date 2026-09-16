# Anti-wiew 3.3.0

Browser file scanner. Standalone repository: https://github.com/fomtimaz3-coder/antivirus-next

## Implemented

- Actual libyara 4.5.8 compiled to WASM by `.github/workflows/yara-wasm.yml`; native wrapper and smoke test included. Browser scans run in isolated workers with a 15-second deadline and a 32 MiB file limit. Files above that limit still receive streaming SHA-256, with skipped coverage clearly reported.
- Bundled fallback: eight selected community rules: EICAR (test), WannaCry and Petya. This is a small historical starter corpus, **not a comprehensive or current antivirus database**. Rules preserve their authors/metadata and GPL-2.0 license in `rules/`. Native YARA license in `vendor/YARA-LICENSE`. Rules using optional native modules are not supported by this browser integration.
- Opt-in VirusTotal SHA-256 lookup through a same-origin Vercel endpoint, before local scanning. File bytes never go to that endpoint. Bring your own API key, kept in page memory only. Hash and key pass through the relay; the hash is disclosed to VirusTotal. IndexedDB verdict cache: six hours. Requests serialized at 16-second intervals per tab. Provider quotas/terms still apply; multiple tabs/devices can exceed them. No shared API credentials are deployed.
- No-detection and unknown reputation results never bypass local analysis. A negative Bloom test only excludes membership in the imported hash set, not malware.
- Bounded DEX header/string/type/method-reference parsing, PE sections/imports/TLS callback addresses/resource directory location, ELF sections/dynamic imports, executable section entropy, contextual script text indicators. These are static indicators, not execution traces or proof of malware.
- Bounded ZIP extraction, CRC verification, APK binary manifest and per-entry YARA/static analysis; bounded recursive extraction (see 3.1). Limits: 500 entries, 32 MiB/entry, 128 MiB total, compression ratio 200.
- Separate signature manifest version, SHA-256 integrity checks, compilation validation before activating a downloaded pack, cached last working pack. Update on reconnect and every six hours while open; closed-tab updates are not guaranteed.
- Empirical SHA-256 benchmark replaces `deviceMemory`; adaptive concurrency responds to measured throughput and UI lag.
- Detailed persisted reports, selective removal, JSON export, dark/light themes, installable offline UI.

## Explicitly unfinished

ClamAV CVD/CLD signature semantics and authenticity validation, Hybrid Analysis, VBA extraction/decompression, APK cryptographic signature verification, real quarantine and durable feedback backend. There is no device-wide protection, system scanning, execution sandbox, or claim that a no-match file is safe. Unknown formats and skipped steps remain visible in reports.

## Run and verify

`npm test` exercises the real WASM with the selected rule corpus, SHA-256 boundaries, hash lookup, malformed containers, ZIP/CRC limits, APK manifest, basic structural fixtures and scheduler behavior.

`npm start` serves the static UI locally. The `/api/reputation` route requires Vercel; it is not provided by the Python static server. Deployment uses the repository root, with `api/reputation.mjs` as a Node function. No framework build is required.

WASM rebuild: trigger the GitHub Actions workflow. It compiles a pinned YARA tag with pinned Emscripten, runs the native smoke test and commits the engine artifacts. Full app tests must also pass before release. Source: https://github.com/VirusTotal/yara/tree/v4.5.8

Community provenance: https://github.com/Yara-Rules/rules ; EICAR blob dad545a504447795ea7c12487fb8c0ca859e383f, WannaCry source blob ac2f175f9c704d0525c0fcb06952dd9944e6c5f7, Petya blob 61cbcc7795c67bc462797cc3509f50a97d6f7863. The selected WannaCry subset is documented in its file header. Publication date of our pack is not the age of the original rules (2016–2017).

## 3.1 update

- History filters stack on mobile, with explicit min-width constraints and a viewport-bounded fixed navigation bar. `qa/mobile.html` is a responsive regression fixture, not a user-facing menu item.
- ZIP extraction now descends two nested levels beyond the outer archive. Every level shares the same 500-entry and 128 MiB expanded-byte budgets. Full nested paths and depth/budget skips remain in reports.
- Mach-O thin 32/64-bit and universal headers, segments/sections, dylib dependencies, rpaths, encryption and signature-directory metadata. No signature verification or execution. Universal sections retain their per-architecture offsets; entropy is calculated per architecture as of 3.3.
- Two optional hash reputation services: VirusTotal then MalwareBazaar. Only services whose keys the user entered receive the hash. A detection stops fallback; unknown/no-detection/error proceeds to the next configured service. Neither negative result bypasses local scanning. Keys remain in page memory, and cache entries are separated by service.
- Daily GitHub Actions feed job downloads the **public** Malpedia auto ZIP, accepts only explicit CC BY-SA 4.0 and TLP:WHITE/CLEAR rules, retains original metadata, splits by platform and size, and tests every shard in the actual WASM before committing. Source and per-rule hashes are preserved in `rules/malpedia-provenance.json`. No private feed or token is used.
- The browser retrieves the committed manifest directly from the project GitHub repository, independently of Vercel deployment. Rules are downloaded lazily for matching PE/ELF/Mach-O formats; cached shards support subsequent offline scans. A bundled eight-rule set is the offline bootstrap fallback. Failed updates retain the previous pack. SHA-256 verifies file consistency; trust is the HTTPS origin and repository, not a cryptographic publisher signature.
- Each YARA invocation has a 15-second worker deadline. Malpedia batch scanning also has a 60-second budget checked between shards. The current operation may run beyond that check; any unscanned shards are explicit partial coverage. A failed later shard does not erase earlier matches.
- Malware corpus harness: `node scripts/corpus-test.mjs /private/corpus.json /private/report.json`. Cases require `path`, `sha256`, `label` (benign/malware), `platform` (win/elf/osx/other) and `expectedRules` (array). Only static byte scans run; no samples or keys are committed or uploaded. Reports distinguish misses/false positives/skips. VirusShare samples have **not** been tested: account access is invitation-only and no authenticated sample corpus was available. Service reply normalization tests use mocks; live reputation requests require the user's own keys.

Malpedia license: https://creativecommons.org/licenses/by-sa/4.0/ . Original rule contents are unchanged; platform shards concatenate them. Automatically generated rules may target unpacked memory samples and do not guarantee detection of packed on-disk files. The public feed currently includes Windows/ELF/macOS rules, not additional DEX rules.


## 3.3 architecture audit

See [ARCHITECTURE.md](ARCHITECTURE.md) for the inspected modules, fixed defects, validation evidence and remaining limitations.

- TAR (regular USTAR entries) and GZIP now feed the same bounded recursive scanner as ZIP. All containers share entry/expanded-byte budgets and a two-level nesting limit. GZIP output is bounded to 32 MiB. Unsupported TAR extension/link records are explicit skips. No archive is written to disk or executed.
- Imported SHA-256 matches work at every supported archive level. A damaged later ZIP/TAR record preserves earlier findings and marks the result partial.
- Online requests support cancellation, bounded storage waits and service-specific statuses. VirusTotal replies must match the requested hash; zero analyzed engines mean unknown.
- Scan intake is serialized; cancellation invalidates pending additions. Stream mode persists. Completed/cancelled queues have explicit end text; history filters synchronize their visible control.
- Cached rule age is checked on startup. Rule downloads have streaming allocation bounds. Service Worker cache includes every new runtime module.
- App/worker version comes from one module. Regression tests run for main pushes and pull requests. No real malware corpus or live user credentials were used in these tests.
