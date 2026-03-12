# CVE Patch Finder

A CVE remediation pipeline for Node.js projects. You give it a Snyk or npm audit report, it looks up every vulnerability on NVD, finds the latest safe version for each package on npm, and patches your package.json automatically. After patching it runs your test suite and rolls back if anything breaks.

No API key needed. No paid services. Just Python and two public APIs.

---

## What it actually does

Most developers know their dependencies are vulnerable but fixing them is tedious — you have to look up each CVE, figure out what version fixes it, decide if it is safe to upgrade, and then update the file. CVE Patch Finder handles all of that in one command.

It runs in five steps:

1. Parses the vulnerability report and pulls out every CVE ID, affected package, and installed version
2. Prints a table so you can see the full picture before anything changes
3. Looks up each CVE on the NVD API to get the CVSS score and patch details
4. Queries the npm registry to find the latest published version that actually fixes the CVE
5. Updates package.json, runs your tests, and rolls back if tests fail

---

## Project structure

```
CVE_Patch_Finder/
├── vulnerable-shopping-app/
│   ├── package.json          <- deliberately old/vulnerable versions
│   ├── server.js             <- Express API
│   ├── public/index.html     <- served at /shop
│   └── tests/app.test.js     <- Jest tests (8 tests)
├── pipeline/
│   ├── cve_patch_finder.py   <- the pipeline
│   └── reports/              <- put your scan reports here
├── scan.sh
└── README.md
```

---

## Requirements

- Python 3.9+
- Node.js 16+

No pip packages needed, the pipeline only uses the standard library.

---

## Running the project

**Step 1 — install app dependencies**

```cmd
cd vulnerable-shopping-app
npm install
cd ..
```

**Step 2 — generate a Snyk report**

```cmd
cd vulnerable-shopping-app
snyk auth
snyk test --json > ..\pipeline\reports\Snyk_report.json
cd ..
```

If you don't have Snyk, you can use npm audit instead:

```cmd
cd vulnerable-shopping-app
npm audit --json > ..\pipeline\reports\npm_audit_report.json
cd ..
```

**Step 3 — run the pipeline**

```cmd
python pipeline\cve_patch_finder.py --format snyk --report pipeline\reports\Snyk_report.json --app-dir vulnerable-shopping-app --patch-all
```

**Step 4 — install the patched versions**

```cmd
cd vulnerable-shopping-app
npm install
```

**Step 5 — verify**

```cmd
npm audit
npm test
```

---

## Command options

```
--report PATH       path to the scan report JSON
--format            snyk or npm (auto-detected from filename)
--app-dir PATH      folder containing package.json
--severity          severity levels to include, e.g. critical,high,medium
                    default is critical,high
--patch-all         apply everything including packages flagged for review
--dry-run           show what would change without touching any files
```

---

## Why Snyk over npm audit

Snyk reports include the real CVE ID directly in an `identifiers.CVE` field, a CVSS score per vulnerability in `cvssDetails`, and the exact fix version in `fixedIn`. This makes it straightforward to feed into the pipeline.

npm audit uses GHSA IDs rather than CVE IDs, and its severity scale is different — the same vulnerability that npm audit calls critical, Snyk often classifies as high. This caused a real issue during development where the pipeline was finding zero results because it was filtering for `critical` only.

Both formats are supported. Snyk just gives cleaner data.

---

## How confidence scoring works

After looking up a CVE on NVD, the pipeline gets a CVSS base score back. That score is mapped directly to NVD's own severity bands to produce a confidence value:

| CVSS range | NVD severity | Confidence | Decision |
|---|---|---|---|
| 9.0 - 10.0 | Critical | 90% | AUTO_PATCH |
| 7.0 - 8.9  | High     | 70% | REVIEW     |
| 4.0 - 6.9  | Medium   | 50% | REVIEW     |
| 0.1 - 3.9  | Low      | 30% | MANUAL     |
| unknown    | -        | 60% | REVIEW     |

The thresholds are based on NVD's own classification rather than arbitrary values, so there is a real justification for each one.

A score of 80 or above gets auto-patched. Between 50 and 79 gets flagged for review. Below 50 is left for manual handling. The `--patch-all` flag overrides all of this and patches everything.

---

## Safety

Before modifying anything the pipeline saves a backup of your package.json as `package.json.bak_run1`. After patching it runs `npm test`. If the tests fail it copies the backup back and exits. The `--dry-run` flag lets you preview everything without touching any files.

---

## Output reports

Every run writes two files to `pipeline/patches/`:

- `remediation_report_run1_TIMESTAMP.md` — human readable, has the CVE details, CVSS scores, what was patched and what wasn't
- `remediation_report_run1_TIMESTAMP.json` — same data in JSON if you want to process it further

---

## The demo app

`vulnerable-shopping-app` is a simple Express shopping API with dependencies pinned to old versions that have real CVEs. It exists so you have something to actually run the pipeline against.

| Package | Version | CVE |
|---|---|---|
| lodash | 4.17.4 | CVE-2019-10744 (prototype pollution) |
| axios | 0.18.0 | CVE-2023-45857 (cookie exposure) |
| serialize-javascript | 1.7.0 | CVE-2019-16769 (XSS) |
| minimist | 1.2.0 | CVE-2020-7598 (prototype pollution) |
| jsonwebtoken | 8.3.0 | CVE-2022-23529 (RCE) |
| ejs | 3.1.6 | CVE-2022-29078 (template injection) |
| node-fetch | 2.6.0 | CVE-2022-0235 (SSRF) |
| body-parser | 1.18.0 | CVE-2024-45590 (DoS) |

To start the app:

```cmd
cd vulnerable-shopping-app
node server.js
```

API runs at `http://localhost:3000` and the UI at `http://localhost:3000/shop`.

To run the tests:

```cmd
npm test
```

---

## APIs used

The pipeline makes calls to two public APIs, both free with no account required.

`services.nvd.nist.gov/rest/json/cves/2.0` — the NVD CVE database. Rate limited to 5 requests per 30 seconds without an API key, so the pipeline waits 1 second between lookups.

`registry.npmjs.org/{package}` — the npm package registry. Returns every published version of a package so the pipeline can find the highest version that is still >= the minimum fix version.

---

## Notes

- `pipeline/patches/` and `*.bak_*` files are excluded from git via `.gitignore`
- All file reads and writes use explicit UTF-8 encoding to avoid crashes on Windows
- Paths are resolved to absolute before use to prevent issues with relative paths on Windows
