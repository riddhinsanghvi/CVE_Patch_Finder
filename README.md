# CVE Patch Finder

An automated CVE remediation pipeline for Node.js projects. Give it a Snyk or npm audit report and it looks up every vulnerability on NVD, checks GitHub Advisories and the official library changelog for the latest safe version, detects whether each vulnerable package is a direct or transitive dependency, and patches your package.json accordingly. After patching it runs your test suite and rolls back if anything breaks.

No API key needed. No paid services. Just Python and public APIs.

---

## What it does

Most developers know their dependencies are vulnerable but fixing them manually is tedious. CVE Patch Finder handles the entire process in one command:

1. Parses the vulnerability report and extracts every CVE ID, affected package, and installed version
2. Prints a table so you can see the full picture before anything changes
3. Looks up each CVE on NVD to get the CVSS score and severity
4. For each vulnerable package, finds the latest safe version by checking three sources
5. Detects whether the package is a direct or transitive dependency and traces which parent brought it in
6. Patches package.json directly for direct deps, or writes to the overrides section for transitive deps
7. Runs your test suite after patching and restores the backup if tests fail

---

## How the latest safe version is picked

The pipeline does not just use the minimum fix version the scanner recommends. It starts at the latest published version and walks backwards, checking each candidate across three layers before accepting it:

**Layer 1 — NVD:** checks whether the candidate version falls inside the affected version range of any known CVE.

**Layer 2 — GitHub Advisory Database:** catches advisories that maintainers file on GitHub before NVD processes them, and advisories NVD never picks up at all. This is the same source npm audit itself uses.

**Layer 3 — Official changelog:** fetches the CHANGELOG and release notes from the official GitHub repo and scans for security-specific keywords. This catches vulnerabilities that maintainers fix quietly without ever filing a CVE or advisory.

The first candidate that is clean across all three layers gets chosen. If nothing is clean above the minimum fix version, the pipeline falls back to the fix version itself. Results are memoized so the same package version is never checked twice in a single run.

---

## How transitive dependencies are handled

A transitive dependency is a package that was pulled in by one of your dependencies rather than being listed in your package.json directly. For example `qs` comes in through `express` — it is never in your package.json but your project is still vulnerable if `qs` has a CVE.

The pipeline detects this by checking whether the vulnerable package appears in your `dependencies` or `devDependencies`. If it does not, it runs `npm ls` to walk the full installed dependency tree and identify which of your direct dependencies is responsible for pulling it in.

For the fix, since you cannot patch a transitive dep directly in package.json, the pipeline writes it to the `overrides` section instead:

```json
"overrides": {
    "qs": "6.15.0"
}
```

npm reads this section during installation and forces that version throughout the entire dependency tree, regardless of what any parent package originally declared.

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

No pip packages needed. The pipeline uses only the Python standard library.

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

If you do not have Snyk, use npm audit instead:

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

Snyk reports include the real CVE ID directly in an `identifiers.CVE` field, a CVSS score per vulnerability, and the exact fix version in `fixedIn`. npm audit uses GHSA IDs rather than CVE IDs and its severity scale differs from NVD — the same vulnerability that npm audit calls critical, Snyk often classifies as high. Both formats are supported but Snyk gives cleaner data.

---

## Confidence scoring

After looking up a CVE on NVD the pipeline maps the CVSS score to a confidence value using NVD's own severity bands:

| CVSS range | NVD severity | Confidence | Decision |
|---|---|---|---|
| 9.0 - 10.0 | Critical | 90% | AUTO_PATCH |
| 7.0 - 8.9  | High     | 70% | REVIEW     |
| 4.0 - 6.9  | Medium   | 50% | REVIEW     |
| 0.1 - 3.9  | Low      | 30% | MANUAL     |
| unknown    | -        | 60% | REVIEW     |

A score of 80 or above gets auto-patched. Between 50 and 79 gets flagged for review. Below 50 is left for manual handling. The `--patch-all` flag overrides all of this and patches everything.

---

## Safety mechanisms

Before modifying anything the pipeline saves a backup of your package.json as `package.json.bak_run1`. After patching it runs `npm test`. If the tests fail the original package.json is restored automatically. The `--dry-run` flag lets you preview everything without touching any files.

---

## Output reports

Every run writes two files to `pipeline/patches/`:

- `remediation_report_run1_TIMESTAMP.md` — human readable, includes CVE details, CVSS scores, dependency type, chosen version, whether it is the npm latest, and what was patched
- `remediation_report_run1_TIMESTAMP.json` — same data in JSON for downstream tooling

---

## The demo app

`vulnerable-shopping-app` is a simple Express shopping API with dependencies pinned to old versions that have real CVEs. It exists so you have something to actually run the pipeline against.

| Package | Version | CVE | Type |
|---|---|---|---|
| lodash | 4.17.4 | CVE-2019-10744 | Prototype pollution |
| axios | 0.18.0 | CVE-2023-45857 | Cookie exposure |
| serialize-javascript | 1.7.0 | CVE-2019-16769 | XSS |
| minimist | 1.2.0 | CVE-2020-7598 | Prototype pollution |
| jsonwebtoken | 8.3.0 | CVE-2022-23529 | RCE |
| ejs | 3.1.6 | CVE-2022-29078 | Template injection |
| node-fetch | 2.6.0 | CVE-2022-0235 | SSRF |
| body-parser | 1.18.0 | CVE-2024-45590 | DoS |

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

All three are free and require no account or API key.

`services.nvd.nist.gov/rest/json/cves/2.0` — the NVD CVE database. Rate limited to 5 requests per 30 seconds without an API key so the pipeline waits 1 second between lookups.

`registry.npmjs.org/{package}` — the npm package registry. Returns every published version of a package so the pipeline can find the highest version that is still above the minimum fix version.

`api.github.com/advisories` — the GitHub Advisory Database. Returns security advisories filed by package maintainers. Rate limited to 60 requests per hour unauthenticated.

---

## Notes

- `pipeline/patches/` and `*.bak_*` files are excluded from git via `.gitignore`
- All file reads and writes use explicit UTF-8 encoding to avoid crashes on Windows
- Paths are resolved to absolute before use to prevent issues with relative paths on Windows
- The `overrides` section in package.json is created automatically if it does not exist
