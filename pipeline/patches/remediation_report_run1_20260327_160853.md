# CVE Remediation Report - Run #1

**Generated:** 2026-03-27 16:08:53
**Source:** `C:\Users\riddh\OneDrive\Documents\CVE_Patch_Finder\pipeline\reports\Snyk.json`

## Summary
| Status | Count |
|--------|-------|
| Auto-patched | 0 |
| Needs review | 5 |
| Manual       | 2 |

---

## Assessments

### axios  [NEEDS REVIEW]

| Field | Value |
|-------|-------|
| CVE ID(s) | CVE-2026-25639, CVE-2021-3749, CVE-2023-45857 |
| Title | Prototype Pollution |
| Installed | `0.18.0` |
| Target version | `1.14.0` |
| npm latest | `1.14.0` |
| Is npm latest | Yes |
| Confidence | 70% |
| Patch available | Yes |
| CVSS Score | 7.5 |
| Deprecated | No |

**Description:** Axios is a promise based HTTP client for the browser and Node.js. Prior to versions 0.30.3 and 1.13.5, the mergeConfig function in axios crashes with a TypeError when processing configuration objects containing __proto__ as an own property. An attacker can trigger this by providing a malicious confi...

**References:**
- https://github.com/axios/axios/commit/28c721588c7a77e7503d0a434e016f852c597b57
- https://github.com/axios/axios/commit/d7ff1409c68168d3057fc3891f911b2b92616f9e
- https://github.com/axios/axios/pull/7369

---

### body-parser  [NEEDS REVIEW]

| Field | Value |
|-------|-------|
| CVE ID(s) | CVE-2024-45590, CVE-2024-45590 |
| Title | Asymmetric Resource Consumption (Amplification) |
| Installed | `1.18.2` |
| Target version | `2.2.2` |
| npm latest | `2.2.2` |
| Is npm latest | Yes |
| Confidence | 70% |
| Patch available | Yes |
| CVSS Score | 7.5 |
| Deprecated | No |

**Description:** body-parser is Node.js body parsing middleware. body-parser <1.20.3 is vulnerable to denial of service when url encoding is enabled. A malicious actor using a specially crafted payload could flood the server with a large number of requests, resulting in denial of service. This issue is patched in 1....

**References:**
- https://github.com/expressjs/body-parser/commit/b2695c4450f06ba3b0ccf48d872a229bb41c9bce
- https://github.com/expressjs/body-parser/security/advisories/GHSA-qwcr-r2fm-qrc7

---

### brace-expansion  [NEEDS REVIEW]

| Field | Value |
|-------|-------|
| CVE ID(s) | CVE-2026-33750, CVE-2026-33750 |
| Title | Infinite loop |
| Installed | `1.1.12` |
| Target version | `5.0.5` |
| npm latest | `5.0.5` |
| Is npm latest | Yes |
| Confidence | 50% |
| Patch available | Yes |
| CVSS Score | 6.5 |
| Deprecated | No |

**Description:** The brace-expansion library generates arbitrary strings containing a common prefix and suffix. Prior to versions 5.0.5, 3.0.2, 2.0.3, and 1.1.13, a brace pattern with a zero step value (e.g., `{1..2..0}`) causes the sequence generation loop to run indefinitely, making the process hang for seconds an...

**References:**
- https://github.com/juliangruber/brace-expansion/blob/daa71bcb4a30a2df9bcb7f7b8daaf2ab30e5794a/src/index.ts#L107-L113
- https://github.com/juliangruber/brace-expansion/blob/daa71bcb4a30a2df9bcb7f7b8daaf2ab30e5794a/src/index.ts#L184
- https://github.com/juliangruber/brace-expansion/commit/311ac0d54994158c0a384e286a7d6cbb17ee8ed5

---

### lodash  [NEEDS REVIEW]

| Field | Value |
|-------|-------|
| CVE ID(s) | CVE-2021-23337, CVE-2019-10744, CVE-2020-8203, SNYK-JS-LODASH-608086, SNYK-JS-LODASH-6139239, CVE-2018-16487 |
| Title | Code Injection |
| Installed | `4.17.4` |
| Target version | `4.17.23` |
| npm latest | `4.17.23` |
| Is npm latest | Yes |
| Confidence | 70% |
| Patch available | Yes |
| CVSS Score | 7.2 |
| Deprecated | No |

**Description:** Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function....

**References:**
- https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf
- https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js%23L14851
- https://security.netapp.com/advisory/ntap-20210312-0006/

---

### qs  [MANUAL]

| Field | Value |
|-------|-------|
| CVE ID(s) | CVE-2025-15284, CVE-2022-24999, CVE-2025-15284, CVE-2022-24999, CVE-2025-15284, CVE-2022-24999 |
| Title | Allocation of Resources Without Limits or Throttling |
| Installed | `6.5.1` |
| Target version | `6.15.0` |
| npm latest | `6.15.0` |
| Is npm latest | Yes |
| Confidence | 30% |
| Patch available | Yes |
| CVSS Score | 3.7 |
| Deprecated | No |

**Description:** Improper Input Validation vulnerability in qs (parse modules) allows HTTP DoS.This issue affects qs: < 6.14.1.


Summary

The arrayLimit option in qs did not enforce limits for bracket notation (a[]=1&a[]=2), only for indexed notation (a[0]=1). This is a consistency bug; arrayLimit should apply unif...

**References:**
- https://github.com/ljharb/qs/commit/3086902ecf7f088d0d1803887643ac6c03d415b9
- https://github.com/ljharb/qs/security/advisories/GHSA-6rw7-vpxm-498p

---

### serialize-javascript  [MANUAL]

| Field | Value |
|-------|-------|
| CVE ID(s) | CVE-2019-16772, CVE-2020-7660, CVE-2019-16769 |
| Title | Cross-site Scripting (XSS) |
| Installed | `1.7.0` |
| Target version | `7.0.5` |
| npm latest | `7.0.5` |
| Is npm latest | Yes |
| Confidence | 30% |
| Patch available | Yes |
| CVSS Score | 3.1 |
| Deprecated | No |

**Description:** The serialize-to-js NPM package before version 3.0.1 is vulnerable to Cross-site Scripting (XSS). It does not properly mitigate against unsafe characters in serialized regular expressions. This vulnerability is not affected on Node.js environment since Node.js's implementation of RegExp.prototype.to...

**References:**
- https://github.com/commenthol/serialize-to-js/commit/181d7d583ae5293cd47cc99b14ad13352875f3e3
- https://github.com/commenthol/serialize-to-js/security/advisories/GHSA-3fjq-93xj-3f3f
- https://github.com/commenthol/serialize-to-js/commit/181d7d583ae5293cd47cc99b14ad13352875f3e3

---

### tar  [NEEDS REVIEW]

| Field | Value |
|-------|-------|
| CVE ID(s) | CVE-2026-26960, CVE-2026-29786, CVE-2026-31802 |
| Title | Directory Traversal |
| Installed | `4.4.19` |
| Target version | `7.5.12` |
| npm latest | `7.5.13` |
| Is npm latest | No - newer version has known issues |
| Confidence | 70% |
| Patch available | Yes |
| CVSS Score | 7.1 |
| Deprecated | No |

**Description:** node-tar is a full-featured Tar for Node.js. When using default options in versions 7.5.7 and below, an attacker-controlled archive can create a hardlink inside the extraction directory that points to a file outside the extraction root, enabling arbitrary file read and write as the extracting user. ...

**References:**
- https://github.com/isaacs/node-tar/commit/2cb1120bcefe28d7ecc719b41441ade59c52e384
- https://github.com/isaacs/node-tar/commit/d18e4e1f846f4ddddc153b0f536a19c050e7499f
- https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx

---
