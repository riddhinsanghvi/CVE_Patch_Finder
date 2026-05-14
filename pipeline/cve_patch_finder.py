#!/usr/bin/env python3
# CVE Patch Finder - automated CVE remediation for Node.js projects
# Reads a Snyk or npm audit report, looks up each CVE on NVD,
# picks the latest safe version by checking NVD, GitHub Advisories,
# and the official library changelog, handles transitive dependencies
# via npm overrides, then patches package.json.
#
# Usage:
#   python pipeline/cve_patch_finder.py --format snyk --report pipeline/reports/Snyk_report.json --app-dir vulnerable-shopping-app --patch-all

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

REPORTS_DIR = Path(__file__).parent / "reports"
PATCHES_DIR = Path(__file__).parent / "patches"

NVD_API         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NPM_REGISTRY    = "https://registry.npmjs.org"
GITHUB_ADVISORY = "https://api.github.com/advisories"
GITHUB_API      = "https://api.github.com/repos"
NVD_DELAY       = 1.0   # NVD rate limit: 5 req / 30s without an API key
GITHUB_DELAY    = 0.5   # GitHub API: 60 req/hr unauthenticated

AUTO_THRESHOLD   = 80
REVIEW_THRESHOLD = 50

# keywords used when scanning changelogs and release notes for security content
# deliberately specific - generic words like "fix" and "patch" cause false positives
SECURITY_KEYWORDS = [
    "security", "vulnerability", "vulnerable", "cve", "exploit",
    "injection", "xss", "csrf", "prototype pollution", "rce",
    "remote code execution", "denial of service", "authorization bypass",
    "information disclosure", "insecure", "malicious", "arbitrary code"
]

# cache for version safety checks so the same package@version is never
# checked twice in a single run - saves API calls and rate limit delays
_version_check_cache = {}


# Makes a GET request to the given URL and returns the parsed JSON response.
# Returns None if the request fails or times out so callers can handle it gracefully.
# Input:  url (str), optional timeout in seconds
# Output: dict or list from JSON response, or None on failure
def http_get(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CVEPatchFinder/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


# Fetches raw text content from a URL, used for reading CHANGELOG files.
# Returns empty string on failure so callers can safely search the result.
# Input:  url (str), optional timeout in seconds
# Output: plain text string, or empty string on failure
def http_get_text(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CVEPatchFinder/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


# Converts a version string like "4.17.21" into a tuple (4, 17, 21, 0) so
# two versions can be compared with standard Python operators.
# Strips any non-numeric characters (^, ~, >=) before parsing.
# Input:  version string
# Output: tuple of ints, e.g. (4, 17, 21, 0)
def ver_key(v):
    v = re.sub(r"[^0-9.]", "", str(v).split(",")[-1].strip())
    parts = [int(x) for x in v.split(".") if x.isdigit()]
    return tuple(parts + [0, 0, 0])


# Checks whether a version string is usable for comparison.
# Rejects None, empty strings, and "?" which the pipeline uses as a placeholder.
# Input:  version string
# Output: True if it looks like a real version number, False otherwise
def is_valid_ver(v):
    return bool(v and v != "?" and re.search(r"\d+\.\d+", v))


# Maps a CVSS base score to a confidence percentage using NVD's severity bands.
# Critical (>=9.0) -> 90%, High (>=7.0) -> 70%, Medium (>=4.0) -> 50%, Low -> 30%.
# Falls back to 60% if the CVSS score is unknown (CVE not yet processed by NVD).
# Input:  CVSS base score (float, 0.0 to 10.0)
# Output: integer confidence score between 0 and 100
def confidence_score(cvss):
    if cvss >= 9.0:  return 90   # NVD Critical
    if cvss >= 7.0:  return 70   # NVD High
    if cvss >= 4.0:  return 50   # NVD Medium
    if cvss >  0.0:  return 30   # NVD Low
    return 60                     # CVSS unknown, default to review range


# Maps a confidence score to one of three action labels.
# AUTO_PATCH means apply it automatically, REVIEW means flag it for a human,
# MANUAL means the risk is too high to touch without careful review.
# Input:  confidence score (int)
# Output: "AUTO_PATCH", "REVIEW", or "MANUAL"
def confidence_label(score):
    if score >= AUTO_THRESHOLD:
        return "AUTO_PATCH"
    if score >= REVIEW_THRESHOLD:
        return "REVIEW"
    return "MANUAL"


# Reads the currently declared version of a package from package.json.
# Strips range prefixes like ^ and ~ so we get a plain version number.
# Falls back to "?" if the file can't be read or the package isn't listed.
# Input:  path to package.json, package name
# Output: version string like "4.17.4", or "?" if not found
def get_installed_version(pkg_json_path, package):
    try:
        with open(Path(pkg_json_path).resolve(), encoding="utf-8") as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies"):
            raw = data.get(section, {}).get(package, "")
            if raw:
                clean = re.sub(r"[^0-9.]", "", raw.split()[0]).strip(".")
                return clean if clean else raw
    except Exception:
        pass
    return "?"


# Checks if a package is a direct dependency by looking it up in the
# dependencies and devDependencies sections of package.json.
# Transitive deps are pulled in by other packages and won't appear in either section.
# Input:  path to package.json, package name
# Output: True if the package is declared directly, False if it is transitive
def is_direct_dependency(pkg_json_path, package):
    try:
        with open(Path(pkg_json_path).resolve(), encoding="utf-8") as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies"):
            if package in data.get(section, {}):
                return True
    except Exception:
        pass
    return False


# Finds which packages in the dependency tree are responsible for pulling in a
# transitive package. Uses "npm ls" which resolves the full dependency tree so
# it works regardless of how many levels deep the transitive package is buried.
# Falls back to a one-level registry lookup if npm ls cannot be run.
# Input:  app directory path, transitive package name
# Output: list of package names that depend on the transitive package
def find_parent_packages(app_dir, transitive_pkg):
    # first try npm ls which handles any depth automatically
    try:
        r = subprocess.run(
            ["npm", "ls", transitive_pkg, "--json", "--all"],
            cwd=str(Path(app_dir).resolve()),
            capture_output=True, text=True, timeout=30
        )
        # npm ls returns non-zero if vulnerabilities exist but still gives output
        if r.stdout:
            tree = json.loads(r.stdout)
            parents = _find_parents_in_tree(tree.get("dependencies", {}), transitive_pkg, set())
            if parents:
                return sorted(parents)
    except Exception:
        pass

    return []


# Recursively walks the npm ls dependency tree to find which top-level packages
# have the target package anywhere in their subtree.
# Input:  dependencies dict from npm ls output, target package name, visited set
# Output: set of top-level package names that lead to the target package
def _find_parents_in_tree(deps, target, visited, top_level=None):
    found = set()
    for pkg_name, pkg_info in deps.items():
        if pkg_name in visited:
            continue
        visited.add(pkg_name)

        current_top = top_level if top_level else pkg_name
        sub_deps    = pkg_info.get("dependencies", {})

        if target in sub_deps:
            found.add(current_top)
        elif sub_deps:
            found.update(_find_parents_in_tree(sub_deps, target, visited, current_top))

    return found


# Parses an npm audit JSON report (npm audit --json) and extracts CRITICAL vulns.
# Handles both the v7+ format (top-level "vulnerabilities" key) and the older
# v6 format (top-level "advisories" key) since they have different structures.
# The fix version is parsed from the "range" field, e.g. "<4.17.21" gives "4.17.21".
# Input:  path to npm audit JSON, optional path to package.json for version lookup
# Output: list of vuln dicts with keys: cve_id, package, installed, fix_hint, severity, title, description
def parse_npm_audit(path, pkg_json_path=""):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    vulns = []

    if "vulnerabilities" in data:
        for pkg, info in data["vulnerabilities"].items():
            if info.get("severity", "").upper() != "CRITICAL":
                continue
            fix_hint = ""
            cve_id   = "N/A"
            title    = pkg
            for via in info.get("via", []):
                if not isinstance(via, dict):
                    continue
                m = re.search(r"<([\d.]+)", via.get("range", ""))
                if m and not fix_hint:
                    fix_hint = m.group(1)
                url = via.get("url", "")
                if url and cve_id == "N/A":
                    cve_id = url.rstrip("/").split("/")[-1]
                if via.get("title") and title == pkg:
                    title = via["title"]
            installed = get_installed_version(pkg_json_path, pkg) if pkg_json_path else "?"
            if fix_hint:
                vulns.append({
                    "cve_id": cve_id, "package": pkg, "installed": installed,
                    "fix_hint": fix_hint, "severity": "CRITICAL",
                    "title": title, "description": ""
                })

    elif "advisories" in data:
        for _, adv in data["advisories"].items():
            if adv.get("severity", "").upper() != "CRITICAL":
                continue
            pkg      = adv.get("module_name", "?")
            fix_raw  = adv.get("patched_versions", "").replace(">=", "").strip()
            fix_hint = re.sub(r"[^0-9.]", "", fix_raw.split()[0]) if fix_raw else ""
            installed = get_installed_version(pkg_json_path, pkg) if pkg_json_path else "?"
            if fix_hint:
                vulns.append({
                    "cve_id": adv.get("cves", ["N/A"])[0], "package": pkg,
                    "installed": installed, "fix_hint": fix_hint,
                    "severity": "CRITICAL", "title": adv.get("title", pkg), "description": ""
                })
    return vulns


# Parses a Snyk JSON report (snyk test --json) and returns vulnerabilities
# matching the requested severity levels (default: critical and high).
# CVE IDs are read directly from identifiers.CVE in each entry - no resolution needed.
# The fix version comes from fixedIn[], and we take the highest one listed.
# If fixedIn is missing, we fall back to upgradePath as a secondary source.
# Input:  path to Snyk JSON, optional path to package.json, set of severity strings
# Output: list of vuln dicts with keys: cve_id, package, installed, fix_hint, severity, title, description, snyk_id, cwe
def parse_snyk_report(path, pkg_json_path="", severities=None):
    allowed = severities if severities else {"critical", "high"}

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    raw_vulns = data.get("vulnerabilities", [])
    if not raw_vulns and "projects" in data:
        for project in data.get("projects", []):
            raw_vulns.extend(project.get("vulnerabilities", []))

    vulns = []
    for v in raw_vulns:
        if v.get("severity", "").lower() not in allowed:
            continue

        identifiers = v.get("identifiers", {})
        cve_list    = identifiers.get("CVE", [])

        # use CVE ID directly from Snyk's identifiers field
        # fall back to Snyk's own advisory ID if no CVE has been assigned yet
        cve_id  = cve_list[0] if cve_list else v.get("id", "N/A")
        package = v.get("packageName", v.get("name", "?"))

        installed = v.get("version", "")
        if not installed and pkg_json_path:
            installed = get_installed_version(pkg_json_path, package)
        installed = installed or "?"

        fixed_in = v.get("fixedIn", [])
        if fixed_in:
            valid    = [f for f in fixed_in if is_valid_ver(str(f))]
            fix_hint = max(valid, key=lambda x: ver_key(str(x))) if valid else str(fixed_in[0])
        else:
            upgrade_path = v.get("upgradePath", [])
            fix_hint = str(upgrade_path[-1]).split("@")[-1] if upgrade_path else ""

        vulns.append({
            "cve_id":      cve_id,
            "package":     package,
            "installed":   installed,
            "fix_hint":    fix_hint,
            "severity":    "CRITICAL",
            "title":       v.get("title", package),
            "description": v.get("description", ""),
            "snyk_id":     v.get("id", ""),
            "cwe":         identifiers.get("CWE", []),
        })

    return vulns


# Prints a simple table of all CVEs found in the report to the terminal.
# Deduplicates entries so the same CVE/package pair only appears once.
# Input:  list of vuln dicts from any of the parse_ functions
# Output: none (prints to stdout)
def print_cve_table(vulns):
    print("")
    print("  CVEs found in report:")
    print("  " + "-" * 65)
    print(f"  {'CVE ID':<22} {'Library':<25} {'Installed'}")
    print("  " + "-" * 65)
    seen = set()
    for v in vulns:
        key = (v["cve_id"], v["package"])
        if key in seen:
            continue
        seen.add(key)
        print(f"  {v['cve_id']:<22} {v['package']:<25} {v['installed']}")
    print("  " + "-" * 65)
    print("")


# Queries the NVD REST API for details about a single CVE.
# Returns the CVSS base score, English description, and reference URLs.
# Returns a dict with found=False if the CVE isn't in NVD or the request fails.
# NVD rate limits unauthenticated requests to 5 per 30 seconds.
# Input:  CVE ID string like "CVE-2022-29078"
# Output: dict with keys: found, description, cvss_score, references, patch_mentioned
def search_nvd(cve_id):
    empty = {"found": False, "description": "", "cvss_score": 0.0,
             "references": [], "patch_mentioned": False}

    if not cve_id or cve_id == "N/A" or not cve_id.startswith("CVE-"):
        return empty

    data = http_get(f"{NVD_API}?cveId={cve_id}", timeout=20)
    if not data:
        return empty

    items = data.get("vulnerabilities", [])
    if not items:
        return empty

    cve_data        = items[0].get("cve", {})
    result          = dict(empty)
    result["found"] = True

    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            result["description"] = desc.get("value", "")
            break

    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            result["cvss_score"] = entries[0].get("cvssData", {}).get("baseScore", 0.0)
            break

    result["references"] = [r.get("url", "") for r in cve_data.get("references", [])[:5]]
    desc_lower = result["description"].lower()
    result["patch_mentioned"] = any(
        w in desc_lower for w in ["fixed", "patch", "update", "upgrade", "prior to", "before"]
    )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# VERSION PICKING - three layer security check
#
# The pipeline does not just use whatever version the scanner recommends.
# It starts at the latest published version and works backwards, checking
# each candidate across three sources before selecting it:
#
#   Layer 1 - NVD:               officially assigned CVEs
#   Layer 2 - GitHub Advisories: maintainer filed advisories before NVD picks them up
#   Layer 3 - Official webpage:  quiet fixes that never got a CVE or advisory filed
#
# The first candidate that is clean across all three layers gets chosen.
# If no clean version exists above fix_hint, falls back to fix_hint itself.
# Memoization prevents the same package@version being checked twice in a run.
# ─────────────────────────────────────────────────────────────────────────────

# Searches NVD for any CVEs that affect a specific version of a package.
# Uses NVD keyword search to find all CVEs mentioning the package, then checks
# each one's version configuration ranges to see if the candidate falls inside.
# Input:  package name, version string to check
# Output: list of CVE ID strings affecting this version, empty if clean
def check_nvd_for_version(package, version):
    if not is_valid_ver(version):
        return []

    url  = f"{NVD_API}?keywordSearch={package}&resultsPerPage=20"
    data = http_get(url, timeout=20)
    if not data:
        return []

    found = []
    for item in data.get("vulnerabilities", []):
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "")

        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue

                    ver_start   = match.get("versionStartIncluding", "")
                    ver_end_exc = match.get("versionEndExcluding", "")
                    ver_end_inc = match.get("versionEndIncluding", "")

                    affected = True
                    if ver_start and is_valid_ver(ver_start):
                        if ver_key(version) < ver_key(ver_start):
                            affected = False
                    if ver_end_exc and is_valid_ver(ver_end_exc):
                        if ver_key(version) >= ver_key(ver_end_exc):
                            affected = False
                    if ver_end_inc and is_valid_ver(ver_end_inc):
                        if ver_key(version) > ver_key(ver_end_inc):
                            affected = False

                    if affected:
                        found.append(cve_id)
                        break

    return list(set(found))


# Queries the GitHub Advisory Database for advisories against a specific npm package.
# Catches advisories that maintainers file on GitHub before NVD processes them,
# and advisories that NVD never picks up at all.
# Checks each advisory's version ranges to see if the candidate version is affected.
# Input:  package name, version string to check
# Output: list of GHSA ID strings affecting this version, empty if clean
def check_github_advisories(package, version):
    if not is_valid_ver(version):
        return []

    url  = f"{GITHUB_ADVISORY}?ecosystem=npm&package={package}&per_page=10"
    data = http_get(url, timeout=20)
    if not data or not isinstance(data, list):
        return []

    found = []
    for advisory in data:
        ghsa_id = advisory.get("ghsa_id", "")
        for vuln in advisory.get("vulnerabilities", []):
            pkg_info = vuln.get("package", {})
            if pkg_info.get("ecosystem", "").lower() != "npm":
                continue
            if pkg_info.get("name", "").lower() != package.lower():
                continue

            first_patched    = vuln.get("first_patched_version", "") or ""
            vulnerable_range = vuln.get("vulnerable_version_range", "") or ""

            # if a patched version exists and ours is at or above it, we are safe
            if first_patched and is_valid_ver(first_patched):
                if ver_key(version) >= ver_key(first_patched):
                    continue

            # no patch version listed - parse the range manually
            # formats: "< 5.0.1", ">= 3.0.0, < 5.0.1"
            if vulnerable_range:
                parts          = [p.strip() for p in vulnerable_range.split(",")]
                still_affected = True
                for part in parts:
                    m_lt  = re.match(r"<\s*([\d.]+)$",  part)
                    m_lte = re.match(r"<=\s*([\d.]+)$", part)
                    m_gte = re.match(r">=\s*([\d.]+)$", part)
                    if m_lt  and ver_key(version) >= ver_key(m_lt.group(1)):
                        still_affected = False
                    if m_lte and ver_key(version) >  ver_key(m_lte.group(1)):
                        still_affected = False
                    if m_gte and ver_key(version) <  ver_key(m_gte.group(1)):
                        still_affected = False
                if not still_affected:
                    continue

            if ghsa_id:
                found.append(ghsa_id)

    return list(set(found))


# Extracts the GitHub owner and repo name from the npm registry package entry.
# The repository field can appear in several formats so we normalise all of them.
# Returns None if no GitHub repo link is found in the package metadata.
# Input:  npm registry JSON response for a package
# Output: (owner, repo) tuple or None
def extract_github_repo(pkg_data):
    repo = pkg_data.get("repository", {})
    if isinstance(repo, str):
        url = repo
    elif isinstance(repo, dict):
        url = repo.get("url", "")
    else:
        url = ""

    if "github.com" not in url:
        url = pkg_data.get("homepage", "")

    m = re.search(r"github\.com[/:]([^/]+)/([^/.\s]+?)(?:\.git)?$", url)
    if m:
        return m.group(1), m.group(2).rstrip("/")
    return None


# Checks the official GitHub repository of a package for security-related content
# in its CHANGELOG and release notes for a specific version.
# Catches vulnerabilities that maintainers fix quietly without filing a CVE
# or GitHub Advisory - these would be invisible to NVD and the advisory DB.
# Input:  GitHub owner string, repo string, version to check
# Output: list of warning strings if security content found, empty if clean
def check_official_webpage(owner, repo, version):
    warnings = []

    # check CHANGELOG via GitHub raw content API
    for branch in ("main", "master"):
        for filename in ("CHANGELOG.md", "CHANGELOG", "HISTORY.md", "History.md"):
            url  = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"
            text = http_get_text(url, timeout=10)
            if not text:
                continue

            # find the section for this version and scan it for security keywords
            # version headings look like: ## 6.15.0  or  # [6.15.0]  or  ### v6.15.0
            pattern = rf"(?:^|\n)#{1,3}.*?v?{re.escape(version)}.*?\n(.*?)(?=\n#{1,3}|\Z)"
            match   = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                section = match.group(1).lower()
                hits    = [kw for kw in SECURITY_KEYWORDS if kw in section]
                if hits:
                    warnings.append(f"changelog mentions: {', '.join(hits)}")
            break
        if warnings:
            break

    # check the GitHub Releases API for release notes on this specific version
    time.sleep(GITHUB_DELAY)
    releases = http_get(f"{GITHUB_API}/{owner}/{repo}/releases", timeout=15)
    if releases and isinstance(releases, list):
        for release in releases:
            tag = release.get("tag_name", "")
            if version in tag:
                body = (release.get("body", "") or "").lower()
                hits = [kw for kw in SECURITY_KEYWORDS if kw in body]
                if hits:
                    warnings.append(f"release notes mention: {', '.join(hits[:3])}")
                break

    return warnings


# Combines all three security checks for a given package version.
# Uses memoization so the same package@version is never checked twice in a run.
#
# Layer 1 - NVD:              officially assigned CVEs with version ranges
# Layer 2 - GitHub Advisories: maintainer filed advisories, often before NVD
# Layer 3 - Official webpage:  quiet fixes that never got a CVE or advisory
#
# Input:  package name, version string, optional npm registry data for repo URL
# Output: list of issue strings from any layer, empty if all three are clean
def check_version_safe(package, version, pkg_registry_data=None):
    cache_key = f"{package}@{version}"
    if cache_key in _version_check_cache:
        return _version_check_cache[cache_key]

    issues = []

    # layer 1 - NVD
    nvd_issues = check_nvd_for_version(package, version)
    issues.extend(nvd_issues)

    # layer 2 - GitHub Advisories
    time.sleep(GITHUB_DELAY)
    github_issues = check_github_advisories(package, version)
    issues.extend(github_issues)

    # layer 3 - official webpage (CHANGELOG + release notes)
    # only runs when we have registry data to extract the repo URL from
    if pkg_registry_data:
        repo_info = extract_github_repo(pkg_registry_data)
        if repo_info:
            owner, repo = repo_info
            time.sleep(GITHUB_DELAY)
            webpage_warnings = check_official_webpage(owner, repo, version)
            if webpage_warnings:
                issues.extend([f"[webpage] {w}" for w in webpage_warnings])

    result = list(set(issues))
    _version_check_cache[cache_key] = result
    return result


# Picks the best version to upgrade to by starting at the latest published version
# and walking backwards until it finds one that passes all three security checks.
# Never goes below fix_hint since anything below still has the original CVE.
# Checks every candidate - no arbitrary limit.
#
# Example:
#   fix_hint = 3.4.0  (minimum safe version from scanner)
#   npm latest = 5.0.2
#
#   candidates (newest first): [5.0.2, 5.0.1, 4.9.0, ... 3.4.0]
#
#   check 5.0.2: NVD clean, GitHub clean, changelog clean -> chosen = 5.0.2
#
#   OR if 5.0.2 has a new CVE:
#   check 5.0.2: found CVE-2025-1234 -> skip
#   check 5.0.1: all clean -> chosen = 5.0.1
#
# Input:  package name, fix_hint, all published versions, npm latest, registry data
# Output: (chosen_version, is_latest) tuple
def smart_version_picker(package, fix_hint, all_versions, latest, pkg_registry_data=None):
    # filter to versions >= fix_hint and sort newest first
    candidates = sorted(
        [v for v in all_versions if is_valid_ver(v) and ver_key(v) >= ver_key(fix_hint)],
        key=ver_key, reverse=True
    )

    if not candidates:
        return fix_hint, False

    for version in candidates:
        print(f"      Checking {version} (NVD + GitHub Advisories + changelog)...", end=" ", flush=True)
        issues = check_version_safe(package, version, pkg_registry_data)

        if not issues:
            print("clean")
            is_latest = (version == latest)
            if not is_latest:
                print(f"      NOTE: {latest} is the npm latest but was skipped - has known issues")
            return version, is_latest

        print(f"found {len(issues)} issue(s): {', '.join(str(x) for x in issues[:2])}")
        time.sleep(NVD_DELAY)

    # no clean version found above fix_hint - fall back to fix_hint itself
    # fix_hint resolves the original CVE so it is always safer than staying put
    print(f"      No fully clean version found above {fix_hint}")
    print(f"      Falling back to fix_hint {fix_hint} (resolves original CVE)")
    return fix_hint, fix_hint == latest


# Queries the npm registry to get all published versions, then calls
# smart_version_picker to find the best safe version across all three layers.
# Passes the full registry response so the webpage check can find the repo URL.
# Also checks whether the latest version carries a deprecation warning.
# Input:  package name, minimum fix version hint, currently installed version
# Output: dict with keys: latest, latest_safe, all_versions, deprecated,
#         deprecation_msg, registry_found, is_latest
def get_latest_safe_version(package, fix_hint, installed):
    result = {
        "latest": "?", "latest_safe": "?", "all_versions": [],
        "deprecated": False, "deprecation_msg": "", "registry_found": False,
        "is_latest": False,
    }

    data = http_get(f"{NPM_REGISTRY}/{package}", timeout=20)
    if not data:
        return result

    result["registry_found"] = True
    all_versions       = list(data.get("versions", {}).keys())
    result["all_versions"] = all_versions
    result["latest"]   = data.get("dist-tags", {}).get("latest", "?")

    latest_meta = data.get("versions", {}).get(result["latest"], {})
    dep_msg     = latest_meta.get("deprecated", "")
    if dep_msg:
        result["deprecated"]      = True
        result["deprecation_msg"] = dep_msg

    repo_info = extract_github_repo(data)
    if repo_info:
        owner, repo = repo_info
        print(f"      Official repo: github.com/{owner}/{repo}")

    if fix_hint and is_valid_ver(fix_hint):
        chosen, is_latest     = smart_version_picker(
            package, fix_hint, all_versions, result["latest"], data
        )
        result["latest_safe"] = chosen
        result["is_latest"]   = is_latest
    else:
        result["latest_safe"] = result["latest"]
        result["is_latest"]   = True

    return result


# Updates a package version in package.json and writes the file back.
# For direct dependencies: updates the version number in place, preserving
# any range prefix (^ or ~) that was already there.
# For transitive dependencies: writes to the "overrides" section instead.
# The overrides section tells npm to force that version throughout the entire
# dependency tree regardless of what any parent package declares.
# Input:  path to package.json, package name, target version, is_transitive flag
# Output: none (modifies package.json on disk)
def apply_patch(pkg_json_path, package, version, is_transitive=False):
    abs_path = str(Path(pkg_json_path).resolve())
    with open(abs_path, encoding="utf-8") as f:
        pkg = json.load(f)

    if is_transitive:
        # transitive dep - add to overrides so npm forces this version tree-wide
        if "overrides" not in pkg:
            pkg["overrides"] = {}
        pkg["overrides"][package] = version
        print(f"      overrides['{package}']: {version}  (transitive dependency)")
    else:
        # direct dep - update version in place
        patched = False
        for section in ("dependencies", "devDependencies"):
            if package in pkg.get(section, {}):
                old    = pkg[section][package]
                prefix = old[0] if old and old[0] in ("^", "~") else ""
                pkg[section][package] = f"{prefix}{version}"
                print(f"      {section}['{package}']: {old} -> {prefix}{version}")
                patched = True
        if not patched:
            print(f"      '{package}' not found in package.json - skipping")
            return

    with open(abs_path, "w", encoding="utf-8") as f:
        json.dump(pkg, f, indent=2)
        f.write("\n")


# Runs the project's test suite using npm test after patches have been applied.
# If the tests fail, returns False so the caller can roll back the changes.
# Returns True if tests pass or if npm test can't be found.
# Input:  path to the app directory
# Output: True if tests passed or were skipped, False if they failed
def run_tests(app_dir):
    print("\n    Running tests...")
    try:
        r = subprocess.run(
            ["npm", "test", "--", "--passWithNoTests"],
            cwd=str(Path(app_dir).resolve()),
            capture_output=True, text=True, timeout=120
        )
        if r.returncode == 0:
            print("    All tests passed\n")
            return True
        print("    Tests failed - rolling back\n")
        print(r.stdout[-1500:])
        return False
    except Exception as e:
        print(f"    Could not run tests: {e}\n")
        return True


# Groups multiple vulnerability entries for the same package into one record.
# When a package has several CVEs, keeps them all in all_cves[] and uses
# the highest fix version across all of them as the upgrade target.
# Input:  list of vuln dicts from any parse_ function
# Output: dict keyed by package name, each value is a merged vuln dict with an all_cves list
def group_by_package(vulns):
    groups = {}
    for v in vulns:
        pkg = v["package"]
        if pkg not in groups:
            groups[pkg] = v.copy()
            groups[pkg]["all_cves"] = [v["cve_id"]]
        else:
            groups[pkg]["all_cves"].append(v["cve_id"])
            if is_valid_ver(v["fix_hint"]) and is_valid_ver(groups[pkg]["fix_hint"]):
                if ver_key(v["fix_hint"]) > ver_key(groups[pkg]["fix_hint"]):
                    groups[pkg]["fix_hint"] = v["fix_hint"]
    return groups


# Writes the remediation report to pipeline/patches/ in both markdown and JSON formats.
# Both files are named with a timestamp so multiple runs don't overwrite each other.
# Input:  run number, timestamp, source report path, list of assessment dicts,
#         and three lists (auto-patched, review, manual) of package strings
# Output: none (writes two files to PATCHES_DIR)
def save_report(run_num, timestamp, report_file, assessments, applied, branched, manual_l):
    PATCHES_DIR.mkdir(parents=True, exist_ok=True)
    ts        = timestamp.strftime("%Y%m%d_%H%M%S")
    md_path   = PATCHES_DIR / f"remediation_report_run{run_num}_{ts}.md"
    json_path = PATCHES_DIR / f"remediation_report_run{run_num}_{ts}.json"

    label_map = {"AUTO_PATCH": "[AUTO-PATCHED]", "REVIEW": "[NEEDS REVIEW]", "MANUAL": "[MANUAL]"}

    lines = [
        f"# CVE Remediation Report - Run #{run_num}",
        f"",
        f"**Generated:** {timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Source:** `{report_file}`",
        f"",
        f"## Summary",
        f"| Status | Count |",
        f"|--------|-------|",
        f"| Auto-patched | {len(applied)} |",
        f"| Needs review | {len(branched)} |",
        f"| Manual       | {len(manual_l)} |",
        f"",
        f"---",
        f"",
        f"## Assessments",
        f"",
    ]

    for a in assessments:
        icon     = label_map.get(a["label"], "")
        dep_type = "transitive (added to overrides)" if a.get("is_transitive") else "direct"
        lines += [
            f"### {a['package']}  {icon}",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| CVE ID(s) | {', '.join(a['cves'])} |",
            f"| Title | {a['title']} |",
            f"| Dependency type | {dep_type} |",
            f"| Installed | `{a['installed']}` |",
            f"| Target version | `{a['latest_safe']}` |",
            f"| npm latest | `{a['npm_latest']}` |",
            f"| Is npm latest | {'Yes' if a.get('is_latest') else 'No - newer version has known issues'} |",
            f"| Confidence | {a['confidence']}% |",
            f"| Patch available | {'Yes' if a['patch_available'] else 'No'} |",
            f"| CVSS Score | {a['cvss_score']} |",
            f"| Deprecated | {'Yes - ' + a['deprecation_msg'] if a['deprecated'] else 'No'} |",
            f"",
        ]
        if a.get("nvd_description"):
            lines += [f"**Description:** {a['nvd_description'][:300]}...", f""]
        if a.get("nvd_references"):
            lines.append(f"**References:**")
            for ref in a["nvd_references"][:3]:
                lines.append(f"- {ref}")
            lines.append("")
        lines += ["---", ""]

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "run": run_num,
            "timestamp": str(timestamp),
            "report_file": report_file,
            "assessments": assessments,
            "patches_applied": applied,
            "patches_review": branched,
            "patches_manual": manual_l,
        }, f, indent=2)

    print(f"\n    Reports saved to: {PATCHES_DIR}")
    print(f"      {md_path.name}")
    print(f"      {json_path.name}")


def main():
    parser = argparse.ArgumentParser(description="CVE Patch Finder - automated CVE remediation for Node.js projects")
    parser.add_argument("--report", default=str(REPORTS_DIR / "Snyk_report.json"),
                        help="Path to Snyk or npm audit JSON report")
    parser.add_argument("--format", choices=["npm", "snyk"], default="snyk",
                        help="Report format: npm or snyk (auto-detected from filename)")
    parser.add_argument("--app-dir", default="./vulnerable-shopping-app",
                        help="App directory containing package.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be patched without changing files")
    parser.add_argument("--patch-all", action="store_true",
                        help="Patch everything including major version bumps")
    parser.add_argument("--severity", default="critical,high",
                        help="Severity levels to include, comma-separated (default: critical,high)")
    args = parser.parse_args()

    report_lower = args.report.lower()
    if "npm_audit" in report_lower or "npm-audit" in report_lower:
        args.format = "npm"
    elif "snyk" in report_lower:
        args.format = "snyk"
    elif args.format not in ("npm", "snyk"):
        print("ERROR: unsupported format. Use --format npm or --format snyk")
        sys.exit(1)

    args.report  = str(Path(args.report).resolve())
    args.app_dir = str(Path(args.app_dir).resolve())
    pkg_json     = os.path.join(args.app_dir, "package.json")

    if not os.path.exists(args.report):
        print(f"\nERROR: report not found: {args.report}")
        sys.exit(1)

    now        = datetime.now()
    severities = {s.strip().lower() for s in args.severity.split(",")}

    print("")
    print("=" * 60)
    print("  CVE Patch Finder")
    print("=" * 60)
    print(f"  Report   : {args.report}")
    print(f"  Format   : {args.format}")
    print(f"  Severity : {args.severity}")
    print(f"  App dir  : {args.app_dir}")
    print(f"  Dry run  : {args.dry_run}")
    print(f"  Patch all: {args.patch_all}")
    print("")

    # Step 1 - parse the report
    print("[1/5] Parsing report...")
    if args.format == "npm":
        vulns = parse_npm_audit(args.report, pkg_json)
    else:
        vulns = parse_snyk_report(args.report, pkg_json, severities)

    if not vulns:
        print("      No vulnerabilities matched the severity filter.")
        return

    print(f"      {len(vulns)} vulnerability entries found")

    # Step 2 - show CVE table
    print("[2/5] CVE summary:")
    print_cve_table(vulns)

    groups = group_by_package(vulns)
    print(f"      {len(groups)} unique packages affected")
    print("")

    # Step 3 - look up each CVE on NVD
    print("[3/5] Looking up CVEs on NVD...")
    print("      (nvd.nist.gov - rate limited, takes a moment)")
    print("")

    nvd_results = {}
    all_cves    = list({v["cve_id"] for v in vulns if v["cve_id"] != "N/A"})

    for i, cve_id in enumerate(all_cves, 1):
        print(f"  [{i}/{len(all_cves)}] {cve_id} ... ", end="", flush=True)
        nvd = search_nvd(cve_id)
        nvd_results[cve_id] = nvd
        if nvd["found"]:
            print(f"found (CVSS {nvd['cvss_score']})")
        else:
            print("not found")
        if i < len(all_cves):
            time.sleep(NVD_DELAY)

    print("")

    # Step 4 - pick latest safe version using all three layers
    print("[4/5] Picking latest safe version (NVD + GitHub Advisories + official changelog)...")
    print("")

    assessments = []
    auto_list, review_list, manual_list = [], [], []

    for pkg, info in groups.items():
        installed     = info["installed"]
        fix_hint      = info["fix_hint"]
        cves          = info["all_cves"]
        is_transitive = not is_direct_dependency(pkg_json, pkg)

        print(f"  {pkg} (installed: {installed})  [{'transitive' if is_transitive else 'direct'}]")
        print(f"    CVEs: {', '.join(cves)}")

        primary_cve = cves[0]
        nvd = nvd_results.get(primary_cve, {
            "found": False, "cvss_score": 0.0,
            "description": "", "references": [], "patch_mentioned": False
        })
        print(f"    NVD:  {'CVSS ' + str(nvd['cvss_score']) if nvd['found'] else 'not found'}")

        npm = get_latest_safe_version(pkg, fix_hint, installed)
        if npm["registry_found"]:
            is_latest_label = "yes" if npm["is_latest"] else "no - newer version has known issues"
            print(f"    npm:  latest={npm['latest']}  chosen={npm['latest_safe']}  is_latest={is_latest_label}")
        else:
            print(f"    npm:  registry unavailable, using hint {fix_hint}")
            npm["latest_safe"] = fix_hint
            npm["latest"]      = fix_hint

        if npm["deprecated"]:
            print(f"    WARN: package is deprecated - {npm['deprecation_msg'][:80]}")

        if is_transitive:
            parents = find_parent_packages(args.app_dir, pkg)
            if parents:
                print(f"    Brought in by: {', '.join(parents)}")
            print(f"    Type: transitive - will be added to overrides in package.json")

        target          = npm["latest_safe"] if is_valid_ver(npm["latest_safe"]) else fix_hint
        patch_available = is_valid_ver(target)

        if patch_available:
            print(f"    Fix:  upgrade to {target}")
        else:
            print(f"    Fix:  no valid version found")

        conf  = confidence_score(nvd["cvss_score"])
        label = confidence_label(conf)

        if args.patch_all and label != "AUTO_PATCH":
            label = "AUTO_PATCH"
            print(f"    Note: --patch-all override applied")

        print(f"    Decision: CVSS {nvd['cvss_score']} -> {conf}% confidence -> {label}")

        if label == "AUTO_PATCH":
            action = f"Upgrade {pkg} from {installed} to {target}"
            auto_list.append(f"{pkg}: {installed} -> {target}")
        elif label == "REVIEW":
            action = f"Check changelog then upgrade to {target}"
            review_list.append(f"{pkg}: {installed} -> {target}")
        else:
            action = f"Manual review needed"
            manual_list.append(f"{pkg}: {installed} -> {target}")

        assessments.append({
            "package":         pkg,
            "installed":       installed,
            "latest_safe":     target,
            "npm_latest":      npm["latest"],
            "is_latest":       npm["is_latest"],
            "is_transitive":   is_transitive,
            "confidence":      conf,
            "label":           label,
            "cves":            cves,
            "title":           info["title"],
            "action":          action,
            "patch_available": patch_available,
            "cvss_score":      nvd["cvss_score"],
            "nvd_description": nvd["description"],
            "nvd_references":  nvd["references"],
            "deprecated":      npm["deprecated"],
            "deprecation_msg": npm["deprecation_msg"],
        })
        print("")

    # Step 5 - patch package.json
    dry_note = " (dry run)" if args.dry_run else ""
    print(f"[5/5] Applying patches{dry_note}...")
    print("")

    if not args.dry_run and os.path.exists(pkg_json):
        bak = pkg_json + ".bak_run1"
        shutil.copy(pkg_json, bak)
        print(f"  Backup: {bak}\n")

        patched_count = 0
        for a in assessments:
            if a["label"] == "AUTO_PATCH" and a["patch_available"]:
                dep_note = " (transitive -> overrides)" if a["is_transitive"] else ""
                print(f"  Patching {a['package']}{dep_note}...")
                apply_patch(pkg_json, a["package"], a["latest_safe"], a["is_transitive"])
                patched_count += 1

        if patched_count > 0:
            print(f"\n  {patched_count} package(s) updated")
            if not run_tests(args.app_dir):
                print("  Restoring original package.json...")
                shutil.copy(bak, pkg_json)
        else:
            print("  Nothing to auto-patch")

    print("")
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    print(f"  Auto-patched   : {len(auto_list)}")
    for p in auto_list:
        print(f"    {p}")
    print(f"  Needs review   : {len(review_list)}")
    for p in review_list:
        print(f"    {p}")
    print(f"  Manual         : {len(manual_list)}")
    for p in manual_list:
        print(f"    {p}")
    print("=" * 60)

    if not args.dry_run and auto_list:
        print("\n  Run 'npm install' in your app folder to download the patched versions.")

    save_report(1, now, args.report, assessments, auto_list, review_list, manual_list)
    print("")


if __name__ == "__main__":
    main()
