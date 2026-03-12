#!/usr/bin/env python3
# CVE Patch Finder - automated CVE remediation for Node.js projects
# Reads a Snyk or npm audit report, looks up each CVE on NVD,
# finds the latest safe version on npm, then patches package.json.
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

NVD_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NPM_REGISTRY = "https://registry.npmjs.org"
NVD_DELAY    = 1.0  # NVD rate limit: 5 req / 30s without an API key

AUTO_THRESHOLD   = 80
REVIEW_THRESHOLD = 50


# Makes a GET request to the given URL and returns the parsed JSON response.
# Returns None if the request fails or times out so callers can handle it gracefully.
# Input:  url (str), optional timeout in seconds
# Output: dict from JSON response, or None on failure
def http_get(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CVEPatchFinder/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


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
            cve_id = "N/A"
            title = pkg
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
            pkg = adv.get("module_name", "?")
            fix_raw = adv.get("patched_versions", "").replace(">=", "").strip()
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
        cve_list = identifiers.get("CVE", [])

        # Use CVE ID directly from Snyk's identifiers field.
        # Fall back to Snyk's own advisory ID if no CVE has been assigned yet.
        cve_id = cve_list[0] if cve_list else v.get("id", "N/A")

        package = v.get("packageName", v.get("name", "?"))

        installed = v.get("version", "")
        if not installed and pkg_json_path:
            installed = get_installed_version(pkg_json_path, package)
        installed = installed or "?"

        fixed_in = v.get("fixedIn", [])
        if fixed_in:
            valid = [f for f in fixed_in if is_valid_ver(str(f))]
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
# NVD rate limits unauthenticated requests to 5 per 30 seconds, so callers
# should add a delay between calls (see NVD_DELAY constant).
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

    cve_data = items[0].get("cve", {})
    result = dict(empty)
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


# Queries the npm registry to find the best version to upgrade a package to.
# "Latest safe" means the highest published version that is >= the fix_hint
# version recommended by the scanner. This is better than just using fix_hint
# directly because a newer patch may have been released since the scan.
# Also checks whether the latest version carries a deprecation warning.
# Input:  package name, minimum fix version hint, currently installed version
# Output: dict with keys: latest, latest_safe, all_versions, deprecated, deprecation_msg, registry_found
def get_latest_safe_version(package, fix_hint, installed):
    result = {
        "latest": "?", "latest_safe": "?", "all_versions": [],
        "deprecated": False, "deprecation_msg": "", "registry_found": False,
    }

    data = http_get(f"{NPM_REGISTRY}/{package}", timeout=20)
    if not data:
        return result

    result["registry_found"] = True
    all_versions = list(data.get("versions", {}).keys())
    result["all_versions"] = all_versions
    result["latest"] = data.get("dist-tags", {}).get("latest", "?")

    latest_meta = data.get("versions", {}).get(result["latest"], {})
    dep_msg = latest_meta.get("deprecated", "")
    if dep_msg:
        result["deprecated"] = True
        result["deprecation_msg"] = dep_msg

    if fix_hint and is_valid_ver(fix_hint):
        safe = [v for v in all_versions if is_valid_ver(v) and ver_key(v) >= ver_key(fix_hint)]
        result["latest_safe"] = max(safe, key=ver_key) if safe else fix_hint
    else:
        result["latest_safe"] = result["latest"]

    return result


# Updates a single package version in package.json and writes the file back.
# Preserves the existing range prefix (^ or ~) if one was present.
# Skips silently if the package is not found in either dependencies section.
# Input:  path to package.json, package name, target version string
# Output: none (modifies package.json on disk)
def apply_patch(pkg_json_path, package, version):
    abs_path = str(Path(pkg_json_path).resolve())
    with open(abs_path, encoding="utf-8") as f:
        pkg = json.load(f)

    patched = False
    for section in ("dependencies", "devDependencies"):
        if package in pkg.get(section, {}):
            old = pkg[section][package]
            prefix = old[0] if old and old[0] in ("^", "~") else ""
            pkg[section][package] = f"{prefix}{version}"
            print(f"      {section}['{package}']: {old} -> {prefix}{version}")
            patched = True

    if patched:
        with open(abs_path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)
            f.write("\n")
    else:
        print(f"      '{package}' not found in package.json - skipping")


# Runs the project's test suite using npm test after patches have been applied.
# If the tests fail, returns False so the caller can roll back the changes.
# Returns True if tests pass or if npm test can't be found (to avoid blocking
# the pipeline on projects that don't have tests set up).
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
# When a package has several CVEs, we keep them all in all_cves[] and use
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
# The markdown version is meant to be human-readable, the JSON is for any downstream tooling.
# Both files are named with a timestamp so multiple runs don't overwrite each other.
# Input:  run number, timestamp, source report path, list of assessment dicts,
#         and three lists (auto-patched, review, manual) of package strings
# Output: none (writes two files to PATCHES_DIR)
def save_report(run_num, timestamp, report_file, assessments, applied, branched, manual_l):
    PATCHES_DIR.mkdir(parents=True, exist_ok=True)
    ts = timestamp.strftime("%Y%m%d_%H%M%S")
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
        icon = label_map.get(a["label"], "")
        lines += [
            f"### {a['package']}  {icon}",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| CVE ID(s) | {', '.join(a['cves'])} |",
            f"| Title | {a['title']} |",
            f"| Installed | `{a['installed']}` |",
            f"| Target version | `{a['latest_safe']}` |",
            f"| npm latest | `{a['npm_latest']}` |",
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

    # auto-detect format from filename
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

    now = datetime.now()
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
    all_cves = list({v["cve_id"] for v in vulns if v["cve_id"] != "N/A"})

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

    # Step 4 - find latest safe version from npm registry
    print("[4/5] Checking npm registry for safe versions...")
    print("")

    assessments = []
    auto_list, review_list, manual_list = [], [], []

    for pkg, info in groups.items():
        installed = info["installed"]
        fix_hint  = info["fix_hint"]
        cves      = info["all_cves"]

        print(f"  {pkg} (installed: {installed})")
        print(f"    CVEs: {', '.join(cves)}")

        primary_cve = cves[0]
        nvd = nvd_results.get(primary_cve, {
            "found": False, "cvss_score": 0.0,
            "description": "", "references": [], "patch_mentioned": False
        })
        print(f"    NVD:  {'CVSS ' + str(nvd['cvss_score']) if nvd['found'] else 'not found'}")

        npm = get_latest_safe_version(pkg, fix_hint, installed)
        if npm["registry_found"]:
            print(f"    npm:  latest={npm['latest']}  safe={npm['latest_safe']}")
        else:
            print(f"    npm:  registry unavailable, using hint {fix_hint}")
            npm["latest_safe"] = fix_hint
            npm["latest"] = fix_hint

        if npm["deprecated"]:
            print(f"    WARN: package is deprecated - {npm['deprecation_msg'][:80]}")

        target = npm["latest_safe"] if is_valid_ver(npm["latest_safe"]) else fix_hint
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
                print(f"  Patching {a['package']}...")
                apply_patch(pkg_json, a["package"], a["latest_safe"])
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
