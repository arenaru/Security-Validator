"""Parse Acunetix scan exports and enrich findings using the local Acunetix vulnerability DB.

This project already has `utils/acunetix_vulnerabilities.json` which is a scraped catalog
(vulnerability_name, severity, reference_link). This script ingests an Acunetix *report/export*
file (typically JSON, sometimes XML), extracts issue/finding entries, then enriches them by:
- exact name match against the DB (case-insensitive)
- CVE match (e.g., "CVE-2024-1234") against DB names

It outputs a normalized JSON list of findings that your Streamlit app can consume later.

Usage (PowerShell):
    C:/Users/binz/Documents/SecVal/myenv/Scripts/python.exe ./script/parse_acunetix_report.py --input report.json --output acunetix_findings.json

Notes:
- Acunetix export schemas vary by product/version. This script uses heuristics and will still
  produce useful output even if it cannot perfectly map every field.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Iterable


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@dataclass(frozen=True)
class DbEntry:
    name: str
    severity: str
    reference_link: str


def _repo_root() -> str:
    # This script lives in ./script; DB is in ./utils
    return os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


def load_acunetix_db(db_path: str | None = None) -> tuple[dict[str, DbEntry], dict[str, list[DbEntry]]]:
    if not db_path:
        db_path = os.path.join(_repo_root(), "utils", "acunetix_vulnerabilities.json")

    with open(db_path, "r", encoding="utf-8") as f:
        rows = json.load(f)

    name_index: dict[str, DbEntry] = {}
    cve_index: dict[str, list[DbEntry]] = {}

    for item in rows if isinstance(rows, list) else []:
        name = str(item.get("vulnerability_name") or "").strip()
        if not name:
            continue
        severity = str(item.get("severity") or "Info").strip() or "Info"
        reference_link = str(item.get("reference_link") or "").strip()
        entry = DbEntry(name=name, severity=severity, reference_link=reference_link)

        key = name.lower()
        # Prefer first occurrence; duplicates are usually identical.
        if key not in name_index:
            name_index[key] = entry

        for cve in {m.group(0).upper() for m in _CVE_RE.finditer(name)}:
            cve_index.setdefault(cve, []).append(entry)

    return name_index, cve_index


def _walk(obj: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    """Depth-first walk returning (json_path, node)."""
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            child_path = f"{path}.{k}" if isinstance(k, str) else f"{path}[{repr(k)}]"
            yield from _walk(v, child_path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def _first_str(d: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _extract_cves_from_text(text: str | None) -> list[str]:
    if not text:
        return []
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(text)})


def _looks_like_finding(d: dict[str, Any]) -> bool:
    # Heuristic: has a name/title and at least one of url/severity/description/cve.
    name = _first_str(d, ("vulnerability_name", "vulnerability", "issue_name", "name", "title", "issue", "alert"))
    if not name:
        return False

    has_context = False
    if _first_str(d, ("url", "affects_url", "affected_url", "target", "host", "endpoint", "path")):
        has_context = True
    if _first_str(d, ("severity", "level", "risk", "rating")):
        has_context = True
    if _first_str(d, ("description", "details", "evidence", "recommendation", "impact")):
        has_context = True

    # CVE might be separate field or inside name/details.
    if _first_str(d, ("cve", "cves", "cve_id", "cveId", "cve_ids")):
        has_context = True
    else:
        if _extract_cves_from_text(json.dumps(d, ensure_ascii=False)):
            has_context = True

    return has_context


def parse_json_report(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    findings: list[dict[str, Any]] = []

    for jpath, node in _walk(doc):
        if not isinstance(node, dict):
            continue
        if not _looks_like_finding(node):
            continue

        name = _first_str(node, ("vulnerability_name", "vulnerability", "issue_name", "name", "title", "issue", "alert")) or "(unnamed)"
        url = _first_str(node, ("url", "affects_url", "affected_url", "target", "endpoint"))
        severity_raw = _first_str(node, ("severity", "level", "risk", "rating"))
        description = _first_str(node, ("description", "details", "summary", "impact"))
        evidence = _first_str(node, ("evidence", "proof", "request", "response"))

        cves: list[str] = []
        cve_field = node.get("cve") or node.get("cves") or node.get("cve_id") or node.get("cveId") or node.get("cve_ids")
        if isinstance(cve_field, str):
            cves.extend(_extract_cves_from_text(cve_field))
        elif isinstance(cve_field, list):
            for it in cve_field:
                if isinstance(it, str):
                    cves.extend(_extract_cves_from_text(it))

        # also scan name/description
        cves.extend(_extract_cves_from_text(name))
        cves.extend(_extract_cves_from_text(description))
        cves = sorted(set(cves))

        findings.append(
            {
                "name": name,
                "url": url,
                "severity_raw": severity_raw,
                "cves": cves,
                "description": description,
                "evidence": evidence,
                "source_path": jpath,
            }
        )

    # Fallback: if nothing matched, attempt a broader string scan for exact vuln-name matches.
    if not findings:
        strings = []
        for _, node in _walk(doc):
            if isinstance(node, str) and node.strip():
                strings.append(node.strip())
        for s in strings:
            findings.append({"name": s, "url": None, "severity_raw": None, "cves": _extract_cves_from_text(s), "description": None, "evidence": None, "source_path": "$"})

    return findings


def parse_xml_report(path: str) -> list[dict[str, Any]]:
    tree = ET.parse(path)
    root = tree.getroot()

    # Generic XML heuristics: look for elements named like Issue/Vulnerability/Alert.
    candidates = []
    for el in root.iter():
        tag = (el.tag or "").lower()
        if any(k in tag for k in ("issue", "vulnerability", "alert", "finding")):
            candidates.append(el)

    findings: list[dict[str, Any]] = []
    for el in candidates:
        # gather text from children
        def find_text(keys: tuple[str, ...]) -> str | None:
            for k in keys:
                for child in el.iter():
                    ctag = (child.tag or "").lower()
                    if ctag.endswith(k) or ctag == k:
                        if child.text and child.text.strip():
                            return child.text.strip()
            return None

        name = find_text(("name", "title", "issue_name", "vulnerability_name", "issue", "alert"))
        if not name:
            continue
        url = find_text(("url", "affected_url", "affects_url", "target", "endpoint"))
        severity_raw = find_text(("severity", "level", "risk", "rating"))
        description = find_text(("description", "details", "summary", "impact"))
        evidence = find_text(("evidence", "proof", "request", "response"))

        text_blob = " ".join([t.strip() for t in (name, description, evidence) if t])
        cves = _extract_cves_from_text(text_blob)

        findings.append(
            {
                "name": name,
                "url": url,
                "severity_raw": severity_raw,
                "cves": cves,
                "description": description,
                "evidence": evidence,
                "source_path": f"xml:{el.tag}",
            }
        )

    return findings


def enrich_findings(findings: list[dict[str, Any]], name_index: dict[str, DbEntry], cve_index: dict[str, list[DbEntry]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    for f in findings:
        name = str(f.get("name") or "").strip()
        key = name.lower()

        db_hit = name_index.get(key)
        matched_by = None
        db_candidates: list[DbEntry] = []

        if db_hit:
            matched_by = "name"
            db_candidates = [db_hit]
        else:
            cves = f.get("cves") or []
            if isinstance(cves, list):
                for cve in cves:
                    cve_u = str(cve).upper()
                    db_candidates.extend(cve_index.get(cve_u, []))
            # de-dup preserving order
            seen = set()
            db_candidates = [e for e in db_candidates if not (e.name in seen or seen.add(e.name))]
            if db_candidates:
                matched_by = "cve"

        # choose primary candidate
        primary = db_candidates[0] if db_candidates else None

        enriched = dict(f)
        if primary:
            enriched["db_name"] = primary.name
            enriched["db_severity"] = primary.severity
            enriched["reference_link"] = primary.reference_link
        else:
            enriched["db_name"] = None
            enriched["db_severity"] = None
            enriched["reference_link"] = None

        enriched["matched_by"] = matched_by
        enriched["db_candidates"] = [{"name": e.name, "severity": e.severity, "reference_link": e.reference_link} for e in db_candidates[:10]]

        out.append(enriched)

    return out


def _guess_format(input_path: str, fmt: str | None) -> str:
    if fmt and fmt != "auto":
        return fmt
    ext = os.path.splitext(input_path)[1].lower()
    if ext == ".json":
        return "json"
    if ext in (".xml", ".nessus", ".scan"):
        return "xml"
    return "json"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Parse Acunetix exports and enrich with local vulnerability DB")
    ap.add_argument("--input", "-i", required=True, help="Path to Acunetix report/export file (.json or .xml)")
    ap.add_argument("--output", "-o", required=True, help="Path to write normalized enriched findings JSON")
    ap.add_argument("--db", default=None, help="Optional path to utils/acunetix_vulnerabilities.json")
    ap.add_argument("--format", choices=["auto", "json", "xml"], default="auto", help="Input format")
    ap.add_argument("--dedup", action="store_true", help="De-duplicate findings by (db_name or name) + url")

    args = ap.parse_args(argv)

    if not os.path.exists(args.input):
        print(f"[ERROR] Input not found: {args.input}", file=sys.stderr)
        return 2

    name_index, cve_index = load_acunetix_db(args.db)

    fmt = _guess_format(args.input, args.format)
    if fmt == "xml":
        findings = parse_xml_report(args.input)
    else:
        findings = parse_json_report(args.input)

    enriched = enrich_findings(findings, name_index, cve_index)

    if args.dedup:
        seen = set()
        deduped = []
        for it in enriched:
            dedup_key = (it.get("db_name") or it.get("name") or "").lower(), (it.get("url") or "").lower()
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            deduped.append(it)
        enriched = deduped

    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)

    # Print a short summary
    total = len(enriched)
    by_match = {"name": 0, "cve": 0, None: 0}
    for it in enriched:
        by_match[it.get("matched_by")] = by_match.get(it.get("matched_by"), 0) + 1

    print(f"[OK] Parsed {total} findings")
    print(f"     Matched by name: {by_match.get('name', 0)}")
    print(f"     Matched by CVE : {by_match.get('cve', 0)}")
    print(f"     Unmatched      : {by_match.get(None, 0)}")
    print(f"[OK] Wrote: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
