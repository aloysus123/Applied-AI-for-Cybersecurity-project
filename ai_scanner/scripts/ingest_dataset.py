#!/usr/bin/env python3
"""
ingest_dataset.py - Air-gapped Knowledge Base Preprocessing & Filtering Pipeline.

Ingests, filters, cleans, and standardizes multi-source vulnerability datasets for
the local AI hybrid scanner (Bandit SAST + RAG + Qwen 2.5 Coder):
  1. MITRE CWE (CSV): Strips delimiter tags (::PHASE:..., ::STRATEGY:...), filters
     for Bandit target CWEs, and outputs clean plain-English mitigations.
  2. OWASP Top 10 (Markdown): Cleans frontmatter/styling, extracts prevention guides,
     scenarios, and maps categories to Bandit CWEs.
  3. OWASP Cheat Sheets (Markdown): Drops non-Python language sheets (Java, PHP,
     .NET, Ruby, etc.), keeping Python-specific & universal mitigation guides.
  4. CVE Records (JSON): Drops >90% non-target CVEs, filters exclusively for Python
     ecosystem vulnerabilities, scrubs HTML noise, and extracts CVSS metrics.
  5. Code Pairs / CVEfixes (.SQL / .DB): Filters strictly for Python language pairs
     and Bandit target CWEs to extract vulnerable-before / remediated-after code.

Outputs clean JSON datasets into: ai_scanner/data/processed/
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import logging
import os
import re
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("DatasetIngest")

# ==============================================================================
# BANDIT TARGET CWE DEFINITIONS & NORMALIZATION
# ==============================================================================

# Core Bandit CWE mappings (from app.core.scanner) plus Bandit plugin CWEs
BANDIT_TARGET_CWES: Set[str] = {
    # Core SAST Targets
    "CWE-78",   # OS Command Injection (B404, B601-B607, B609)
    "CWE-89",   # SQL Injection (B608)
    "CWE-259",  # Hardcoded Passwords / Secrets (B105-B107)
    "CWE-377",  # Insecure Temporary File / Directory (B108)
    "CWE-327",  # Broken / Risky Cryptography (B303-B305, B413, B505)
    "CWE-295",  # Improper Certificate Validation (B501-B504)
    "CWE-502",  # Deserialization of Untrusted Data (B301, B302, B403, B506)
    "CWE-95",   # Improper Neutralization of Directives in Code / Eval (B102, B307)
    "CWE-79",   # Cross-Site Scripting (B701-B703)
    "CWE-611",  # XML External Entity (XXE) Injection (B313-B320, B405-B410)
    # Extended Bandit Plugin Targets
    "CWE-20",   # Improper Input Validation (B101 assert)
    "CWE-22",   # Path Traversal / Tar Slip (B202 tarfile)
    "CWE-94",   # Improper Control of Code Generation (Dynamic Code Injection)
    "CWE-250",  # Execution with Unnecessary Privileges (B325)
    "CWE-319",  # Cleartext Transmission of Sensitive Information (B322)
    "CWE-330",  # Use of Insufficiently Random Values (B311)
    "CWE-338",  # Cryptographically Weak PRNG (B311)
    "CWE-605",  # Multiple Binds to Same Port (B104)
    "CWE-703",  # Improper Handling of Exceptional Conditions (B110, B112)
    "CWE-732",  # Incorrect Permission Assignment / chmod (B103)
}

# Non-Python ecosystem blacklist keywords (used to aggressively reject non-Python CVEs & Cheatsheets)
NON_PYTHON_ECOSYSTEM_TERMS = {
    "wordpress", "php", "joomla", "drupal", "ruby on rails", "rubygems",
    "maven", "nuget", "android", "ios", "golang", "c++", "cplusplus",
    "c#", "csharp", "dotnet", ".net", "rust-lang", "swift", "kotlin",
    "apple tv", "cisco ios", "typo3", "magento", "spring boot", "laravel",
    "struts", "jenkins", "apache tomcat", "coldfusion"
}

# Fast positive Python indicator keywords
FAST_PY_SUBSTRINGS = (
    "python", "pypi", "pip", "django", "flask", "fastapi", "paramiko",
    "jinja2", "sqlalchemy", "werkzeug", "aiohttp", "tornado", "celery",
    "urllib3", "scrapy", "numpy", "pandas", "scipy", "httpx"
)

# Precompiled single regex for exact Python boundary matches (50x faster than multiple uncompiled regexes)
COMPILED_PYTHON_REGEX = re.compile(
    r"\b(python|pypi|django|flask|fastapi|paramiko|jinja2|sqlalchemy|werkzeug|aiohttp|tornado|celery|urllib3|scrapy|numpy|pandas|scipy|scikit-learn|httpx)\b|\bpip\s+install\b",
    re.IGNORECASE,
)

MITRE_MITIGATION_PATTERN = re.compile(r"(PHASE|STRATEGY|DESCRIPTION|EFFECTIVENESS):")
MITRE_CONSEQUENCE_PATTERN = re.compile(r"(SCOPE|IMPACT|NOTE|LIKELIHOOD):")
HTML_TAG_REGEX = re.compile(r"<[^>]+>")
WHITESPACE_REGEX = re.compile(r"\s+")


def normalize_cwe_id(val: Any) -> Optional[str]:
    """Normalize any string/int CWE representation (e.g., '78', 'CWE-078', 'cwe-78') to 'CWE-78'."""
    if val is None:
        return None
    val_str = str(val).strip()
    match = re.search(r"(\d+)", val_str)
    if match:
        return f"CWE-{int(match.group(1))}"
    return None


def strip_html_tags(text: str) -> str:
    """Unescapes HTML entities and strips all HTML tags into clean plain text."""
    if not text:
        return ""
    unescaped = html.unescape(text)
    cleaned = HTML_TAG_REGEX.sub(" ", unescaped)
    cleaned = cleaned.replace("&nbsp;", " ")
    return WHITESPACE_REGEX.sub(" ", cleaned).strip()


# ==============================================================================
# 1. MITRE CWE PREPROCESSOR
# ==============================================================================

def clean_mitre_mitigations(raw_text: str) -> str:
    """
    Strips messy delimiter tags from MITRE's Potential Mitigations column:
    e.g. ::PHASE:Architecture and Design:STRATEGY:Separation of Privilege:DESCRIPTION:...
    Returns clean, readable plain-English bullet points.
    """
    if not raw_text or not raw_text.strip():
        return "No specific mitigations recorded."

    segments = [s.strip() for s in raw_text.split("::") if s.strip()]
    cleaned_items: List[str] = []

    for seg in segments:
        matches = list(MITRE_MITIGATION_PATTERN.finditer(seg))
        if not matches:
            if seg:
                cleaned_items.append(seg)
            continue

        tag_values: Dict[str, str] = {}
        for i, match in enumerate(matches):
            tag_name = match.group(1).lower()
            start_pos = match.end()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(seg)
            val = seg[start_pos:end_pos].strip(" :")
            tag_values[tag_name] = val

        desc = tag_values.get("description", "")
        strategy = tag_values.get("strategy", "")
        phase = tag_values.get("phase", "")
        effectiveness = tag_values.get("effectiveness", "")

        header_parts = []
        if strategy:
            header_parts.append(strategy)
        if phase:
            header_parts.append(f"Phase: {phase}")

        prefix = f"[{' | '.join(header_parts)}] " if header_parts else ""
        eff = f" (Effectiveness: {effectiveness})" if effectiveness else ""

        if desc:
            cleaned_items.append(f"{prefix}{desc}{eff}")
        elif seg:
            cleaned_items.append(seg)

    if not cleaned_items:
        return "No specific mitigations recorded."

    return "\n".join(f"• {item}" for item in cleaned_items)


def clean_mitre_consequences(raw_text: str) -> str:
    """
    Strips messy delimiter tags from MITRE's Common Consequences column:
    e.g. ::SCOPE:Confidentiality:IMPACT:Read Application Data:NOTE:...
    Returns human-readable English consequence summaries.
    """
    if not raw_text or not raw_text.strip():
        return "Consequences vary depending on application context."

    segments = [s.strip() for s in raw_text.split("::") if s.strip()]
    cleaned_items: List[str] = []

    for seg in segments:
        matches = list(MITRE_CONSEQUENCE_PATTERN.finditer(seg))
        if not matches:
            if seg:
                cleaned_items.append(seg)
            continue

        scopes: List[str] = []
        impacts: List[str] = []
        notes: List[str] = []

        for i, match in enumerate(matches):
            tag_name = match.group(1)
            start_pos = match.end()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(seg)
            val = seg[start_pos:end_pos].strip(" :")
            if not val:
                continue
            if tag_name == "SCOPE":
                scopes.append(val)
            elif tag_name == "IMPACT":
                impacts.append(val)
            elif tag_name == "NOTE":
                notes.append(val)

        parts: List[str] = []
        if impacts:
            parts.append(f"Impact: {', '.join(impacts)}")
        if scopes:
            parts.append(f"Scope: {', '.join(sorted(set(scopes)))}")
        if notes:
            parts.append(f"Details: {' '.join(notes)}")

        if parts:
            cleaned_items.append(". ".join(parts) + ".")
        elif seg:
            cleaned_items.append(seg)

    if not cleaned_items:
        return "Consequences vary depending on application context."

    return "\n".join(f"• {item}" for item in cleaned_items)


def process_cwe_dataset(cwe_dir: Path, output_file: Path) -> int:
    """
    Finds and processes MITRE CWE CSV files (e.g., 699.csv).
    Filters strictly for Bandit's target CWE IDs and strips delimiter tags.
    """
    logger.info("--> Processing MITRE CWE dataset from: %s", cwe_dir)
    csv_files = list(cwe_dir.glob("*.csv"))
    if not csv_files:
        logger.warning("No CSV files found in %s", cwe_dir)
        return 0

    processed_records: List[Dict[str, Any]] = []
    total_rows = 0

    for csv_file in csv_files:
        logger.info("Reading CWE CSV: %s", csv_file.name)
        with open(csv_file, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_rows += 1
                raw_cwe_id = row.get("CWE-ID") or row.get("CWE ID") or row.get("ID")
                normalized_id = normalize_cwe_id(raw_cwe_id)

                if not normalized_id or normalized_id not in BANDIT_TARGET_CWES:
                    continue  # Filter out non-Bandit target CWEs

                name = row.get("Name", "").strip()
                description = row.get("Description", "").strip()
                extended_desc = row.get("Extended Description", "").strip()
                if extended_desc:
                    description = f"{description}\n\nExtended Context:\n{extended_desc}"

                mitigations_clean = clean_mitre_mitigations(row.get("Potential Mitigations", ""))
                consequences_clean = clean_mitre_consequences(row.get("Common Consequences", ""))
                likelihood = row.get("Likelihood of Exploit", "").strip() or "Unknown"

                record = {
                    "source": "MITRE_CWE",
                    "cwe_id": normalized_id,
                    "name": name,
                    "description": description,
                    "likelihood_of_exploit": likelihood,
                    "common_consequences": consequences_clean,
                    "potential_mitigations": mitigations_clean,
                }
                processed_records.append(record)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(processed_records, out, indent=2, ensure_ascii=False)

    logger.info(
        "MITRE CWE processed: kept %d target CWEs (filtered from %d total rows). Saved to %s",
        len(processed_records),
        total_rows,
        output_file.name,
    )
    return len(processed_records)


# ==============================================================================
# 2. OWASP TOP 10 PREPROCESSOR
# ==============================================================================

def process_owasp_top10(top10_dir: Path, output_file: Path) -> int:
    """
    Parses OWASP Top 10 markdown documents. Extracts category headers, descriptions,
    remediation guidance, and maps them to Bandit CWE IDs.
    """
    logger.info("--> Processing OWASP Top 10 dataset from: %s", top10_dir)
    md_files = sorted(top10_dir.glob("*.md"))
    if not md_files:
        logger.warning("No Markdown files found in %s", top10_dir)
        return 0

    processed_records: List[Dict[str, Any]] = []

    for md_file in md_files:
        filename = md_file.name
        # Skip intro/meta files that do not define specific top 10 categories
        if filename.startswith("0x") or filename.startswith("X01") or filename.lower().startswith("index"):
            continue

        try:
            with open(md_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            logger.error("Could not read %s: %s", md_file, e)
            continue

        # Extract title (e.g. # A05:2025 Injection ...)
        title_match = re.search(r"^#\s+([^\n!]+)", content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else filename.replace(".md", "")

        # Extract category ID (e.g. A05:2025 or A05)
        cat_match = re.search(r"(A\d{2}(?::\d{4})?)", title)
        category_id = cat_match.group(1) if cat_match else "OWASP_TOP10"

        # Extract Description
        desc_match = re.search(r"##\s*Description\.?\s*\n(.*?)(?=\n##|\Z)", content, re.DOTALL | re.IGNORECASE)
        description = desc_match.group(1).strip() if desc_match else ""

        # Extract How to Prevent (Remediation)
        prevent_match = re.search(r"##\s*How to prevent\.?\s*\n(.*?)(?=\n##|\Z)", content, re.DOTALL | re.IGNORECASE)
        how_to_prevent = prevent_match.group(1).strip() if prevent_match else ""

        # Extract Example Attack Scenarios
        scenarios_match = re.search(
            r"##\s*Example attack scenarios\.?\s*\n(.*?)(?=\n##|\Z)", content, re.DOTALL | re.IGNORECASE
        )
        attack_scenarios = scenarios_match.group(1).strip() if scenarios_match else ""

        # Extract Mapped CWEs
        cwe_matches = re.findall(r"CWE-(\d+)", content)
        mapped_cwes = sorted({f"CWE-{num}" for num in cwe_matches})
        bandit_intersect = sorted(set(mapped_cwes).intersection(BANDIT_TARGET_CWES))

        # Clean markdown artifacts & HTML img tags
        clean_desc = re.sub(r"!\[.*?\]\(.*?\)(\{.*?\})?", "", description)
        clean_desc = re.sub(r"<[^>]+>", "", clean_desc).strip()

        clean_prevent = re.sub(r"!\[.*?\]\(.*?\)(\{.*?\})?", "", how_to_prevent)
        clean_prevent = re.sub(r"<[^>]+>", "", clean_prevent).strip()

        record = {
            "source": "OWASP_Top_10",
            "file": filename,
            "category_id": category_id,
            "title": title,
            "description": clean_desc,
            "how_to_prevent": clean_prevent,
            "example_scenarios": attack_scenarios[:1500] if attack_scenarios else "",
            "mapped_cwes": mapped_cwes,
            "bandit_target_cwes": bandit_intersect,
        }
        processed_records.append(record)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(processed_records, out, indent=2, ensure_ascii=False)

    logger.info("OWASP Top 10 processed: %d categories saved to %s", len(processed_records), output_file.name)
    return len(processed_records)


# ==============================================================================
# 3. OWASP CHEAT SHEETS PREPROCESSOR (LANGUAGE-FILTERED)
# ==============================================================================

def process_cheatsheets(cheats_dir: Path, output_file: Path) -> int:
    """
    Parses OWASP Cheat Sheets.
    Filters by language: Drops sheets dedicated to non-Python ecosystems (Java, PHP,
    .NET, Ruby, NodeJS, Go, Android, iOS), keeping Python-specific & universal guides.
    """
    logger.info("--> Processing OWASP Cheat Sheets from: %s", cheats_dir)
    md_files = list(cheats_dir.glob("*.md"))
    if not md_files:
        logger.warning("No Cheat Sheet markdown files found in %s", cheats_dir)
        return 0

    processed_records: List[Dict[str, Any]] = []
    dropped_count = 0

    for md_file in md_files:
        name_lower = md_file.name.lower()

        # Check if file is dedicated to a non-Python language/runtime
        is_foreign_lang = any(
            foreign in name_lower
            for foreign in [
                "java_", "java.", "in_java", "javascript", "typescript", "node",
                "php", "dotnet", "dot_net", "c_sharp", "c-based", "cplusplus",
                "golang", "ruby", "ios", "android", "swift", "kotlin", "laravel",
                "spring", "rust"
            ]
        )
        if is_foreign_lang and "python" not in name_lower and "django" not in name_lower and "flask" not in name_lower:
            dropped_count += 1
            continue

        try:
            with open(md_file, "r", encoding="utf-8", errors="replace") as f:
                raw_text = f.read()
        except Exception as e:
            logger.error("Could not read %s: %s", md_file, e)
            continue

        # Strip frontmatter (e.g. --- ... ---)
        body = re.sub(r"^---[\s\S]*?---\s*", "", raw_text)

        # Extract title
        title_match = re.search(r"^#\s+([^\n]+)", body, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else md_file.stem.replace("_", " ")

        # Remove HTML tags & images
        cleaned_body = re.sub(r"!\[.*?\]\(.*?\)", "", body)
        cleaned_body = re.sub(r"<[^>]+>", " ", cleaned_body)
        cleaned_body = re.sub(r"\n{3,}", "\n\n", cleaned_body).strip()

        # Check for related CWE mentions
        cwe_matches = re.findall(r"CWE-(\d+)", cleaned_body)
        associated_cwes = sorted({f"CWE-{num}" for num in cwe_matches if f"CWE-{num}" in BANDIT_TARGET_CWES})

        is_python_specific = any(k in name_lower or k in cleaned_body.lower() for k in ["python", "django", "flask"])

        record = {
            "source": "OWASP_Cheat_Sheet",
            "filename": md_file.name,
            "title": title,
            "is_python_specific": is_python_specific,
            "associated_bandit_cwes": associated_cwes,
            "content": cleaned_body,
        }
        processed_records.append(record)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(processed_records, out, indent=2, ensure_ascii=False)

    logger.info(
        "OWASP Cheat Sheets processed: kept %d sheets (dropped %d non-Python sheets). Saved to %s",
        len(processed_records),
        dropped_count,
        output_file.name,
    )
    return len(processed_records)


# ==============================================================================
# 4. CVE / NVD PREPROCESSOR (PYTHON & BANDIT CWE FILTERED)
# ==============================================================================

def _is_strictly_python_cve(raw_text: str, cve_data: Dict[str, Any]) -> bool:
    """
    Determines if a CVE record specifically belongs to the Python ecosystem.
    Rejects PHP, WordPress, Java, Android, and other non-Python technologies.
    """
    lower_text = raw_text.lower()

    # Rejection list
    if any(term in lower_text for term in NON_PYTHON_ECOSYSTEM_TERMS):
        return False

    # Fast substring check before running regex
    if not any(sub in lower_text for sub in FAST_PY_SUBSTRINGS):
        return False

    cna = cve_data.get("containers", {}).get("cna", {})

    # Check affected packages and vendors
    for aff in cna.get("affected", []):
        prod = str(aff.get("product", "")).lower()
        vendor = str(aff.get("vendor", "")).lower()
        if "python" in prod or "python" in vendor or "pypi" in prod or "pypi" in vendor:
            return True
        for cpe in aff.get("cpes", []):
            cpe_lower = cpe.lower()
            if ":python:" in cpe_lower or ":pypi:" in cpe_lower:
                return True

    # Precompiled single regex match
    if COMPILED_PYTHON_REGEX.search(lower_text):
        return True

    return False


def _extract_cwe_from_cve_json(cve_data: Dict[str, Any]) -> List[str]:
    """Extracts and normalizes all CWE IDs from CVE JSON containers (cna and adp)."""
    found_cwes: Set[str] = set()
    containers = cve_data.get("containers", {})

    # 1. CNA container
    cna = containers.get("cna", {})
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId")
            norm = normalize_cwe_id(cwe_id)
            if norm:
                found_cwes.add(norm)
            else:
                desc_text = desc.get("description", "")
                norm_desc = normalize_cwe_id(desc_text)
                if norm_desc:
                    found_cwes.add(norm_desc)

    # 2. ADP (Authorized Data Publisher) containers
    for adp in containers.get("adp", []):
        for pt in adp.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                norm = normalize_cwe_id(cwe_id)
                if norm:
                    found_cwes.add(norm)

    return sorted(found_cwes)


def _extract_cvss_metrics(cna: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts standardized CVSS v3.1 / v3.0 score, severity, and vector string."""
    metrics_list = cna.get("metrics", [])
    for metric in metrics_list:
        for cvss_key in ("cvssV3_1", "cvssV3_0", "cvssV3"):
            if cvss_key in metric:
                obj = metric[cvss_key]
                return {
                    "version": obj.get("version", "3.1"),
                    "base_score": obj.get("baseScore", 0.0),
                    "base_severity": obj.get("baseSeverity", "UNKNOWN"),
                    "vector_string": obj.get("vectorString", ""),
                }
    return {"version": "N/A", "base_score": 0.0, "base_severity": "UNKNOWN", "vector_string": ""}


def _parse_single_cve_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Fast worker function to read, filter, and clean a single CVE JSON record."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_text = f.read()

        # Fast string pre-filter: Skip immediately if none of Bandit's CWEs are in text
        if not any(cwe in raw_text for cwe in BANDIT_TARGET_CWES):
            return None

        data = json.loads(raw_text)

        # Drop rejected records
        if data.get("cveMetadata", {}).get("state") == "REJECTED":
            return None

        # Filter strictly for Python
        if not _is_strictly_python_cve(raw_text, data):
            return None

        # Extract CWEs and ensure at least one matches Bandit's targets
        cwes = _extract_cwe_from_cve_json(data)
        bandit_matches = [c for c in cwes if c in BANDIT_TARGET_CWES]
        if not bandit_matches:
            return None

        cve_id = data.get("cveMetadata", {}).get("cveId", file_path.stem)
        cna = data.get("containers", {}).get("cna", {})

        # Extract & clean description
        descriptions = cna.get("descriptions", [])
        english_desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                english_desc = d.get("value", "")
                break
        if not english_desc and descriptions:
            english_desc = descriptions[0].get("value", "")

        clean_description = strip_html_tags(english_desc)

        # Extract solutions/mitigations if present
        solutions = cna.get("solutions", [])
        solution_text = ""
        if solutions:
            solution_text = strip_html_tags(solutions[0].get("value", ""))

        cvss = _extract_cvss_metrics(cna)

        # Extract affected product names
        affected_prods = []
        for aff in cna.get("affected", []):
            prod = aff.get("product")
            if prod:
                affected_prods.append(str(prod))

        return {
            "source": "NVD_CVE_List_V5",
            "cve_id": cve_id,
            "target_cwes": bandit_matches,
            "all_cwes": cwes,
            "affected_products": affected_prods,
            "cvss_score": cvss["base_score"],
            "cvss_severity": cvss["base_severity"],
            "cvss_vector": cvss["vector_string"],
            "description": clean_description,
            "solution": solution_text,
        }
    except Exception:
        return None


def process_cve_dataset(
    cve_root: Path,
    output_file: Path,
    target_years: Optional[List[str]] = None,
    max_cves: int = 5000,
    max_workers: int = 8,
) -> int:
    """
    Ingests CVE JSON files (from CVE List V5 or NVD feeds).
    Scans files multi-threaded, applies strict Python and Bandit-CWE filters,
    and drops HTML/metadata noise.
    """
    logger.info("--> Processing CVE JSON dataset from: %s", cve_root)
    if not cve_root.exists():
        logger.warning("CVE directory %s does not exist", cve_root)
        return 0

    cves_dir = cve_root / "cves" if (cve_root / "cves").is_dir() else cve_root

    # Collect year directories to inspect
    available_years = [d.name for d in cves_dir.iterdir() if d.is_dir() and d.name.isdigit()]
    if target_years:
        selected_years = [y for y in available_years if y in target_years]
    else:
        # Default to modern high-value years (2020-2026) for fast & relevant training/retrieval
        selected_years = [y for y in available_years if int(y) >= 2020]

    logger.info("Scanning CVE records for years: %s", selected_years)

    candidate_files: List[Path] = []
    for year in selected_years:
        year_path = cves_dir / year
        for root_str, _, files in os.walk(year_path):
            for file_name in files:
                if file_name.endswith(".json") and not file_name.startswith("delta"):
                    candidate_files.append(Path(root_str) / file_name)

    logger.info("Collected %d candidate CVE JSON files. Filtering multi-threaded...", len(candidate_files))

    matched_records: List[Dict[str, Any]] = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in executor.map(_parse_single_cve_file, candidate_files):
            if result:
                matched_records.append(result)
                if len(matched_records) >= max_cves:
                    logger.info("Reached maximum requested CVE limit (%d).", max_cves)
                    break

    elapsed = time.time() - start_time
    logger.info(
        "CVE filtering complete in %.2fs. Kept %d Python + Bandit CVEs (dropped %.1f%% noise).",
        elapsed,
        len(matched_records),
        (1.0 - (len(matched_records) / max(len(candidate_files), 1))) * 100,
    )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(matched_records, out, indent=2, ensure_ascii=False)

    logger.info("Saved cleaned CVE dataset to: %s", output_file.name)
    return len(matched_records)


# ==============================================================================
# 5. CODE PAIRS / CVEFIXES PREPROCESSOR (.SQL / .DB)
# ==============================================================================

import textwrap

HUNK_HEADER_REGEX = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$")


def _extract_aligned_hunks(diff_text: str) -> List[Dict[str, Any]]:
    """
    Parses a unified diff into strictly aligned, untruncated vulnerability-fix pairs.

    Enforces:
      1. Hunk Line Count Verification: Validates that (@@ -old_start,old_count +new_start,new_count @@)
         line counts exactly match the actual lines present. Drops truncated or corrupted hunks.
      2. Perfect Scope Alignment: Each code pair is extracted strictly within a single hunk.
         Prevents mixing top-level imports or unrelated loop fragments into one Frankenstein snippet.
      3. Symmetric Context: vulnerable_code contains the old context + deletions, and fixed_code
         contains the new context + additions for the exact same region.
      4. Spurious Signal Filtering: Drops hunks that only change imports or comments without code logic.
      5. Indentation Normalization: Dedents both snippets cleanly so indentation is consistent.
    """
    clean_diff = diff_text.replace("\\n", "\n").replace("''", "'").replace("\\012", "\n")
    lines = clean_diff.split("\n")

    aligned_pairs: List[Dict[str, Any]] = []
    current_hdr: Optional[str] = None
    current_context: str = ""
    current_lines: List[str] = []
    exp_old = 0
    exp_new = 0

    def process_current_hunk():
        if not current_hdr:
            return

        meaningful = [l for l in current_lines if l != ""]
        act_old = sum(1 for l in meaningful if l.startswith("-") or l.startswith(" "))
        act_new = sum(1 for l in meaningful if l.startswith("+") or l.startswith(" "))

        # 1. Hunk Header Line Count Verification (Drop truncated hunks)
        if act_old != exp_old or act_new != exp_new:
            return

        old_lines = []
        new_lines = []
        changed_lines = []

        for l in meaningful:
            if l.startswith("-"):
                old_lines.append(l[1:])
                changed_lines.append(l[1:].strip())
            elif l.startswith("+"):
                new_lines.append(l[1:])
                changed_lines.append(l[1:].strip())
            elif l.startswith(" "):
                old_lines.append(l[1:])
                new_lines.append(l[1:])

        # Must contain actual modifications
        if not changed_lines:
            return

        # 2. Filter Spurious Signals: Drop hunks that are purely imports, comments, or docstrings
        non_trivial_changes = [
            c for c in changed_lines
            if c and not c.startswith(("import ", "from ", "#", '"""', "'''", "*", "-"))
        ]
        if not non_trivial_changes:
            return

        # 3. Symmetric Block Reconstruction with Dedenting
        raw_before = "\n".join(old_lines)
        raw_after = "\n".join(new_lines)

        clean_before = textwrap.dedent(raw_before).strip()
        clean_after = textwrap.dedent(raw_after).strip()

        # Both sides must be non-empty and genuinely different
        if clean_before and clean_after and clean_before != clean_after:
            full_hunk_diff = f"{current_hdr}\n" + "\n".join(meaningful)
            aligned_pairs.append({
                "enclosing_context": current_context.strip(),
                "vulnerable_code": clean_before,
                "fixed_code": clean_after,
                "diff_patch": full_hunk_diff,
            })

    for line in lines:
        m = HUNK_HEADER_REGEX.match(line)
        if m:
            process_current_hunk()
            current_context = m.group(5) or ""
            current_hdr = f"@@ -{m.group(1)},{m.group(2) or 1} +{m.group(3)},{m.group(4) or 1} @@{current_context}"
            current_lines = []
            exp_old = int(m.group(2)) if m.group(2) is not None else 1
            exp_new = int(m.group(4)) if m.group(4) is not None else 1
        elif current_hdr is not None:
            current_lines.append(line)

    process_current_hunk()
    return aligned_pairs


def _lookup_cwe_for_cve_id(cve_id: str, cve_root: Path) -> Optional[str]:
    """Fast O(1) file lookup of a CVE's CWE ID from cvelistV5 sharded directories."""
    m = re.match(r"CVE-(\d{4})-(\d+)", cve_id)
    if not m:
        return None
    year, num = m.group(1), m.group(2)
    prefix = num[:-3] + "xxx" if len(num) > 3 else "0xxx"
    target = cve_root / "cves" / year / prefix / f"{cve_id}.json"
    if not target.exists():
        # Fallback if no 'cves' subfolder
        target = cve_root / year / prefix / f"{cve_id}.json"
    if target.exists():
        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                d = json.load(f)
                cna = d.get("containers", {}).get("cna", {})
                for pt in cna.get("problemTypes", []):
                    for desc in pt.get("descriptions", []):
                        cwe_id = desc.get("cweId")
                        if cwe_id:
                            m_cwe = re.search(r"(\d+)", cwe_id)
                            if m_cwe:
                                return f"CWE-{m_cwe.group(1)}"
        except Exception:
            pass
    return None


def process_code_pairs(
    code_pairs_dir: Path,
    output_file: Path,
    cve_root: Optional[Path] = None,
    max_pairs: int = 1000,
) -> int:
    """
    Ingests CVEfixes code pair records from .sql dumps or SQLite .db files.
    Filters exclusively for:
      - Language: Python (.py files or programming_language == 'Python')
      - Vulnerability: CWE matching Bandit's target CWEs
    Extracts structured:
      - vulnerable_code: lines removed before patch
      - fixed_code: lines added in patch
      - diff_patch: full unified diff
    """
    logger.info("--> Processing Code Pairs / CVEfixes from: %s", code_pairs_dir)
    if not code_pairs_dir.exists():
        logger.warning("Code pairs directory %s does not exist", code_pairs_dir)
        return 0

    sql_files = list(code_pairs_dir.glob("*.sql"))
    db_files = list(code_pairs_dir.glob("*.db")) + list(code_pairs_dir.glob("*.sqlite*"))

    if not sql_files and not db_files:
        logger.info(
            "No .sql or .db files found in %s yet. (Skipping code pairs until CVEfixes file is placed).",
            code_pairs_dir,
        )
        return 0

    processed_pairs: List[Dict[str, Any]] = []

    # Priority 1: Direct SQLite Database (.db or .sqlite)
    target_db = db_files[0] if db_files else None

    # Priority 2: Check if .sql file is actually an SQLite binary
    if not target_db and sql_files:
        first_sql = sql_files[0]
        try:
            with open(first_sql, "rb") as check_f:
                header = check_f.read(16)
                if header.startswith(b"SQLite format 3"):
                    target_db = first_sql
        except Exception:
            pass

    if target_db:
        logger.info("Found SQLite database: %s. Querying Python code pairs...", target_db.name)
        try:
            conn = sqlite3.connect(str(target_db))
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0].lower() for row in cursor.fetchall()}

            if "file_change" in tables and "fixes" in tables and "cve" in tables:
                query = """
                    SELECT 
                        fc.file_change_id,
                        f.cve_id,
                        c.cwe_id,
                        fc.filename,
                        fc.programming_language,
                        fc.diff
                    FROM file_change fc
                    JOIN fixes f ON fc.hash = f.hash
                    JOIN cve c ON f.cve_id = c.cve_id
                    WHERE (LOWER(fc.programming_language) = 'python' OR fc.filename LIKE '%.py')
                """
                cursor.execute(query)
                while True:
                    rows = cursor.fetchmany(100)
                    if not rows:
                        break
                    for row in rows:
                        fc_id, cve_id, raw_cwe, filename, lang, raw_diff = row
                        norm_cwe = normalize_cwe_id(raw_cwe)
                        if not norm_cwe or norm_cwe not in BANDIT_TARGET_CWES:
                            continue

                        hunks = _extract_aligned_hunks(raw_diff or "")
                        for h in hunks:
                            processed_pairs.append({
                                "source": "CVEfixes_Aligned_Hunk",
                                "file_change_id": fc_id,
                                "cve_id": cve_id,
                                "cwe_id": norm_cwe,
                                "filename": filename,
                                "enclosing_context": h["enclosing_context"],
                                "language": "Python",
                                "vulnerable_code": h["vulnerable_code"],
                                "fixed_code": h["fixed_code"],
                                "diff_patch": h["diff_patch"],
                            })
                            if len(processed_pairs) >= max_pairs:
                                break
                    if len(processed_pairs) >= max_pairs:
                        logger.info("Reached maximum requested code pairs limit (%d).", max_pairs)
                        break

            conn.close()
        except Exception as e:
            logger.error("Error querying SQLite file %s: %s", target_db, e)

    # Priority 3: Large Text SQL Dump parsing with diff extraction & CWE lookup
    elif sql_files:
        sql_file = sql_files[0]
        logger.info("Parsing SQL dump: %s for Python code changes...", sql_file.name)
        hash_to_cve: Dict[str, str] = {}
        cve_cwe_cache: Dict[str, Optional[str]] = {}

        try:
            with open(sql_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # Phase 1: Ingest fixes table (lines 2-13,000)
                    if line.startswith("INSERT INTO fixes VALUES("):
                        m = re.match(r"INSERT INTO fixes VALUES\('([^']+)','([^']+)'", line)
                        if m:
                            hash_to_cve[m.group(2)] = m.group(1)

                    # Phase 2: Ingest file_change table (lines 25,000-76,000)
                    elif line.startswith("INSERT INTO file_change VALUES("):
                        if ".py" in line:
                            diff_match = re.search(r"replace\('(@@[\s\S]*?)',\s*'\\n'", line)
                            if diff_match:
                                hdr_m = re.match(
                                    r"INSERT INTO file_change VALUES\('[^']+','([^']+)','([^']+)'", line
                                )
                                if hdr_m:
                                    commit_hash = hdr_m.group(1)
                                    filename = hdr_m.group(2)
                                    if filename.endswith(".py"):
                                        cve_id = hash_to_cve.get(commit_hash)
                                        if not cve_id:
                                            continue

                                        if cve_id not in cve_cwe_cache:
                                            cwe_found = None
                                            if cve_root:
                                                cwe_found = _lookup_cwe_for_cve_id(cve_id, cve_root)
                                            cve_cwe_cache[cve_id] = cwe_found

                                        cwe_id = cve_cwe_cache[cve_id]
                                        if cwe_id and cwe_id in BANDIT_TARGET_CWES:
                                            hunks = _extract_aligned_hunks(diff_match.group(1))
                                            for h in hunks:
                                                processed_pairs.append({
                                                    "source": "CVEfixes_Aligned_Hunk",
                                                    "cve_id": cve_id,
                                                    "cwe_id": cwe_id,
                                                    "filename": filename,
                                                    "enclosing_context": h["enclosing_context"],
                                                    "language": "Python",
                                                    "vulnerable_code": h["vulnerable_code"],
                                                    "fixed_code": h["fixed_code"],
                                                    "diff_patch": h["diff_patch"],
                                                })
                                                if len(processed_pairs) >= max_pairs:
                                                    break

                                            if len(processed_pairs) >= max_pairs:
                                                logger.info(
                                                    "Extracted %d verified, aligned Python code pairs! Early stopping.",
                                                    max_pairs,
                                                )
                                                break

                    elif line.startswith('CREATE TABLE IF NOT EXISTS "method_change"'):
                        # file_change table has finished
                        break

        except Exception as e:
            logger.error("Error reading SQL script %s: %s", sql_file, e)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(processed_pairs, out, indent=2, ensure_ascii=False)

    logger.info(
        "Code Pairs processed: %d verified Python pairs (with vulnerable_code & fixed_code) saved to %s",
        len(processed_pairs),
        output_file.name,
    )
    return len(processed_pairs)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(processed_pairs, out, indent=2, ensure_ascii=False)

    logger.info("Code Pairs processed: %d Python pairs saved to %s", len(processed_pairs), output_file.name)
    return len(processed_pairs)


# ==============================================================================
# PIPELINE ORCHESTRATION & SUMMARY
# ==============================================================================

def run_ingestion_pipeline(
    raw_dir: Path,
    processed_dir: Path,
    cve_years: Optional[List[str]] = None,
    skip_cve: bool = False,
    skip_code_pairs: bool = False,
    max_cves: int = 5000,
    max_code_pairs: int = 1000,
) -> Dict[str, Any]:
    """Coordinates the full dataset ingestion and filtering workflow."""
    start_time = time.time()
    logger.info("=================================================================")
    logger.info("STARTING KNOWLEDGE BASE INGESTION & FILTERING PIPELINE")
    logger.info("Raw Directory:       %s", raw_dir)
    logger.info("Processed Directory: %s", processed_dir)
    logger.info("Target Bandit CWEs:  %d categories", len(BANDIT_TARGET_CWES))
    logger.info("=================================================================")

    processed_dir.mkdir(parents=True, exist_ok=True)

    summary: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "bandit_target_cwes": sorted(BANDIT_TARGET_CWES),
        "results": {},
    }

    # 1. MITRE CWE CSV
    cwe_input = raw_dir / "CWE"
    cwe_output = processed_dir / "cwe_mitre.json"
    cwe_count = process_cwe_dataset(cwe_input, cwe_output)
    summary["results"]["mitre_cwe"] = {"count": cwe_count, "path": str(cwe_output)}

    # 2. OWASP Top 10 Markdown
    top10_input = raw_dir / "Top10"
    top10_output = processed_dir / "owasp_top10.json"
    top10_count = process_owasp_top10(top10_input, top10_output)
    summary["results"]["owasp_top10"] = {"count": top10_count, "path": str(top10_output)}

    # 3. OWASP Cheat Sheets Markdown (Python + Universal)
    cheats_input = raw_dir / "cheatsheets"
    cheats_output = processed_dir / "cheatsheets.json"
    cheats_count = process_cheatsheets(cheats_input, cheats_output)
    summary["results"]["cheatsheets"] = {"count": cheats_count, "path": str(cheats_output)}

    # 4. CVE Records JSON (Python + Bandit CWE)
    if not skip_cve:
        cve_input = raw_dir / "cvelistV5-main"
        if not cve_input.exists():
            cve_input = raw_dir / "cve"
        cve_output = processed_dir / "cve_nvd.json"
        cve_count = process_cve_dataset(
            cve_input, cve_output, target_years=cve_years, max_cves=max_cves
        )
        summary["results"]["cve_nvd"] = {"count": cve_count, "path": str(cve_output)}
    else:
        logger.info("Skipping CVE ingestion (--skip-cve requested).")
        summary["results"]["cve_nvd"] = {"count": 0, "status": "skipped"}

    # 5. Code Pairs / CVEfixes SQL
    if not skip_code_pairs:
        pairs_input = raw_dir / "code_pairs"
        pairs_output = processed_dir / "code_pairs.json"
        cve_source_dir = raw_dir / "cvelistV5-main"
        if not cve_source_dir.exists():
            cve_source_dir = raw_dir / "cve"
        pairs_count = process_code_pairs(
            pairs_input, pairs_output, cve_root=cve_source_dir, max_pairs=max_code_pairs
        )
        summary["results"]["code_pairs"] = {"count": pairs_count, "path": str(pairs_output)}
    else:
        logger.info("Skipping Code Pairs ingestion (--skip-code-pairs requested).")
        summary["results"]["code_pairs"] = {"count": 0, "status": "skipped"}

    total_time = time.time() - start_time
    summary["total_runtime_seconds"] = round(total_time, 2)

    # Save summary report
    summary_file = processed_dir / "ingestion_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info("=================================================================")
    logger.info("INGESTION PIPELINE COMPLETED SUCCESSFULLY IN %.2fs", total_time)
    logger.info("Summary report saved to: %s", summary_file)
    logger.info("=================================================================")
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Air-gapped Hybrid Scanner Dataset Ingestion & Filtering Pipeline"
    )
    # Determine default paths relative to script location or current workspace
    script_dir = Path(__file__).resolve().parent
    default_base = script_dir.parent if script_dir.name == "scripts" else script_dir

    default_raw = default_base / "data" / "raw"
    default_processed = default_base / "data" / "processed"

    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=default_raw,
        help="Path to raw dataset directory (default: %(default)s)",
    )
    parser.add_argument(
        "--processed-dir",
        type=Path,
        default=default_processed,
        help="Path to save processed JSON datasets (default: %(default)s)",
    )
    parser.add_argument(
        "--cve-years",
        type=str,
        default="2021,2022,2023,2024,2025,2026",
        help="Comma-separated years of CVEs to inspect (default: %(default)s)",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=5000,
        help="Max number of matching Python CVEs to retain (default: %(default)s)",
    )
    parser.add_argument(
        "--max-code-pairs",
        type=int,
        default=1000,
        help="Max number of Python code pairs to extract from CVEfixes (default: %(default)s)",
    )
    parser.add_argument(
        "--skip-cve",
        action="store_true",
        help="Skip CVE JSON ingestion",
    )
    parser.add_argument(
        "--skip-code-pairs",
        action="store_true",
        help="Skip Code Pairs / CVEfixes ingestion",
    )

    args = parser.parse_args()
    target_years = [y.strip() for y in args.cve_years.split(",") if y.strip()] if args.cve_years else None

    run_ingestion_pipeline(
        raw_dir=args.raw_dir,
        processed_dir=args.processed_dir,
        cve_years=target_years,
        skip_cve=args.skip_cve,
        skip_code_pairs=args.skip_code_pairs,
        max_cves=args.max_cves,
        max_code_pairs=args.max_code_pairs,
    )


if __name__ == "__main__":
    main()
