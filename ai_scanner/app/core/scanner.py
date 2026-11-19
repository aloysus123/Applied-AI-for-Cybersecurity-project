"""
SAST Engine Wrapper for Bandit Static Analysis.

Accepts raw Python code strings, individual files, or entire source code
directories, executes Bandit static security analysis, and parses the
structured JSON output into clean internal dictionaries for downstream
RAG and LLM triage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Optional

# Fallback mapping from Bandit Test ID to MITRE CWE ID
BANDIT_TO_CWE: dict[str, str] = {
    # Command Injection / Shell Execution
    "B404": "CWE-78",   # import_subprocess
    "B601": "CWE-78",   # paramiko_calls
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_with_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions (SQLi)
    "B609": "CWE-78",   # linux_wildcard_injection
    # Hardcoded Secrets & Cryptographic Weaknesses
    "B105": "CWE-259",  # hardcoded_password_string
    "B106": "CWE-259",  # hardcoded_password_funcarg
    "B107": "CWE-259",  # hardcoded_password_default
    "B108": "CWE-377",  # hardcoded_tmp_directory
    "B303": "CWE-327",  # md5 / sha1
    "B304": "CWE-327",  # ciphers
    "B305": "CWE-327",  # cipher_modes
    "B413": "CWE-327",  # import_pycrypto (deprecated crypto)
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B502": "CWE-295",  # ssl_with_bad_version
    "B503": "CWE-295",  # ssl_with_bad_defaults
    "B504": "CWE-295",  # ssl_with_no_revoke
    "B505": "CWE-327",  # weak_cryptographic_key
    # Insecure Deserialization
    "B301": "CWE-502",  # pickle
    "B302": "CWE-502",  # marshal
    "B403": "CWE-502",  # import_pickle
    "B506": "CWE-502",  # yaml_load
    # Code Injection / Dynamic Execution
    "B102": "CWE-95",   # exec_used
    "B307": "CWE-95",   # eval
    # Cross-Site Scripting (XSS)
    "B701": "CWE-79",   # jinja2_autoescape_false
    "B702": "CWE-79",   # use_of_mako_templates
    "B703": "CWE-79",   # django_mark_safe
    # XML External Entity (XXE)
    "B313": "CWE-611",  # xml_bad_cElementTree
    "B314": "CWE-611",  # xml_bad_ElementTree
    "B315": "CWE-611",  # xml_bad_expatbuilder
    "B316": "CWE-611",  # xml_bad_expatreader
    "B317": "CWE-611",  # xml_bad_xmlsax
    "B318": "CWE-611",  # xml_bad_minidom
    "B319": "CWE-611",  # xml_bad_pulldom
    "B320": "CWE-611",  # xml_bad_etree
    "B405": "CWE-611",  # import_xml_etree
    "B406": "CWE-611",  # import_xml_sax
    "B407": "CWE-611",  # import_xml_expat
    "B408": "CWE-611",  # import_xml_minidom
    "B409": "CWE-611",  # import_xml_pulldom
    "B410": "CWE-611",  # import_lxml
}

DEFAULT_EXCLUDE_PATTERNS = [
    "*/venv/*",
    "*/.venv/*",
    "*/env/*",
    "*/.git/*",
    "*/__pycache__/*",
    "*/site-packages/*",
    "*/node_modules/*",
]


def _resolve_bandit_command() -> list[str]:
    """
    Determine the best command to invoke Bandit reliably across
    virtual environments, containers, and host platforms.
    """
    env_bandit = os.environ.get("BANDIT_PATH")
    if env_bandit and (os.path.isfile(env_bandit) or shutil.which(env_bandit)):
        return [env_bandit]

    which_bandit = shutil.which("bandit")
    if which_bandit:
        return [which_bandit]

    # Search common virtualenv locations relative to current working directory or sys.executable
    script_dirs = [
        os.path.dirname(sys.executable),
        os.path.join(os.getcwd(), "ai_scanner", "venv", "Scripts"),
        os.path.join(os.getcwd(), "ai_scanner", "venv", "bin"),
        os.path.join(os.getcwd(), "venv", "Scripts"),
        os.path.join(os.getcwd(), "venv", "bin"),
    ]
    for directory in script_dirs:
        for name in ("bandit.exe", "bandit"):
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return [candidate]

    # Fallback to invoking bandit module through the current python runtime
    return [sys.executable, "-m", "bandit"]


def _extract_cwe_id(issue: dict[str, Any]) -> str:
    """Normalize and extract the CWE identifier (e.g., CWE-78)."""
    cwe_info = issue.get("issue_cwe")
    if isinstance(cwe_info, dict) and cwe_info.get("id"):
        return f"CWE-{cwe_info['id']}"
    if isinstance(cwe_info, int):
        return f"CWE-{cwe_info}"
    if isinstance(cwe_info, str) and cwe_info.strip():
        val = cwe_info.strip()
        return val if val.upper().startswith("CWE-") else f"CWE-{val}"

    test_id = issue.get("test_id", "")
    return BANDIT_TO_CWE.get(test_id, "CWE-UNKNOWN")


def _extract_code_snippet(issue: dict[str, Any], raw_code: str = "") -> str:
    """
    Extract the exact flagged line(s) from the code string or file,
    falling back to Bandit's formatted snippet if raw indexing fails.
    """
    line_number = issue.get("line_number", 1)
    line_range = issue.get("line_range") or [line_number]

    # If raw_code wasn't passed directly, try loading from issue filename if exists
    if not raw_code:
        file_path = issue.get("filename")
        if file_path and os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    raw_code = f.read()
            except OSError:
                raw_code = ""

    if raw_code:
        code_lines = raw_code.splitlines()
        if code_lines:
            start_idx = max(0, min(line_range) - 1)
            end_idx = min(len(code_lines), max(line_range))
            if start_idx < len(code_lines):
                extracted = "\n".join(code_lines[start_idx:end_idx]).strip()
                if extracted:
                    return extracted

    # Fallback: strip line number prefixes from Bandit's code field
    raw_snippet = issue.get("code", "")
    cleaned_lines = [re.sub(r"^\s*\d+\s*", "", line) for line in raw_snippet.splitlines()]
    return "\n".join(cleaned_lines).strip()


class BanditScanner:
    """Bandit SAST wrapper for deterministic static analysis of Python code."""

    def __init__(self, bandit_command: Optional[list[str]] = None):
        self.bandit_command = bandit_command or _resolve_bandit_command()

    def scan_code(self, raw_code: str) -> list[dict[str, Any]]:
        """
        Scan a raw Python code string with Bandit.

        Writes the code to a secure temporary file, executes bandit -f json -q <temp_file>,
        and parses the output into a list of clean internal dictionaries containing:
          - test_id (e.g., B602)
          - cwe_id (e.g., CWE-78)
          - line_number and code_snippet (exact flagged lines)
          - issue_severity and issue_confidence
        """
        if not raw_code or not raw_code.strip():
            return []

        # Secure temporary file creation (compatible with Windows & POSIX)
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8"
        ) as temp_file:
            temp_file.write(raw_code)
            temp_file_path = temp_file.name

        try:
            cmd = self.bandit_command + ["-f", "json", "-q", temp_file_path]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            stdout = res.stdout.strip()
            if not stdout:
                if res.returncode not in (0, 1) and res.stderr:
                    raise RuntimeError(f"Bandit execution failed (exit code {res.returncode}): {res.stderr}")
                return []

            try:
                raw_json = json.loads(stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Failed to parse Bandit JSON output: {exc}. Output was: {stdout}") from exc

            return self._parse_bandit_results(raw_json, raw_code=raw_code, include_file=False)

        finally:
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except OSError:
                    pass

    def scan_file(self, file_path: str) -> list[dict[str, Any]]:
        """Read a Python file from disk and scan its contents."""
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
        results = self.scan_code(code)
        # Attach the filename metadata for file-based scans
        rel_path = os.path.relpath(file_path, os.getcwd())
        for r in results:
            r["filename"] = rel_path
        return results

    def scan_directory(
        self,
        dir_path: str,
        exclude_patterns: Optional[list[str]] = None
    ) -> list[dict[str, Any]]:
        """
        Recursively scan an entire source code folder with Bandit using -r.
        Excludes virtual environments, cache, and test libraries by default.
        """
        if not os.path.isdir(dir_path):
            raise NotADirectoryError(f"Target directory does not exist: {dir_path}")

        excludes = exclude_patterns or DEFAULT_EXCLUDE_PATTERNS
        cmd = self.bandit_command + ["-r", dir_path, "-x", ",".join(excludes), "-f", "json", "-q"]

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        stdout = res.stdout.strip()
        if not stdout:
            if res.returncode not in (0, 1) and res.stderr:
                raise RuntimeError(f"Bandit directory scan failed (exit code {res.returncode}): {res.stderr}")
            return []

        try:
            raw_json = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Failed to parse Bandit JSON output: {exc}. Output was: {stdout}") from exc

        return self._parse_bandit_results(raw_json, raw_code="", include_file=True)

    def scan_path(self, target_path: str) -> list[dict[str, Any]]:
        """Auto-detect whether target is a file or a directory and scan accordingly."""
        if os.path.isdir(target_path):
            return self.scan_directory(target_path)
        return self.scan_file(target_path)

    def _parse_bandit_results(
        self,
        raw_json: dict[str, Any],
        raw_code: str = "",
        include_file: bool = False
    ) -> list[dict[str, Any]]:
        """Parse raw Bandit JSON findings into clean internal dictionaries."""
        parsed_findings: list[dict[str, Any]] = []

        for issue in raw_json.get("results", []):
            finding: dict[str, Any] = {}

            if include_file:
                filepath = issue.get("filename", "")
                try:
                    rel_path = os.path.relpath(filepath, os.getcwd())
                except ValueError:
                    rel_path = filepath
                finding["filename"] = rel_path

            finding.update({
                "test_id": issue.get("test_id", "UNKNOWN"),
                "cwe_id": _extract_cwe_id(issue),
                "line_number": issue.get("line_number", 0),
                "code_snippet": _extract_code_snippet(issue, raw_code),
                "issue_severity": issue.get("issue_severity", "UNDEFINED"),
                "issue_confidence": issue.get("issue_confidence", "UNDEFINED"),
            })
            parsed_findings.append(finding)

        return parsed_findings


# Convenience functions for direct import
def scan_code(raw_code: str) -> list[dict[str, Any]]:
    """Scan raw Python code string and return clean parsed findings."""
    scanner = BanditScanner()
    return scanner.scan_code(raw_code)


def scan_file(file_path: str) -> list[dict[str, Any]]:
    """Scan a single Python file on disk."""
    scanner = BanditScanner()
    return scanner.scan_file(file_path)


def scan_directory(dir_path: str) -> list[dict[str, Any]]:
    """Recursively scan an entire source code directory."""
    scanner = BanditScanner()
    return scanner.scan_directory(dir_path)


def scan_path(target_path: str) -> list[dict[str, Any]]:
    """Scan either a file or a directory."""
    scanner = BanditScanner()
    return scanner.scan_path(target_path)


def main() -> None:
    """CLI entrypoint for standalone testing and pipeline verification."""
    parser = argparse.ArgumentParser(
        description="Deterministic SAST Engine using Bandit for Python code analysis."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Path to Python file OR source folder to scan (or '-' for stdin). If omitted, runs milestone sample check.",
    )
    parser.add_argument(
        "--code",
        "-c",
        type=str,
        help="Raw Python code string to scan.",
    )
    args = parser.parse_args()

    scanner = BanditScanner()

    # 1. Inline code
    if args.code:
        results = scanner.scan_code(args.code)
    # 2. Stdin
    elif args.target == "-":
        code_from_stdin = sys.stdin.read()
        results = scanner.scan_code(code_from_stdin)
    # 3. Path provided (File or Directory)
    elif args.target:
        if not os.path.exists(args.target):
            print(f"Error: Target path not found: {args.target}", file=sys.stderr)
            sys.exit(1)
        results = scanner.scan_path(args.target)
    # 4. Default Milestone Check
    else:
        milestone_code = (
            "import subprocess\n\n"
            "password = \"supersecretpassword123\"\n"
            "subprocess.Popen(\"ls -la\", shell=True)\n"
        )
        results = scanner.scan_code(milestone_code)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
