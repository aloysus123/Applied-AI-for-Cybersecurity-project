"""
Unit tests for Bandit SAST Engine and CWE Mapping.
"""

import os
import sys
import unittest

# Ensure ai_scanner is on the Python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.core.scanner import BanditScanner, scan_code, scan_directory


class TestBanditScanner(unittest.TestCase):
    """Test suite for Bandit scanner integration and result formatting."""

    def setUp(self):
        self.scanner = BanditScanner()
        self.expected_keys = {
            "test_id",
            "cwe_id",
            "line_number",
            "code_snippet",
            "issue_severity",
            "issue_confidence",
        }

    def test_clean_code_returns_empty_list(self):
        """Clean Python code without security flaws should return no issues."""
        clean_code = (
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n\n"
            "print(add(2, 3))\n"
        )
        results = self.scanner.scan_code(clean_code)
        self.assertEqual(results, [])

    def test_empty_input_returns_empty_list(self):
        """Empty or whitespace-only code strings should safely return an empty list."""
        self.assertEqual(self.scanner.scan_code(""), [])
        self.assertEqual(self.scanner.scan_code("   \n\t  "), [])

    def test_command_injection_detection(self):
        """Verify command injection (B602 / CWE-78) is detected with correct metadata."""
        vuln_code = (
            "import subprocess\n"
            "def run_cmd(user_arg):\n"
            "    subprocess.Popen(user_arg, shell=True)\n"
        )
        results = self.scanner.scan_code(vuln_code)
        self.assertTrue(len(results) > 0)

        # Check that expected keys exist in every finding
        for item in results:
            self.assertEqual(set(item.keys()), self.expected_keys)

        # Specifically find B602
        b602_items = [r for r in results if r["test_id"] == "B602"]
        self.assertEqual(len(b602_items), 1)
        b602 = b602_items[0]

        self.assertEqual(b602["cwe_id"], "CWE-78")
        self.assertEqual(b602["line_number"], 3)
        self.assertIn("subprocess.Popen(user_arg, shell=True)", b602["code_snippet"])
        self.assertIn(b602["issue_severity"], ["LOW", "MEDIUM", "HIGH"])
        self.assertIn(b602["issue_confidence"], ["LOW", "MEDIUM", "HIGH"])

    def test_hardcoded_password_detection(self):
        """Verify hardcoded passwords (B105 / CWE-259) are detected."""
        vuln_code = (
            "def authenticate():\n"
            "    secret_token = 'SuperSecret123!'\n"
            "    return secret_token\n"
        )
        results = self.scanner.scan_code(vuln_code)
        b105_items = [r for r in results if r["test_id"] == "B105"]
        self.assertTrue(len(b105_items) >= 1)
        b105 = b105_items[0]

        self.assertEqual(b105["cwe_id"], "CWE-259")
        self.assertEqual(b105["line_number"], 2)
        self.assertIn("secret_token = 'SuperSecret123!'", b105["code_snippet"])

    def test_milestone_check_script(self):
        """Verify the milestone sample script (hardcoded password + Popen shell=True)."""
        code = (
            "import subprocess\n\n"
            "password = \"supersecretpassword123\"\n"
            "subprocess.Popen(\"ls -la\", shell=True)\n"
        )
        results = scan_code(code)
        test_ids = {r["test_id"] for r in results}
        cwe_ids = {r["cwe_id"] for r in results}

        self.assertIn("B105", test_ids)
        self.assertIn("B602", test_ids)
        self.assertIn("CWE-259", cwe_ids)
        self.assertIn("CWE-78", cwe_ids)

    def test_scan_directory(self):
        """Verify recursive folder scanning across sample vulnerable scripts."""
        sample_dir = os.path.join(os.path.dirname(__file__), "sample_vuln_code")
        results = scan_directory(sample_dir)
        self.assertTrue(len(results) >= 3)
        # Check that filename is included when scanning directories
        for item in results:
            self.assertIn("filename", item)
            self.assertIn("test_id", item)
            self.assertIn("cwe_id", item)
            self.assertIn("line_number", item)
            self.assertIn("code_snippet", item)


if __name__ == "__main__":
    unittest.main()
