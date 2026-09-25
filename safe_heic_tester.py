#!/usr/bin/env python3
"""
Safe HEIC Endpoint Tester
=========================
A defensive security tool that audits web applications for HEIC/HEIF
server-side processing issues.

It checks:
1. Whether the target server processes HEIC images.
2. Which underlying decoding library is used (and its version).
3. How the server reacts to structurally malformed, non-exploitative
   HEIC inputs (safe DoS / robustness probing).

WARNING: Use only on systems you own or have written authorization to test.
WARNING: This tool contains NO exploit code, NO RCE, NO payloads.

Usage:
  # Interactive (prompts for URL and endpoint)
  python safe_heic_tester.py

  # Direct arguments
  python safe_heic_tester.py --url https://example.com --endpoint /api/upload

  # With authentication
  python safe_heic_tester.py --url https://example.com --endpoint /api/upload \\
      --cookie "session=abc123"
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] Missing dependency. Install with: pip install requests")
    sys.exit(1)


# ==================== Saved Configuration Path ====================

CONFIG_FILE = Path.home() / ".safe_heic_tester.json"


# ==================== Configuration ====================

@dataclass
class TestConfig:
    """Runtime configuration for a test session."""
    base_url: str                    # Required - no default
    endpoint: str                    # Required - no default
    field_name: str = "image"
    timeout: float = 30.0
    delay_between_tests: float = 2.0
    max_response_size: int = 5000
    output_dir: Path = Path("./test_results")
    verbose: bool = False
    cookie: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)


# ==================== Test Input Generation ====================

class HEICTestGenerator:
    """
    Generates HEIC payloads for safe testing.

    All payloads here are deliberately NON-exploitative.
    They only aim to trigger clear parser errors or robustness issues.
    """

    @staticmethod
    def minimal_valid_heic() -> bytes:
        """A minimal but valid HEIC file (ftyp box only)."""
        return b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heicmif1"

    @staticmethod
    def empty_file() -> bytes:
        """Completely empty payload."""
        return b""

    @staticmethod
    def garbage_data() -> bytes:
        """100 random bytes."""
        return os.urandom(100)

    @staticmethod
    def truncated_ftyp() -> bytes:
        """File truncated in the middle of the header."""
        return b"\x00\x00\x00\x18ftypheic"

    @staticmethod
    def huge_box_size() -> bytes:
        """Box with an enormous declared size."""
        data = bytearray(HEICTestGenerator.minimal_valid_heic())
        struct.pack_into(">I", data, 0, 0xFFFFFFFF)
        return bytes(data)

    @staticmethod
    def zero_box_size() -> bytes:
        """Box with a declared size of zero."""
        data = bytearray(HEICTestGenerator.minimal_valid_heic())
        struct.pack_into(">I", data, 0, 0x00000000)
        return bytes(data)

    @staticmethod
    def deep_nested_meta() -> bytes:
        """Deeply nested meta boxes."""
        nested = b""
        for _ in range(50):
            inner = nested
            size = 8 + len(inner)
            nested = struct.pack(">I", size) + b"meta" + b"\x00\x00\x00\x00" + inner
        return HEICTestGenerator.minimal_valid_heic() + nested

    @staticmethod
    def invalid_iloc_offset() -> bytes:
        """An iloc box with an offset field pointing outside the file."""
        header = HEICTestGenerator.minimal_valid_heic()
        iloc_payload = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        iloc_size = 8 + len(iloc_payload)
        iloc = struct.pack(">I", iloc_size) + b"iloc" + iloc_payload
        return header + iloc

    @staticmethod
    def fake_huge_ispe() -> bytes:
        """An ispe box with huge dimensions."""
        header = HEICTestGenerator.minimal_valid_heic()
        ispe_payload = (
            b"\x00\x00\x00\x00"
            + struct.pack(">I", 0xFFFF)
            + struct.pack(">I", 0xFFFF)
        )
        ispe_size = 8 + len(ispe_payload)
        ispe = struct.pack(">I", ispe_size) + b"ispe" + ispe_payload
        return header + ispe

    @classmethod
    def all_tests(cls) -> List[Dict]:
        """Returns the full list of test cases."""
        return [
            {
                "name": "baseline_valid",
                "description": "Valid HEIC file - verifies acceptance",
                "data": cls.minimal_valid_heic(),
                "expect": "success",
                "severity": "info",
            },
            {
                "name": "empty_file",
                "description": "Empty payload",
                "data": cls.empty_file(),
                "expect": "rejection",
                "severity": "info",
            },
            {
                "name": "garbage_data",
                "description": "Random bytes",
                "data": cls.garbage_data(),
                "expect": "rejection",
                "severity": "info",
            },
            {
                "name": "truncated_header",
                "description": "Truncated header",
                "data": cls.truncated_ftyp(),
                "expect": "rejection",
                "severity": "low",
            },
            {
                "name": "huge_box_size",
                "description": "Huge box size (Integer Overflow)",
                "data": cls.huge_box_size(),
                "expect": "rejection",
                "severity": "medium",
            },
            {
                "name": "zero_box_size",
                "description": "Zero box size (Infinite Loop)",
                "data": cls.zero_box_size(),
                "expect": "rejection",
                "severity": "medium",
            },
            {
                "name": "deep_nested_meta",
                "description": "Deeply nested meta boxes",
                "data": cls.deep_nested_meta(),
                "expect": "rejection",
                "severity": "medium",
            },
            {
                "name": "invalid_iloc",
                "description": "Invalid iloc offset (OOB Read)",
                "data": cls.invalid_iloc_offset(),
                "expect": "rejection",
                "severity": "high",
            },
            {
                "name": "huge_ispe",
                "description": "Huge ispe dimensions (Overflow)",
                "data": cls.fake_huge_ispe(),
                "expect": "rejection",
                "severity": "high",
            },
        ]


# ==================== Runner ====================

class SafeHEICTester:
    """Main runner - dispatches tests and analyzes responses."""

    def __init__(self, config: TestConfig):
        self.cfg = config
        self.session = self._build_session()
        self.results: List[Dict] = []
        self.cfg.output_dir.mkdir(parents=True, exist_ok=True)

    def _build_session(self) -> requests.Session:
        """Builds an HTTP session with retry behavior."""
        s = requests.Session()
        retry = Retry(
            total=2, backoff_factor=1,
            status_forcelist=[502, 503, 504],
            allowed_methods=["POST"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("https://", adapter)
        s.mount("http://", adapter)

        s.headers.update({
            "User-Agent": "SafeHEICTester/1.0 (Authorized Security Audit)",
            "Accept": "*/*",
        })
        if self.cfg.cookie:
            s.headers["Cookie"] = self.cfg.cookie
        s.headers.update(self.cfg.extra_headers)
        return s

    def _send_test(self, test: Dict) -> Dict:
        """Sends a single test and returns the result."""
        url = self.cfg.base_url.rstrip("/") + self.cfg.endpoint
        files = {
            self.cfg.field_name: (
                f"test_{test['name']}.heic",
                test["data"],
                "image/heic",
            )
        }

        start_time = time.time()
        response_info = {
            "name": test["name"],
            "description": test["description"],
            "expected": test["expect"],
            "severity": test["severity"],
            "input_size": len(test["data"]),
            "input_md5": hashlib.md5(test["data"]).hexdigest(),
        }

        try:
            r = self.session.post(
                url,
                files=files,
                timeout=self.cfg.timeout,
                allow_redirects=False,
            )
            elapsed = time.time() - start_time

            response_info.update({
                "status_code": r.status_code,
                "elapsed_seconds": round(elapsed, 3),
                "response_size": len(r.content),
                "response_headers": dict(r.headers),
                "response_body_preview": r.text[:self.cfg.max_response_size],
                "error": None,
                "timeout": False,
            })

        except requests.exceptions.Timeout:
            response_info.update({
                "status_code": None,
                "elapsed_seconds": self.cfg.timeout,
                "error": "TIMEOUT",
                "timeout": True,
                "response_body_preview": "",
            })

        except requests.exceptions.ConnectionError as e:
            response_info.update({
                "status_code": None,
                "elapsed_seconds": round(time.time() - start_time, 3),
                "error": f"CONNECTION_ERROR: {e}",
                "timeout": False,
                "response_body_preview": "",
            })

        except Exception as e:
            response_info.update({
                "status_code": None,
                "elapsed_seconds": round(time.time() - start_time, 3),
                "error": f"UNEXPECTED: {type(e).__name__}: {e}",
                "timeout": False,
                "response_body_preview": "",
            })

        response_info["analysis"] = self._analyze(test, response_info)
        return response_info

    def _analyze(self, test: Dict, resp: Dict) -> Dict:
        """Analyzes the response and classifies it."""
        status = resp.get("status_code")
        body = (resp.get("response_body_preview") or "").lower()
        headers = resp.get("response_headers") or {}

        analysis = {
            "verdict": "UNKNOWN",
            "indicators": [],
            "library_detected": None,
            "confidence": "low",
        }

        if resp.get("timeout"):
            analysis["verdict"] = "TIMEOUT"
            analysis["indicators"].append("Server did not respond within timeout")
            analysis["confidence"] = "medium"
            return analysis

        if "CONNECTION_ERROR" in (resp.get("error") or ""):
            analysis["verdict"] = "POSSIBLE_CRASH"
            analysis["indicators"].append("Connection dropped - server may have crashed")
            analysis["confidence"] = "medium"
            return analysis

        if status and 500 <= status < 600:
            analysis["verdict"] = "SERVER_ERROR"
            analysis["indicators"].append(f"HTTP {status} - internal server error")
            analysis["confidence"] = "high"

        elif status in (400, 415, 422):
            analysis["verdict"] = "SAFE_REJECTION"
            analysis["indicators"].append(f"HTTP {status} - correct rejection")
            analysis["confidence"] = "high"

        elif status in (200, 201):
            if test["name"] == "baseline_valid":
                analysis["verdict"] = "BASELINE_OK"
                analysis["indicators"].append("Server accepts and processes HEIC")
            else:
                analysis["verdict"] = "ACCEPTED_MALFORMED"
                analysis["indicators"].append(
                    "Malformed file was accepted - either safe handling or lack of validation"
                )
                analysis["confidence"] = "low"

        elif status in (401, 403):
            analysis["verdict"] = "AUTH_REQUIRED"
            analysis["indicators"].append("Authentication required")

        elif status == 404:
            analysis["verdict"] = "ENDPOINT_NOT_FOUND"
            analysis["indicators"].append("Endpoint not found - adjust --endpoint")

        analysis["library_detected"] = self._detect_library(body, headers)
        return analysis

    @staticmethod
    def _detect_library(body: str, headers: Dict) -> Optional[str]:
        """Fingerprints the decoding library from error messages."""
        patterns = {
            "libheif": [r"libheif[\s/\-]?v?([\d.]+)", r"heif[_\-]error"],
            "libavif": [r"libavif[\s/\-]?v?([\d.]+)", r"avif[_\-]error"],
            "pillow":  [r"PIL\.", r"pillow"],
            "imagemagick": [r"imagemagick", r"magick"],
            "ffmpeg":  [r"ffmpeg", r"libavcodec"],
            "libde265": [r"libde265", r"de265"],
        }
        combined = body + " " + json.dumps(headers).lower()
        for lib, pats in patterns.items():
            for p in pats:
                m = re.search(p, combined, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.groups() else "unknown"
                    return f"{lib} v{version}"
        return None

    def run(self, tests: Optional[List[Dict]] = None):
        """Runs all test cases."""
        if tests is None:
            tests = HEICTestGenerator.all_tests()

        print(f"\n{'='*70}")
        print(f"  Safe HEIC Tester")
        print(f"  Target:  {self.cfg.base_url}{self.cfg.endpoint}")
        print(f"  Tests:   {len(tests)}")
        print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")

        for i, test in enumerate(tests, 1):
            print(f"[{i}/{len(tests)}] Testing: {test['name']}")
            print(f"         -> {test['description']}")

            result = self._send_test(test)
            self.results.append(result)

            verdict = result["analysis"]["verdict"]
            icon = {
                "BASELINE_OK": "[OK]",
                "SAFE_REJECTION": "[SAFE]",
                "SERVER_ERROR": "[ERR]",
                "TIMEOUT": "[TIMEOUT]",
                "POSSIBLE_CRASH": "[CRASH?]",
                "ACCEPTED_MALFORMED": "[WARN]",
                "AUTH_REQUIRED": "[AUTH]",
                "ENDPOINT_NOT_FOUND": "[404]",
                "UNKNOWN": "[?]",
            }.get(verdict, "[?]")

            print(f"         -> {icon} {verdict} "
                  f"(HTTP {result.get('status_code')}, "
                  f"{result.get('elapsed_seconds', '?')}s)")

            if result["analysis"]["library_detected"]:
                print(f"         -> Library: {result['analysis']['library_detected']}")

            if i < len(tests):
                time.sleep(self.cfg.delay_between_tests)

        print(f"\n{'='*70}")
        print(f"  Test run complete - {len(self.results)} test(s) executed")
        print(f"{'='*70}\n")

        self._print_summary()
        self._save_report()

    def _print_summary(self):
        """Prints a summary of results."""
        print("Summary")
        print("-" * 70)

        counts = {}
        for r in self.results:
            v = r["analysis"]["verdict"]
            counts[v] = counts.get(v, 0) + 1

        for verdict, count in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"  {verdict:<25} : {count}")

        concerns = [
            r for r in self.results
            if r["analysis"]["verdict"] in (
                "SERVER_ERROR", "TIMEOUT", "POSSIBLE_CRASH"
            )
        ]

        if concerns:
            print(f"\nConcerns ({len(concerns)}):")
            for r in concerns:
                print(f"  - {r['name']}: {r['analysis']['verdict']}")
                for ind in r["analysis"]["indicators"]:
                    print(f"      -> {ind}")

        libs = {
            r["analysis"]["library_detected"]
            for r in self.results
            if r["analysis"]["library_detected"]
        }
        if libs:
            print(f"\nDetected libraries:")
            for lib in libs:
                print(f"  - {lib}")

        print()

    def _save_report(self):
        """Saves the report as JSON and HTML."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        json_path = self.cfg.output_dir / f"report_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.now().isoformat(),
                "target": self.cfg.base_url + self.cfg.endpoint,
                "results": self.results,
            }, f, indent=2, ensure_ascii=False)

        html_path = self.cfg.output_dir / f"report_{timestamp}.html"
        html_path.write_text(self._build_html(timestamp), encoding="utf-8")

        print(f"Report saved:")
        print(f"   JSON: {json_path}")
        print(f"   HTML: {html_path}")
        print(f"   Open the HTML file in a browser to view the report.\n")

    def _build_html(self, timestamp: str) -> str:
        """Builds the HTML report."""
        rows = ""
        for r in self.results:
            verdict = r["analysis"]["verdict"]
            color = {
                "BASELINE_OK": "#3fb950",
                "SAFE_REJECTION": "#3fb950",
                "SERVER_ERROR": "#f85149",
                "TIMEOUT": "#f0883e",
                "POSSIBLE_CRASH": "#f0883e",
                "ACCEPTED_MALFORMED": "#d29922",
                "AUTH_REQUIRED": "#58a6ff",
                "ENDPOINT_NOT_FOUND": "#8b949e",
            }.get(verdict, "#8b949e")

            body = r.get("response_body_preview", "")[:300]
            body = body.replace("<", "&lt;").replace(">", "&gt;")

            rows += f"""
            <tr>
                <td>{r['name']}</td>
                <td>{r['description']}</td>
                <td style="color:{color}; font-weight:bold;">{verdict}</td>
                <td>{r.get('status_code', '-')}</td>
                <td>{r.get('elapsed_seconds', '-')}s</td>
                <td><code>{body}</code></td>
            </tr>
            """

        return f"""<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<title>HEIC Test Report - {self.cfg.base_url}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Tahoma, sans-serif;
         background:#0d1117; color:#c9d1d9; padding:24px; }}
  h1 {{ color:#58a6ff; }}
  .meta {{ background:#161b22; padding:16px; border-radius:8px;
           border:1px solid #30363d; margin-bottom:24px; }}
  .meta b {{ color:#3fb950; }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ text-align:left; padding:10px; border-bottom:1px solid #30363d;
           font-size:13px; vertical-align:top; }}
  th {{ color:#8b949e; background:#161b22; }}
  code {{ font-family:ui-monospace,Menlo,monospace; font-size:11px;
          color:#f0883e; word-break:break-all; }}
  .warning {{ background:#3d1e1e; border-left:4px solid #f85149;
              padding:12px; border-radius:4px; margin:16px 0; }}
</style>
</head>
<body>
<h1>Safe HEIC Test Report</h1>

<div class="meta">
  <p><b>Target:</b> {self.cfg.base_url}{self.cfg.endpoint}</p>
  <p><b>Date:</b> {timestamp}</p>
  <p><b>Number of tests:</b> {len(self.results)}</p>
  <p><b>Tool:</b> Safe HEIC Tester v1.0</p>
</div>

<div class="warning">
  <strong>Notice:</strong> This report is the result of a security audit
  performed on a site owned by the user. All tests are safe and no commands
  were executed on the target.
</div>

<h2>Detailed Results</h2>
<table>
<thead>
<tr>
  <th>Test</th>
  <th>Description</th>
  <th>Verdict</th>
  <th>HTTP</th>
  <th>Time</th>
  <th>Response</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>

</body>
</html>
"""


# ==================== Saved Configuration ====================

def load_saved_config() -> Dict:
    """Loads the saved configuration."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_config(url: str, endpoint: str, field: str):
    """Saves the configuration for next run."""
    try:
        CONFIG_FILE.write_text(json.dumps({
            "url": url,
            "endpoint": endpoint,
            "field": field,
        }, indent=2))
        print(f"   [SAVED] Configuration saved to {CONFIG_FILE}")
    except Exception as e:
        print(f"   [WARN] Failed to save configuration: {e}")


# ==================== Interactive Input ====================

def prompt_for_target(args):
    """
    Prompts the user for URL and endpoint if not provided as arguments.
    """
    saved = load_saved_config()

    print("\n" + "="*70)
    print("  Target Configuration")
    print("="*70)

    # ---------- URL ----------
    if not args.url:
        if saved.get("url"):
            print(f"\nLast URL used: {saved['url']}")
            use_saved = input("   Use it? [Y/n]: ").strip().lower()
            if use_saved in ("", "y", "yes"):
                args.url = saved["url"]

    if not args.url:
        while True:
            url = input("\nEnter target URL (e.g., https://example.com): ").strip()
            if not url:
                print("   URL is required.")
                continue

            if not url.startswith(("http://", "https://")):
                url = "https://" + url
                print(f"   Prefixed with https:// -> {url}")

            if not re.match(r"^https?://[a-zA-Z0-9\-._]+\.[a-zA-Z]{2,}", url):
                print("   Invalid URL format. Example: https://example.com")
                continue

            args.url = url
            break
    else:
        print(f"\nURL (from argument): {args.url}")

    # ---------- Endpoint ----------
    if not args.endpoint:
        if saved.get("endpoint"):
            print(f"\nLast endpoint used: {saved['endpoint']}")
            use_saved = input("   Use it? [Y/n]: ").strip().lower()
            if use_saved in ("", "y", "yes"):
                args.endpoint = saved["endpoint"]

    if not args.endpoint:
        while True:
            endpoint = input(
                "\nEnter endpoint path (e.g., /api/upload): "
            ).strip()
            if not endpoint:
                print("   Endpoint is required.")
                continue

            if not endpoint.startswith("/"):
                endpoint = "/" + endpoint
                print(f"   Prefixed with / -> {endpoint}")

            args.endpoint = endpoint
            break
    else:
        print(f"Endpoint (from argument): {args.endpoint}")

    # ---------- Field (optional) ----------
    if args.field == "image":
        field = input(
            f"\nUpload field name [default: image, press Enter to skip]: "
        ).strip()
        if field:
            args.field = field

    # ---------- Save ----------
    save_config(args.url, args.endpoint, args.field)

    # ---------- Confirmation ----------
    print("\n" + "="*70)
    print("  Final Configuration")
    print("="*70)
    print(f"  Target    : {args.url}{args.endpoint}")
    print(f"  Field     : {args.field}")
    print(f"  Timeout   : {args.timeout}s")
    print(f"  Delay     : {args.delay}s")
    print("="*70)

    return args


# ==================== CLI ====================

def parse_args():
    p = argparse.ArgumentParser(
        description="Safe testing of your web application against HEIC-related issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive (prompts for URL and endpoint)
  python safe_heic_tester.py

  # Direct arguments
  python safe_heic_tester.py --url https://example.com --endpoint /api/upload

  # With authentication
  python safe_heic_tester.py --url https://example.com --endpoint /api/upload \\
      --cookie "session=abc123"

  # Slow scan
  python safe_heic_tester.py --url https://example.com --endpoint /api/upload \\
      --delay 5

  # Single test
  python safe_heic_tester.py --url https://example.com --endpoint /api/upload \\
      --test huge_box_size

  # Reset saved configuration
  python safe_heic_tester.py --reset
        """,
    )

    # --url and --endpoint have no required and no default
    p.add_argument("--url", default=None,
                   help="Target URL (if omitted, you will be prompted)")
    p.add_argument("--endpoint", default=None,
                   help="Upload endpoint path (if omitted, you will be prompted)")

    p.add_argument("--field", default="image", help="Upload field name")
    p.add_argument("--cookie", help="Session cookie for authentication")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="Request timeout in seconds")
    p.add_argument("--delay", type=float, default=2.0,
                   help="Delay between tests in seconds")
    p.add_argument("--output", default="./test_results",
                   help="Output directory for reports")
    p.add_argument("--test", help="Run a single test by name")
    p.add_argument("--header", action="append", default=[],
                   help="Additional header (Key: Value)")
    p.add_argument("--verbose", action="store_true",
                   help="Enable verbose output")
    p.add_argument("--yes", action="store_true",
                   help="Skip ownership confirmation prompt")
    p.add_argument("--reset", action="store_true",
                   help="Delete the saved configuration")

    return p.parse_args()


def main():
    args = parse_args()

    # ---------- Reset saved configuration if requested ----------
    if args.reset:
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
            print(f"[REMOVED] Saved configuration deleted: {CONFIG_FILE}")
        else:
            print("[INFO] No saved configuration found.")
        sys.exit(0)

    # ---------- Interactive input ----------
    args = prompt_for_target(args)

    # ---------- Security notice ----------
    print("\n" + "="*70)
    print("  Safe HEIC Tester - For authorized security testing ONLY")
    print("="*70)
    print("\nThis tool:")
    print("  [+] Checks whether your server processes HEIC on the backend")
    print("  [+] Fingerprints the decoding library and version")
    print("  [+] Observes server behavior against malformed inputs")
    print("  [-] Does NOT execute any commands on the target")
    print("  [-] Does NOT exploit any vulnerability")
    print("  [-] Does NOT attempt to read any data")

    if not args.yes:
        print("\nI confirm that I own this target or have written authorization to test it.")
        confirm = input("Type 'yes' to continue: ").strip().lower()
        if confirm != "yes":
            print("Aborted.")
            sys.exit(0)

    # ---------- Build extra headers ----------
    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    # ---------- Configuration ----------
    cfg = TestConfig(
        base_url=args.url,
        endpoint=args.endpoint,
        field_name=args.field,
        timeout=args.timeout,
        delay_between_tests=args.delay,
        output_dir=Path(args.output),
        verbose=args.verbose,
        cookie=args.cookie,
        extra_headers=extra_headers,
    )

    # ---------- Test selection ----------
    all_tests = HEICTestGenerator.all_tests()
    if args.test:
        all_tests = [t for t in all_tests if t["name"] == args.test]
        if not all_tests:
            print(f"[!] No test found with name: {args.test}")
            print(f"    Available: {[t['name'] for t in HEICTestGenerator.all_tests()]}")
            sys.exit(1)

    # ---------- Run ----------
    tester = SafeHEICTester(cfg)
    tester.run(all_tests)


if __name__ == "__main__":
    main()