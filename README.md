<div align="center">

# 🛡️ Safe HEIC Endpoint Tester

**A defensive security tool for auditing server-side HEIC/HEIF image processing pipelines.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3A-yes-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange.svg)]()

*Detect crash-prone HEIC decoders. Identify vulnerable libraries. Audit safely.*

[Overview](#-overview) •
[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[How It Works](#-how-it-works) •
[Safety & Ethics](#-safety--ethics)

</div>

---

## 📖 Overview

`safe_heic_tester` is a **defensive security auditing tool** designed to test
whether a web application safely processes **HEIC/HEIF** images on the server
side.

Modern image pipelines (upload endpoints, CDNs, thumbnailing services) often
decode HEIC files using libraries such as `libheif`, `libavif`, `libde265`,
or ImageMagick. Poorly maintained versions of these libraries have historically
been affected by memory-corruption bugs that can lead to **denial of service,
memory disclosure, or remote code execution** when given malformed input.

This tool helps **developers, security engineers, and bug bounty hunters
(on their own scope)** to:

- Confirm whether their server actually decodes HEIC files.
- Fingerprint the underlying image library and its version.
- Observe how the server behaves when presented with structurally
  malformed — but non-exploitative — HEIC inputs.
- Produce an exportable audit report (JSON + HTML).

> **⚠️ This tool does NOT exploit any vulnerability.**
> It only sends deliberately malformed files and observes the server's
> response (HTTP status, timing, connection state). It cannot execute code,
> read data, or alter the target in any way.

---

## ✨ Features

- 🔍 **Endpoint Discovery** — Confirms whether HEIC is processed server-side.
- 🧪 **9 Built-in Probe Cases** — Covers size overflow, depth nesting,
  offset corruption, and dimension overflow patterns.
- 🧬 **Library Fingerprinting** — Detects `libheif`, `libavif`, `libde265`,
  ImageMagick, FFmpeg, Pillow, and extracts version strings from error
  messages and headers.
- 🎯 **Verdict Classification** — 9 distinct verdicts including
  `SAFE_REJECTION`, `SERVER_ERROR`, `TIMEOUT`, `POSSIBLE_CRASH`.
- 📊 **Rich Reports** — Exportable JSON + interactive HTML report.
- 🖥️ **Interactive CLI** — Prompts for target URL and endpoint if not
  supplied via arguments.
- 💾 **Config Memory** — Remembers last-used URL, endpoint, and field name.
- 🍪 **Session-Aware** — Supports authentication cookies and custom headers.
- 🐢 **Rate-Limited** — Configurable delay between requests (polite by default).
- 🔐 **No Exploitation** — Zero payloads, zero RCE, zero data exfiltration.

---

## ⚙️ Installation

### Requirements

- Python **3.8+**
- `requests`

### Install

```bash
git clone https://github.com/NULL200OK/safe_heic_tester.git
cd safe_heic_tester

pip install requests
```

Or, if you prefer a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate         # Linux / macOS
venv\Scripts\activate            # Windows

pip install requests
```

---

## 🚀 Usage

### Interactive Mode (recommended for first-time users)

```bash
python safe_heic_tester.py
```

You will be prompted for:

```
🌐 Enter target URL (e.g., https://example.com): example.com
📁 Enter endpoint path (e.g., /api/upload): /api/upload
📎 Upload field name [default: image]:
```

Your inputs are saved to `~/.safe_heic_tester.json` for the next run.

---

### Non-Interactive Mode

```bash
python safe_heic_tester.py \
    --url https://example.com \
    --endpoint /api/upload \
    --yes
```

---

### With Authentication

```bash
python safe_heic_tester.py \
    --url https://example.com \
    --endpoint /api/upload \
    --cookie "session=abc123; user=john" \
    --yes
```

---

### Run a Single Test

```bash
python safe_heic_tester.py \
    --url https://example.com \
    --endpoint /api/upload \
    --test huge_box_size \
    --yes
```

Available test names:

| Test Name | Description | Severity |
|-----------|-------------|----------|
| `baseline_valid` | Valid HEIC file (sanity check) | info |
| `empty_file` | Empty payload | info |
| `garbage_data` | 100 random bytes | info |
| `truncated_header` | Truncated `ftyp` box | low |
| `huge_box_size` | `0xFFFFFFFF` box size (integer overflow) | medium |
| `zero_box_size` | Zero box size (infinite loop) | medium |
| `deep_nested_meta` | 50-level nested `meta` boxes | medium |
| `invalid_iloc` | Malformed `iloc` offset (OOB read) | high |
| `huge_ispe` | `ispe` with `0xFFFF x 0xFFFF` dimensions | high |

---

### Slow Scan (Network-Friendly)

```bash
python safe_heic_tester.py \
    --url https://example.com \
    --endpoint /api/upload \
    --delay 5 \
    --yes
```

---

### Reset Saved Configuration

```bash
python safe_heic_tester.py --reset
```

---

## 🧠 How It Works

The tool operates in four stages:

### 1. Input Generation
For each test case, a small HEIC payload is generated in memory.
Payloads are **structurally malformed but non-exploitative** — they target
parser logic, not memory corruption vectors.

### 2. HTTP Dispatch
Each payload is uploaded as a `multipart/form-data` POST request to the
target endpoint with `Content-Type: image/heic`.

### 3. Response Analysis
The server's HTTP status code, response time, headers, and body are
inspected. The tool classifies the outcome into one of nine verdicts:

| Verdict | Meaning |
|---------|---------|
| `BASELINE_OK` | Server accepts and processes HEIC normally |
| `SAFE_REJECTION` | Server correctly rejects malformed input |
| `SERVER_ERROR` | Server returned HTTP 5xx (possible DoS) |
| `TIMEOUT` | Request exceeded timeout (possible infinite loop) |
| `POSSIBLE_CRASH` | Connection dropped mid-request (possible crash) |
| `ACCEPTED_MALFORMED` | Malformed file was accepted — needs review |
| `AUTH_REQUIRED` | Endpoint requires authentication |
| `ENDPOINT_NOT_FOUND` | Endpoint does not exist (404) |
| `UNKNOWN` | Unclassified response |

### 4. Library Fingerprinting
Response bodies and headers are scanned against known error signatures
to identify the decoding library (e.g., `libheif v1.15.1`).

---

## 📊 Sample Output

```
======================================================================
  🛡️  Safe HEIC Tester
  Target: https://example.com/api/upload
  Tests:  9
======================================================================

[1/9] Testing: baseline_valid
      └─ ✅ BASELINE_OK (HTTP 200, 0.42s)

[2/9] Testing: empty_file
      └─ 🟢 SAFE_REJECTION (HTTP 400, 0.11s)

...

[5/9] Testing: huge_box_size
      └─ 🔴 SERVER_ERROR (HTTP 500, 0.87s)
      └─ 📚 libheif v1.15.1

======================================================================
📊 Summary
----------------------------------------------------------------------
  SAFE_REJECTION       : 5
  BASELINE_OK          : 1
  SERVER_ERROR         : 2
  TIMEOUT              : 1

⚠️  Concerns (3):
  • huge_box_size: SERVER_ERROR → HTTP 500
  • zero_box_size: TIMEOUT → possible infinite loop
  • invalid_iloc: POSSIBLE_CRASH → connection drop

📚 Detected Libraries:
  • libheif v1.15.1
======================================================================
```

Reports are saved to `./test_results/`:

```
test_results/
├── report_20250115_143022.json
└── report_20250115_143022.html
```

---

## 🛡️ Safety & Ethics

This tool is intended for **authorized security testing only**.

### ✅ Permitted Use

- Testing your own applications.
- Testing within a bug bounty program whose scope explicitly
  covers the target endpoint.
- Testing in isolated lab environments (staging, VMs, containers).
- Security research with written authorization.

### ❌ Prohibited Use

- Testing any system you do not own or lack authorization to test.
- Using the tool against production systems without explicit consent.
- Using the tool for denial of service, data exfiltration, or any
  unauthorized activity.
- Removing or altering the safety disclaimers in the source code.

### 🔒 Built-in Safeguards

- The tool **does not execute any commands** on the target.
- The tool **does not read any data** from the target.
- The tool **does not persist** any information from the target.
- The tool **imposes a delay** between requests by default (2s).
- The tool **requires explicit confirmation** before running.

By running this tool, you accept full responsibility for its use.

---

## 🗺️ Roadmap

- [ ] Add `--monitor` mode (periodic background scans).
- [ ] Add Slack / Telegram / Discord webhook notifications.
- [ ] Add `--profile` support (multiple target configurations).
- [ ] Add Docker image for isolated execution.
- [ ] Add AVIF and JPEG XL test cases.
- [ ] Add OpenAPI spec import for endpoint auto-discovery.

---

## 🤝 Contributing

Contributions are welcome, provided they respect the project's
defensive nature. Please open an issue before submitting a pull request
for major features.

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-feature`.
3. Commit your changes: `git commit -am 'Add my feature'`.
4. Push to the branch: `git push origin feature/my-feature`.
5. Open a Pull Request.

---

## 📜 License

This project is licensed under the **MIT License** — see the
[LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The author(s) of this tool assume no responsibility for any misuse or
damage caused by this software. Users are solely responsible for
complying with all applicable laws and regulations in their jurisdiction.
```

---

## 👤 Author

**NULL200OK**
GitHub: [https://github.com/NULL200OK](https://github.com/NULL200OK)

---

<div align="center">

**⭐ If this tool helped your security audit, consider starring the repository.**

*Built with a defensive-first mindset.*

</div>
