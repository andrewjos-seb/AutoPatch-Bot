# 🛡️ AutoPatch-Bot

**AI-Powered Code Security Scanner** - Automatically detects vulnerabilities in your code and suggests fixes.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Hackathon%20Project-orange.svg)

## 🚀 Features

### Vulnerability Detection
- ✅ **SQL Injection** - Detects unsanitized queries
- ✅ **XSS (Cross-Site Scripting)** - innerHTML, dangerouslySetInnerHTML, etc.
- ✅ **Hardcoded Secrets** - API keys, passwords, tokens, AWS keys
- ✅ **Command Injection** - os.system, eval, exec, child_process
- ✅ **Insecure Dependencies** - Known vulnerable packages with CVEs
- ✅ **Race Conditions** - Thread-unsafe operations
- ✅ **Path Traversal** - Unsanitized file operations
- ✅ **Insecure Deserialization** - pickle, yaml.load

### Language Support
- 🐍 Python (.py)
- 📜 JavaScript/TypeScript (.js, .ts, .jsx, .tsx)

### Features
- 🤖 **AI-Powered Fixes** - Gemini AI suggests secure code replacements
- 📊 **Confidence Scoring** - Reduces false positives
- 📈 **Risk Scoring** - A-F security grade for your codebase
- 📄 **HTML Reports** - Beautiful, shareable security reports
- 📋 **JSON Export** - For CI/CD integration
- 🔧 **Auto-Fix** - Automatically patch vulnerabilities
- 🔗 **GitHub Integration** - PR scanning, comments, and check runs

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/andrewjos-seb/AutoPatch-Bot.git
cd AutoPatch-Bot

# Install dependencies
pip install -r requirements.txt

# Set up API keys (optional, for AI features)
export GEMINI_API_KEY="your-gemini-api-key"
export GITHUB_TOKEN="your-github-token"
```

---

## 🔍 Usage

### CLI Scanner

```bash
# Scan current directory
python scanner.py .

# Scan and auto-fix vulnerabilities
python scanner.py . --fix

# Generate HTML report
python scanner.py . --output html

# Generate all report formats
python scanner.py . --output all -o security_report

# Scan specific file
python scanner.py vulnerable.py --verbose
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `path` | Path to scan (file or directory) |
| `--fix`, `-f` | Auto-apply fixes to vulnerable code |
| `--verbose`, `-v` | Show detailed output |
| `--output`, `-O` | Output format: `terminal`, `html`, `json`, `all` |
| `-o FILE` | Output file name |

---

## 🔗 GitHub Integration

### Webhook Setup

1. **Run the webhook server:**
```bash
python bot.py
```

2. **Expose with ngrok (for testing):**
```bash
ngrok http 5000
```

3. **Configure GitHub Webhook:**
   - Go to your repo → Settings → Webhooks → Add webhook
   - Payload URL: `https://your-ngrok-url/webhook`
   - Content type: `application/json`
   - Events: Pull requests

### Environment Variables

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"        # GitHub Personal Access Token
export GITHUB_WEBHOOK_SECRET="your-secret"     # Webhook secret (optional)
export GEMINI_API_KEY="AIza..."                # Gemini API key for AI fixes
```

### Features
- 📝 **Auto-comment** on PRs with vulnerability report
- ✅ **Check runs** - Block PRs with critical issues
- 🔧 **Auto-fix PRs** - Creates a PR with security patches

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║     🛡️  AutoPatch-Bot v2.0: AI Security Scanner              ║
╚══════════════════════════════════════════════════════════════╝

📁 Target: ./src
🔧 Auto-fix: Enabled

🔍 Collecting files to scan...
📄 Found 15 source files

📦 Scanning dependencies...
✓ Found 2 dependency issues

🔬 Scanning source files...
  [1/15] app.py... ⚠️ 3 issues
  [2/15] utils.py... ✓

════════════════════════════════════════════════════════════════
📊 SCAN RESULTS
════════════════════════════════════════════════════════════════
   Files scanned:    15
   Lines analyzed:   3,245
   Scan time:        2.34s
   Issues found:     12
   Risk score:       65/100
   Security grade:   C

📈 SUMMARY BY SEVERITY:
   🔴 CRITICAL: 4
   🟠 HIGH: 5
   🟡 MEDIUM: 3
```

---

## 🛠️ Project Structure

```
AutoPatch-Bot/
├── scanner.py          # CLI security scanner
├── bot.py              # GitHub webhook server
├── requirements.txt    # Python dependencies
├── test_vulnerable.py  # Sample vulnerable Python code
├── test_vulnerable.js  # Sample vulnerable JavaScript code
└── README.md           # This file
```

---

## 🏆 Hackathon Metrics

| Metric | Target | Status |
|--------|--------|--------|
| Vulnerability Types | 5+ | ✅ 8 types |
| Languages Supported | 2 | ✅ Python + JS/TS |
| Fix Suggestions | Yes | ✅ AI-powered |
| Confidence Scoring | Yes | ✅ 0-100% |
| GitHub Integration | Yes | ✅ Webhook + PR |
| Report Generation | Yes | ✅ HTML + JSON |

---

## 📝 License

MIT License - Built for Hackathon 2026

---

## 👥 Team

- Built with ❤️ by the AutoPatch-Bot Team
