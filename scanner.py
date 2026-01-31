#!/usr/bin/env python3
"""
🛡️ AutoPatch-Bot: AI-Powered Code Security Scanner v2.0
Hackathon Project - Scans code for vulnerabilities and auto-fixes them.

Features:
- Detects 5+ vulnerability types
- Supports Python + JavaScript/TypeScript
- AI-powered fix suggestions with confidence scoring
- HTML & JSON report generation
- Performance metrics
- Git integration for auto-commits

Detects:
1. SQL Injection
2. XSS (Cross-Site Scripting)
3. Hardcoded Secrets
4. Insecure Dependencies
5. Race Conditions
6. Command Injection
7. Path Traversal
8. Insecure Deserialization
"""

import os
import sys
import json
import re
import argparse
import requests
import time
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ============================================================
# 🎨 TERMINAL COLORS
# ============================================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    GRAY = '\033[90m'

# Enable colors on Windows
if sys.platform == 'win32':
    os.system('color')

# ============================================================
# 🔑 CONFIGURATION
# ============================================================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

# ============================================================
# 📊 VULNERABILITY PATTERNS (Enhanced)
# ============================================================
VULNERABILITY_PATTERNS = {
    "python": {
        "sql_injection": [
            r'execute\s*\(\s*["\'].*%s.*["\']',
            r'execute\s*\(\s*f["\']',
            r'cursor\.execute\s*\([^,]+\+',
            r'\.format\s*\([^)]*\).*execute',
            r'executemany\s*\([^,]+\+',
            r'raw\s*\(\s*["\']SELECT',
        ],
        "xss": [
            r'render_template_string\s*\(',
            r'Markup\s*\([^)]*\+',
            r'\.safe\s*=\s*True',
            r'mark_safe\s*\(',
            r'\|safe\}',
        ],
        "hardcoded_secrets": [
            r'(api_key|apikey|secret|password|token|key|credential)\s*=\s*["\'][^"\']{8,}["\']',
            r'(AWS_ACCESS_KEY|AWS_SECRET|PRIVATE_KEY|GITHUB_TOKEN)\s*=',
            r'sk-[a-zA-Z0-9]{20,}',
            r'ghp_[a-zA-Z0-9]{36}',
            r'AKIA[A-Z0-9]{16}',
        ],
        "race_condition": [
            r'threading\.(Thread|Lock)',
            r'asyncio\.(gather|create_task)',
            r'global\s+\w+',
            r'multiprocessing\.(Process|Pool)',
        ],
        "command_injection": [
            r'os\.system\s*\(',
            r'subprocess\.call\s*\([^,]*\+',
            r'subprocess\.Popen\s*\([^,]*shell\s*=\s*True',
            r'eval\s*\(',
            r'exec\s*\(',
        ],
        "path_traversal": [
            r'open\s*\([^)]*\+[^)]*\)',
            r'os\.path\.join\s*\([^)]*request',
            r'send_file\s*\([^)]*\+',
        ],
        "insecure_deserialization": [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*\)',
            r'marshal\.loads?\s*\(',
        ],
    },
    "javascript": {
        "sql_injection": [
            r'query\s*\(\s*[`"\'].*\$\{',
            r'execute\s*\(\s*[`"\'].*\+',
            r'sequelize\.query\s*\(',
            r'knex\.raw\s*\(',
        ],
        "xss": [
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'document\.write\s*\(',
            r'\.html\s*\([^)]*\+',
            r'dangerouslySetInnerHTML',
            r'v-html\s*=',
            r'\[innerHTML\]',
        ],
        "hardcoded_secrets": [
            r'(api_key|apikey|secret|password|token|key)\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'(AWS_ACCESS_KEY|AWS_SECRET|PRIVATE_KEY)\s*[:=]',
            r'sk-[a-zA-Z0-9]{20,}',
            r'ghp_[a-zA-Z0-9]{36}',
        ],
        "race_condition": [
            r'async\s+function.*await.*await',
            r'Promise\.all\s*\(',
            r'setInterval\s*\(',
        ],
        "command_injection": [
            r'child_process\.exec\s*\(',
            r'child_process\.spawn\s*\([^,]*shell',
            r'eval\s*\(',
            r'new\s+Function\s*\(',
        ],
        "prototype_pollution": [
            r'Object\.assign\s*\([^,]*,\s*\w+\)',
            r'\[key\]\s*=\s*value',
            r'merge\s*\(',
            r'extend\s*\(',
        ],
    }
}

# Insecure dependencies database (expanded)
INSECURE_DEPENDENCIES = {
    "python": {
        "pyyaml": {"vulnerable_versions": ["<5.4"], "reason": "Arbitrary code execution via yaml.load()", "cve": "CVE-2020-14343"},
        "django": {"vulnerable_versions": ["<3.2.14"], "reason": "SQL injection and XSS vulnerabilities", "cve": "CVE-2022-28346"},
        "flask": {"vulnerable_versions": ["<2.2.5"], "reason": "Security headers and cookie issues", "cve": "CVE-2023-30861"},
        "requests": {"vulnerable_versions": ["<2.31.0"], "reason": "Sensitive data exposure", "cve": "CVE-2023-32681"},
        "urllib3": {"vulnerable_versions": ["<2.0.7"], "reason": "CRLF injection vulnerability", "cve": "CVE-2023-45803"},
        "pillow": {"vulnerable_versions": ["<10.0.1"], "reason": "Buffer overflow vulnerabilities", "cve": "CVE-2023-44271"},
        "jinja2": {"vulnerable_versions": ["<3.1.2"], "reason": "Sandbox escape vulnerability", "cve": "CVE-2024-22195"},
        "cryptography": {"vulnerable_versions": ["<41.0.0"], "reason": "Memory corruption issues", "cve": "CVE-2023-38325"},
        "numpy": {"vulnerable_versions": ["<1.22.0"], "reason": "Buffer overflow", "cve": "CVE-2021-41496"},
    },
    "javascript": {
        "lodash": {"vulnerable_versions": ["<4.17.21"], "reason": "Prototype pollution", "cve": "CVE-2021-23337"},
        "axios": {"vulnerable_versions": ["<1.6.0"], "reason": "Server-side request forgery", "cve": "CVE-2023-45857"},
        "express": {"vulnerable_versions": ["<4.18.2"], "reason": "Open redirect vulnerability", "cve": "CVE-2022-24999"},
        "minimist": {"vulnerable_versions": ["<1.2.6"], "reason": "Prototype pollution", "cve": "CVE-2021-44906"},
        "node-fetch": {"vulnerable_versions": ["<2.6.7"], "reason": "Sensitive information exposure", "cve": "CVE-2022-0235"},
        "jsonwebtoken": {"vulnerable_versions": ["<9.0.0"], "reason": "Algorithm confusion attacks", "cve": "CVE-2022-23529"},
        "moment": {"vulnerable_versions": ["<2.29.4"], "reason": "ReDoS vulnerability", "cve": "CVE-2022-31129"},
        "qs": {"vulnerable_versions": ["<6.10.3"], "reason": "Prototype pollution", "cve": "CVE-2022-24999"},
    }
}

# Severity scoring
SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2
}

# ============================================================
# 🤖 GEMINI API
# ============================================================
def call_gemini_api(prompt):
    """Call Gemini API using REST."""
    if not GEMINI_API_KEY:
        return None
        
    headers = {"Content-Type": "application/json"}
    
    data = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096}
    }
    
    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers=headers, json=data, timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            return result['candidates'][0]['content']['parts'][0]['text'].strip()
        return None
    except Exception:
        return None

# ============================================================
# 🔍 SCANNER CLASS
# ============================================================
class SecurityScanner:
    def __init__(self, target_path, auto_fix=False, verbose=False, 
                 output_format='terminal', output_file=None):
        self.target_path = Path(target_path)
        self.auto_fix = auto_fix
        self.verbose = verbose
        self.output_format = output_format
        self.output_file = output_file
        self.issues_found = []
        self.files_scanned = 0
        self.files_fixed = 0
        self.lines_scanned = 0
        self.start_time = None
        self.end_time = None
        
    def print_banner(self):
        """Print the scanner banner."""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║     🛡️  AutoPatch-Bot v2.0: AI Security Scanner              ║
║     Detecting vulnerabilities & auto-patching code           ║
╠══════════════════════════════════════════════════════════════╣
║  Detects: SQL Injection | XSS | Secrets | Dependencies      ║
║           Race Conditions | Command Injection | Path Traversal║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}"""
        print(banner)
        print(f"{Colors.YELLOW}📁 Target: {self.target_path}{Colors.END}")
        print(f"{Colors.YELLOW}🔧 Auto-fix: {'Enabled' if self.auto_fix else 'Disabled'}{Colors.END}")
        print(f"{Colors.YELLOW}📊 Output: {self.output_format.upper()}{Colors.END}")
        print(f"{Colors.YELLOW}📅 Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print("─" * 64)

    def get_language(self, filename):
        """Determine language from file extension."""
        ext = Path(filename).suffix.lower()
        if ext == '.py':
            return 'python'
        elif ext in ['.js', '.ts', '.jsx', '.tsx', '.mjs']:
            return 'javascript'
        return None

    def scan_dependencies(self):
        """Scan dependency files for insecure packages."""
        issues = []
        
        # Check Python requirements
        req_patterns = ['requirements*.txt', 'Pipfile', 'pyproject.toml']
        for pattern in req_patterns:
            for req_file in self.target_path.rglob(pattern):
                try:
                    content = req_file.read_text()
                    for line in content.splitlines():
                        line_lower = line.strip().lower()
                        if line_lower and not line_lower.startswith('#'):
                            match = re.match(r'^([a-zA-Z0-9_-]+)', line_lower)
                            if match:
                                pkg_name = match.group(1)
                                if pkg_name in INSECURE_DEPENDENCIES['python']:
                                    info = INSECURE_DEPENDENCIES['python'][pkg_name]
                                    issues.append({
                                        'file': str(req_file),
                                        'type': 'Insecure Dependency',
                                        'severity': 'HIGH',
                                        'confidence': 90,
                                        'line': 0,
                                        'vulnerable_code': line.strip(),
                                        'description': f"Package '{pkg_name}' has known vulnerabilities",
                                        'explanation': f"{info['reason']} ({info.get('cve', 'N/A')})",
                                        'fix': f"Upgrade: pip install --upgrade {pkg_name}",
                                        'cve': info.get('cve', 'N/A')
                                    })
                except Exception as e:
                    if self.verbose:
                        print(f"Error reading {req_file}: {e}")

        # Check package.json
        for pkg_file in self.target_path.rglob('package.json'):
            if 'node_modules' in str(pkg_file):
                continue
            try:
                content = json.loads(pkg_file.read_text())
                all_deps = {}
                all_deps.update(content.get('dependencies', {}))
                all_deps.update(content.get('devDependencies', {}))
                
                for pkg_name in all_deps:
                    pkg_lower = pkg_name.lower()
                    if pkg_lower in INSECURE_DEPENDENCIES['javascript']:
                        info = INSECURE_DEPENDENCIES['javascript'][pkg_lower]
                        issues.append({
                            'file': str(pkg_file),
                            'type': 'Insecure Dependency',
                            'severity': 'HIGH',
                            'confidence': 90,
                            'line': 0,
                            'vulnerable_code': f'"{pkg_name}": "{all_deps[pkg_name]}"',
                            'description': f"Package '{pkg_name}' has known vulnerabilities",
                            'explanation': f"{info['reason']} ({info.get('cve', 'N/A')})",
                            'fix': f"Upgrade: npm update {pkg_name}",
                            'cve': info.get('cve', 'N/A')
                        })
            except Exception as e:
                if self.verbose:
                    print(f"Error reading {pkg_file}: {e}")
                    
        return issues

    def pre_scan_patterns(self, content, language):
        """Quick pattern-based pre-scan for potential issues."""
        potential_issues = []
        patterns = VULNERABILITY_PATTERNS.get(language, {})
        
        for vuln_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                try:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        potential_issues.append({
                            'type': vuln_type,
                            'line': line_num,
                            'match': match.group()
                        })
                except re.error:
                    continue
        
        return potential_issues

    def ai_scan_code(self, filename, content, potential_issues=None):
        """Send code to Gemini AI for deep analysis."""
        if not GEMINI_API_KEY:
            return []
            
        context = ""
        if potential_issues:
            context = f"\nPre-scan found potential issues at lines: {[p['line'] for p in potential_issues]}"
        
        prompt = f"""You are an expert security code reviewer. Analyze this code from {filename}.
{context}

DETECT THESE VULNERABILITIES:
1. SQL Injection - unsanitized user input in queries
2. XSS - unsanitized output to HTML
3. Hardcoded Secrets - API keys, passwords, tokens
4. Command Injection - os.system, eval, exec with user input
5. Path Traversal - file operations with user input
6. Race Conditions - thread-unsafe operations
7. Insecure Deserialization - pickle, yaml.load

For EACH vulnerability, return JSON:
{{
    "found": true,
    "type": "SQL Injection",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": 0-100,
    "line_number": 42,
    "vulnerable_code": "code snippet",
    "explanation": "Why dangerous",
    "fixed_code": "Fixed code"
}}

If clean: {{"found": false}}
Return ONLY valid JSON.

CODE:
```
{content[:8000]}  
```"""
        
        response_text = call_gemini_api(prompt)
        if not response_text:
            return []
            
        try:
            text = response_text.replace("```json", "").replace("```", "").strip()
            result = json.loads(text)
            if isinstance(result, dict):
                return [] if result.get('found') == False else [result]
            return [r for r in result if r.get('found', True)]
        except json.JSONDecodeError:
            return []

    def scan_file(self, filepath):
        """Scan a single file for vulnerabilities."""
        language = self.get_language(filepath)
        if not language:
            return []
        
        try:
            content = Path(filepath).read_text(encoding='utf-8', errors='ignore')
            self.lines_scanned += len(content.splitlines())
        except Exception as e:
            print(f"{Colors.RED}Error reading {filepath}: {e}{Colors.END}")
            return []
        
        self.files_scanned += 1
        
        # Pattern pre-scan
        potential = self.pre_scan_patterns(content, language)
        
        # AI scan
        ai_results = self.ai_scan_code(filepath, content, potential)
        
        issues = []
        
        # Use AI results
        for result in ai_results:
            if result.get('confidence', 50) >= 50:
                issues.append({
                    'file': str(filepath),
                    'type': result.get('type', 'Unknown'),
                    'severity': result.get('severity', 'MEDIUM'),
                    'confidence': result.get('confidence', 50),
                    'line': result.get('line_number', 0),
                    'vulnerable_code': result.get('vulnerable_code', ''),
                    'explanation': result.get('explanation', ''),
                    'fixed_code': result.get('fixed_code', '')
                })
        
        # Fallback to pattern results
        if not issues and potential:
            type_mapping = {
                'sql_injection': ('SQL Injection', 'CRITICAL'),
                'xss': ('XSS (Cross-Site Scripting)', 'HIGH'),
                'hardcoded_secrets': ('Hardcoded Secret', 'CRITICAL'),
                'race_condition': ('Race Condition', 'MEDIUM'),
                'command_injection': ('Command Injection', 'CRITICAL'),
                'path_traversal': ('Path Traversal', 'HIGH'),
                'insecure_deserialization': ('Insecure Deserialization', 'CRITICAL'),
                'prototype_pollution': ('Prototype Pollution', 'HIGH'),
            }
            lines = content.splitlines()
            for p in potential:
                vuln_type, severity = type_mapping.get(p['type'], ('Security Issue', 'MEDIUM'))
                line_content = lines[p['line']-1] if p['line'] <= len(lines) else ''
                issues.append({
                    'file': str(filepath),
                    'type': vuln_type,
                    'severity': severity,
                    'confidence': 75,
                    'line': p['line'],
                    'vulnerable_code': line_content.strip(),
                    'explanation': f"Pattern detected: {p['match'][:60]}",
                    'fixed_code': 'Use AI mode for auto-fix (set GEMINI_API_KEY)'
                })
        
        return issues

    def apply_fix(self, filepath, vulnerable_code, fixed_code):
        """Apply a fix to a file."""
        if not vulnerable_code or not fixed_code or fixed_code.startswith('Use AI mode'):
            return False
            
        try:
            content = Path(filepath).read_text(encoding='utf-8')
            if vulnerable_code in content:
                new_content = content.replace(vulnerable_code, fixed_code)
                Path(filepath).write_text(new_content, encoding='utf-8')
                return True
        except Exception:
            pass
        return False

    def print_issue(self, issue, index):
        """Print a single issue with formatting."""
        severity_colors = {
            'CRITICAL': Colors.RED + Colors.BOLD,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.CYAN
        }
        
        sev = issue.get('severity', 'MEDIUM')
        color = severity_colors.get(sev, Colors.YELLOW)
        confidence = issue.get('confidence', 50)
        
        conf_icon = "🔴" if confidence >= 90 else "🟠" if confidence >= 70 else "🟡"
        
        print(f"""
{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
{Colors.BOLD}[Issue #{index}]{Colors.END} {color}{issue['type']}{Colors.END}
{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
📁 File: {Colors.CYAN}{issue['file']}{Colors.END}
📍 Line: {issue.get('line', 'N/A')}
{color}⚠️ Severity: {sev}{Colors.END}  |  {conf_icon} Confidence: {confidence}%

{Colors.BOLD}❌ Vulnerable Code:{Colors.END}
{Colors.RED}{issue.get('vulnerable_code', 'N/A')}{Colors.END}

{Colors.BOLD}💡 Explanation:{Colors.END}
{issue.get('explanation', 'N/A')}

{Colors.BOLD}✅ Suggested Fix:{Colors.END}
{Colors.GREEN}{issue.get('fixed_code', 'N/A')}{Colors.END}
""")

    def calculate_risk_score(self):
        """Calculate overall risk score."""
        if not self.issues_found:
            return 0, "A+"
        
        total_score = sum(
            SEVERITY_SCORES.get(i.get('severity', 'MEDIUM'), 5) * (i.get('confidence', 50) / 100)
            for i in self.issues_found
        )
        
        # Normalize to 0-100
        risk_score = min(100, total_score * 5)
        
        if risk_score < 10:
            grade = "A"
        elif risk_score < 25:
            grade = "B"
        elif risk_score < 50:
            grade = "C"
        elif risk_score < 75:
            grade = "D"
        else:
            grade = "F"
            
        return risk_score, grade

    def generate_html_report(self):
        """Generate HTML report."""
        risk_score, grade = self.calculate_risk_score()
        scan_time = (self.end_time - self.start_time) if self.end_time and self.start_time else 0
        
        # Count by severity
        severity_counts = defaultdict(int)
        for issue in self.issues_found:
            severity_counts[issue.get('severity', 'MEDIUM')] += 1
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoPatch-Bot Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            text-align: center;
            padding: 40px 20px;
            background: rgba(255,255,255,0.05);
            border-radius: 20px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
        }}
        .header h1 {{ font-size: 2.5em; color: #00d4ff; margin-bottom: 10px; }}
        .header p {{ color: #888; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(255,255,255,0.05);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            transition: transform 0.3s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; }}
        .stat-label {{ color: #888; margin-top: 5px; }}
        .grade-A {{ color: #00ff88; }}
        .grade-B {{ color: #88ff00; }}
        .grade-C {{ color: #ffff00; }}
        .grade-D {{ color: #ff8800; }}
        .grade-F {{ color: #ff0044; }}
        .severity-critical {{ background: linear-gradient(135deg, #ff0044, #cc0033); }}
        .severity-high {{ background: linear-gradient(135deg, #ff4400, #cc3300); }}
        .severity-medium {{ background: linear-gradient(135deg, #ffaa00, #cc8800); }}
        .severity-low {{ background: linear-gradient(135deg, #00aaff, #0088cc); }}
        .issues {{ margin-top: 30px; }}
        .issue {{
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            border-left: 4px solid;
        }}
        .issue.critical {{ border-color: #ff0044; }}
        .issue.high {{ border-color: #ff4400; }}
        .issue.medium {{ border-color: #ffaa00; }}
        .issue.low {{ border-color: #00aaff; }}
        .issue-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .issue-type {{ font-size: 1.3em; font-weight: bold; }}
        .issue-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .code-block {{
            background: #0a0a15;
            padding: 15px;
            border-radius: 10px;
            overflow-x: auto;
            font-family: 'Fira Code', monospace;
            margin: 10px 0;
        }}
        .code-bad {{ border-left: 3px solid #ff0044; }}
        .code-good {{ border-left: 3px solid #00ff88; }}
        .meta {{ color: #888; font-size: 0.9em; }}
        .footer {{
            text-align: center;
            padding: 20px;
            margin-top: 40px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AutoPatch-Bot Security Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number grade-{grade}">{grade}</div>
                <div class="stat-label">Security Grade</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #ff4444;">{len(self.issues_found)}</div>
                <div class="stat-label">Issues Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #00d4ff;">{self.files_scanned}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #00ff88;">{self.lines_scanned:,}</div>
                <div class="stat-label">Lines Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #ffaa00;">{scan_time:.2f}s</div>
                <div class="stat-label">Scan Time</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card severity-critical">
                <div class="stat-number">{severity_counts.get('CRITICAL', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card severity-high">
                <div class="stat-number">{severity_counts.get('HIGH', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card severity-medium">
                <div class="stat-number">{severity_counts.get('MEDIUM', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card severity-low">
                <div class="stat-number">{severity_counts.get('LOW', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <div class="issues">
            <h2 style="margin-bottom: 20px;">📋 Detailed Findings</h2>
"""
        
        for i, issue in enumerate(self.issues_found, 1):
            sev = issue.get('severity', 'MEDIUM').lower()
            html += f"""
            <div class="issue {sev}">
                <div class="issue-header">
                    <span class="issue-type">{issue['type']}</span>
                    <span class="issue-badge severity-{sev}">{issue.get('severity', 'MEDIUM')} | {issue.get('confidence', 50)}%</span>
                </div>
                <p class="meta">📁 {issue['file']} (Line {issue.get('line', 'N/A')})</p>
                <h4 style="margin-top: 15px;">Vulnerable Code:</h4>
                <div class="code-block code-bad"><code>{issue.get('vulnerable_code', 'N/A')}</code></div>
                <h4>Explanation:</h4>
                <p>{issue.get('explanation', 'N/A')}</p>
                <h4 style="margin-top: 10px;">Suggested Fix:</h4>
                <div class="code-block code-good"><code>{issue.get('fixed_code', 'N/A')}</code></div>
            </div>
"""
        
        html += """
        </div>
        <div class="footer">
            <p>🛡️ AutoPatch-Bot - AI-Powered Code Security Scanner</p>
            <p>Built for Hackathon 2026</p>
        </div>
    </div>
</body>
</html>"""
        
        return html

    def generate_json_report(self):
        """Generate JSON report."""
        risk_score, grade = self.calculate_risk_score()
        scan_time = (self.end_time - self.start_time) if self.end_time and self.start_time else 0
        
        return {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "target": str(self.target_path),
                "files_scanned": self.files_scanned,
                "lines_scanned": self.lines_scanned,
                "scan_duration_seconds": scan_time,
                "auto_fix_enabled": self.auto_fix
            },
            "summary": {
                "total_issues": len(self.issues_found),
                "risk_score": risk_score,
                "security_grade": grade,
                "by_severity": {
                    "critical": len([i for i in self.issues_found if i.get('severity') == 'CRITICAL']),
                    "high": len([i for i in self.issues_found if i.get('severity') == 'HIGH']),
                    "medium": len([i for i in self.issues_found if i.get('severity') == 'MEDIUM']),
                    "low": len([i for i in self.issues_found if i.get('severity') == 'LOW'])
                }
            },
            "issues": self.issues_found
        }

    def run(self):
        """Run the full scan."""
        self.start_time = time.time()
        self.print_banner()
        
        if not self.target_path.exists():
            print(f"{Colors.RED}❌ Path does not exist: {self.target_path}{Colors.END}")
            return
        
        # Check for API key
        if not GEMINI_API_KEY:
            print(f"{Colors.YELLOW}⚠️ GEMINI_API_KEY not set - using pattern-based detection only{Colors.END}")
            print(f"{Colors.GRAY}   Set env var for AI-powered fixes: $env:GEMINI_API_KEY='your_key'{Colors.END}")
        
        # Collect files
        print(f"\n{Colors.BLUE}🔍 Collecting files to scan...{Colors.END}")
        files_to_scan = []
        
        if self.target_path.is_file():
            files_to_scan = [self.target_path]
        else:
            for ext in ['*.py', '*.js', '*.ts', '*.jsx', '*.tsx', '*.mjs']:
                files_to_scan.extend(self.target_path.rglob(ext))
            files_to_scan = [f for f in files_to_scan 
                           if 'node_modules' not in str(f) 
                           and '.git' not in str(f)
                           and '__pycache__' not in str(f)
                           and 'venv' not in str(f)]
        
        print(f"{Colors.GREEN}📄 Found {len(files_to_scan)} source files{Colors.END}")
        
        # Scan dependencies
        print(f"\n{Colors.BLUE}📦 Scanning dependencies...{Colors.END}")
        dep_issues = self.scan_dependencies()
        self.issues_found.extend(dep_issues)
        print(f"{Colors.GREEN}✓ Found {len(dep_issues)} dependency issues{Colors.END}")
        
        # Scan files
        print(f"\n{Colors.BLUE}🔬 Scanning source files...{Colors.END}")
        for i, filepath in enumerate(files_to_scan, 1):
            print(f"  [{i}/{len(files_to_scan)}] {filepath.name}...", end='', flush=True)
            issues = self.scan_file(filepath)
            self.issues_found.extend(issues)
            if issues:
                print(f" {Colors.YELLOW}⚠️ {len(issues)} issues{Colors.END}")
            else:
                print(f" {Colors.GREEN}✓{Colors.END}")
        
        self.end_time = time.time()
        scan_time = self.end_time - self.start_time
        
        # Print results
        risk_score, grade = self.calculate_risk_score()
        
        print(f"\n{'═' * 64}")
        print(f"{Colors.BOLD}📊 SCAN RESULTS{Colors.END}")
        print(f"{'═' * 64}")
        print(f"   Files scanned:    {self.files_scanned}")
        print(f"   Lines analyzed:   {self.lines_scanned:,}")
        print(f"   Scan time:        {scan_time:.2f}s")
        print(f"   Issues found:     {len(self.issues_found)}")
        print(f"   Risk score:       {risk_score:.0f}/100")
        
        grade_colors = {'A': Colors.GREEN, 'B': Colors.GREEN, 'C': Colors.YELLOW, 'D': Colors.RED, 'F': Colors.RED}
        print(f"   Security grade:   {grade_colors.get(grade[0], Colors.YELLOW)}{grade}{Colors.END}")
        
        if not self.issues_found:
            print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 No vulnerabilities detected!{Colors.END}")
        else:
            # Sort and print issues
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            self.issues_found.sort(key=lambda x: severity_order.get(x.get('severity', 'MEDIUM'), 2))
            
            print(f"\n{Colors.RED}{Colors.BOLD}⚠️ VULNERABILITIES DETECTED:{Colors.END}")
            
            for i, issue in enumerate(self.issues_found, 1):
                self.print_issue(issue, i)
            
            # Summary
            print(f"\n{'═' * 64}")
            print(f"{Colors.BOLD}📈 SUMMARY BY SEVERITY:{Colors.END}")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = len([i for i in self.issues_found if i.get('severity') == sev])
                if count > 0:
                    color = {'CRITICAL': Colors.RED, 'HIGH': Colors.RED, 
                            'MEDIUM': Colors.YELLOW, 'LOW': Colors.CYAN}[sev]
                    print(f"   {color}{sev}: {count}{Colors.END}")
        
        # Auto-fix
        if self.auto_fix:
            print(f"\n{Colors.BLUE}{Colors.BOLD}🔧 APPLYING AUTO-FIXES...{Colors.END}")
            for issue in self.issues_found:
                if issue.get('fixed_code') and issue.get('vulnerable_code'):
                    if self.apply_fix(issue['file'], issue['vulnerable_code'], issue['fixed_code']):
                        self.files_fixed += 1
                        print(f"   {Colors.GREEN}✅ Fixed: {issue['type']} in {Path(issue['file']).name}{Colors.END}")
            print(f"\n{Colors.GREEN}🎉 Applied {self.files_fixed} fixes!{Colors.END}")
        
        # Generate reports
        if self.output_format in ['html', 'all']:
            html_file = self.output_file or f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            Path(html_file).write_text(self.generate_html_report(), encoding='utf-8')
            print(f"\n{Colors.GREEN}📄 HTML report saved: {html_file}{Colors.END}")
        
        if self.output_format in ['json', 'all']:
            json_file = (self.output_file or f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            if self.output_format == 'all':
                json_file = json_file.replace('.html', '.json')
            Path(json_file).write_text(json.dumps(self.generate_json_report(), indent=2), encoding='utf-8')
            print(f"{Colors.GREEN}📄 JSON report saved: {json_file}{Colors.END}")
        
        print(f"\n{'═' * 64}")
        print(f"{Colors.CYAN}Scan complete! Stay secure! 🛡️{Colors.END}\n")
        
        return len(self.issues_found) == 0


# ============================================================
# 🚀 MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='🛡️ AutoPatch-Bot v2.0: AI-Powered Code Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py .                          # Scan current directory
  python scanner.py ./src --fix                # Scan and auto-fix
  python scanner.py . --output html            # Generate HTML report
  python scanner.py . --output all -o report   # All formats

Environment:
  GEMINI_API_KEY    Set for AI-powered analysis and fixes
        """
    )
    
    parser.add_argument('path', nargs='?', default='.', help='Path to scan')
    parser.add_argument('--fix', '-f', action='store_true', help='Auto-apply fixes')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--output', '-O', choices=['terminal', 'html', 'json', 'all'], 
                       default='terminal', help='Output format')
    parser.add_argument('-o', '--output-file', help='Output file name')
    
    args = parser.parse_args()
    
    scanner = SecurityScanner(
        target_path=args.path,
        auto_fix=args.fix,
        verbose=args.verbose,
        output_format=args.output,
        output_file=args.output_file
    )
    
    success = scanner.run()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
