#!/usr/bin/env python3
"""
🛡️ AutoPatch-Bot: GitHub PR Security Scanner
Webhook service that auto-scans Pull Requests for vulnerabilities

Features:
1. Auto-scan PRs when opened/updated
2. Comment scan results on PRs
3. Suggest fixes inline
4. Block PRs with critical issues
5. Create fix PRs automatically
"""

import os
import re
import json
import hmac
import hashlib
import requests
from flask import Flask, request, jsonify
from datetime import datetime

# ============================================================
# 🔑 CONFIGURATION (Use Environment Variables!)
# ============================================================
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

# App setup
app = Flask(__name__)

# ============================================================
# 📊 VULNERABILITY PATTERNS
# ============================================================
VULNERABILITY_PATTERNS = {
    "python": {
        "sql_injection": [
            (r'execute\s*\(\s*f["\']', "SQL Injection: f-string in execute()"),
            (r'cursor\.execute\s*\([^,]+\+', "SQL Injection: string concatenation"),
            (r'\.format\s*\([^)]*\).*execute', "SQL Injection: .format() in query"),
        ],
        "xss": [
            (r'render_template_string\s*\(', "XSS: render_template_string with user input"),
            (r'Markup\s*\([^)]*\+', "XSS: Markup with concatenation"),
        ],
        "hardcoded_secrets": [
            (r'(api_key|apikey|secret|password|token)\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded secret detected"),
            (r'AKIA[A-Z0-9]{16}', "AWS Access Key detected"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token detected"),
        ],
        "command_injection": [
            (r'os\.system\s*\(', "Command Injection: os.system()"),
            (r'subprocess\.(call|Popen)\s*\([^)]*shell\s*=\s*True', "Command Injection: shell=True"),
            (r'eval\s*\(', "Code Injection: eval()"),
        ],
        "insecure_deserialization": [
            (r'pickle\.loads?\s*\(', "Insecure Deserialization: pickle"),
            (r'yaml\.load\s*\([^)]*\)', "Insecure Deserialization: yaml.load without Loader"),
        ],
    },
    "javascript": {
        "sql_injection": [
            (r'query\s*\(\s*[`"\'].*\$\{', "SQL Injection: template literal in query"),
            (r'execute\s*\(\s*[`"\'].*\+', "SQL Injection: string concatenation"),
        ],
        "xss": [
            (r'innerHTML\s*=', "XSS: innerHTML assignment"),
            (r'document\.write\s*\(', "XSS: document.write()"),
            (r'dangerouslySetInnerHTML', "XSS: dangerouslySetInnerHTML in React"),
        ],
        "hardcoded_secrets": [
            (r'(api_key|apikey|secret|password|token)\s*[:=]\s*["\'][^"\']{10,}["\']', "Hardcoded secret"),
        ],
        "command_injection": [
            (r'child_process\.exec\s*\(', "Command Injection: child_process.exec"),
            (r'eval\s*\(', "Code Injection: eval()"),
        ],
    }
}

SEVERITY_MAP = {
    "sql_injection": "CRITICAL",
    "command_injection": "CRITICAL", 
    "hardcoded_secrets": "CRITICAL",
    "insecure_deserialization": "CRITICAL",
    "xss": "HIGH",
    "race_condition": "MEDIUM",
}

# ============================================================
# 🔐 SECURITY
# ============================================================
def verify_webhook_signature(payload, signature):
    """Verify GitHub webhook signature."""
    if not GITHUB_WEBHOOK_SECRET:
        return True  # Skip verification if no secret configured
    
    expected = 'sha256=' + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected, signature or '')

# ============================================================
# 🤖 GEMINI AI
# ============================================================
def call_gemini_api(prompt):
    """Call Gemini API for AI analysis."""
    if not GEMINI_API_KEY:
        return None
    
    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048}
            },
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()['candidates'][0]['content']['parts'][0]['text'].strip()
    except Exception as e:
        app.logger.error(f"Gemini API error: {e}")
    
    return None

def get_ai_fix(filename, vulnerable_code, vuln_type):
    """Get AI-suggested fix for vulnerability."""
    prompt = f"""You are a security expert. Fix this {vuln_type} vulnerability in {filename}.

Vulnerable code:
```
{vulnerable_code}
```

Provide ONLY the fixed code, no explanation. The fix should:
1. Be a drop-in replacement
2. Maintain the same functionality
3. Be secure against {vuln_type}
"""
    
    fix = call_gemini_api(prompt)
    if fix:
        # Clean up response
        fix = fix.replace("```python", "").replace("```javascript", "").replace("```", "").strip()
    return fix

# ============================================================
# 🔍 SCANNER
# ============================================================
def get_language(filename):
    """Determine language from filename."""
    if filename.endswith('.py'):
        return 'python'
    elif filename.endswith(('.js', '.ts', '.jsx', '.tsx')):
        return 'javascript'
    return None

def scan_code(filename, content):
    """Scan code for vulnerabilities."""
    language = get_language(filename)
    if not language:
        return []
    
    issues = []
    patterns = VULNERABILITY_PATTERNS.get(language, {})
    lines = content.split('\n')
    
    for vuln_type, pattern_list in patterns.items():
        for pattern, description in pattern_list:
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                    
                    # Get AI fix
                    fix = get_ai_fix(filename, line_content, vuln_type)
                    
                    issues.append({
                        'type': vuln_type,
                        'severity': SEVERITY_MAP.get(vuln_type, 'MEDIUM'),
                        'description': description,
                        'line': line_num,
                        'code': line_content.strip(),
                        'fix': fix,
                        'file': filename
                    })
            except re.error:
                continue
    
    return issues

def scan_pr_files(repo_full_name, pr_number):
    """Scan all files in a PR."""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Get PR files
    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/files"
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        app.logger.error(f"Failed to get PR files: {response.status_code}")
        return []
    
    all_issues = []
    files = response.json()
    
    for file in files:
        filename = file['filename']
        language = get_language(filename)
        
        if not language:
            continue
        
        # Get file content
        if file.get('raw_url'):
            content_response = requests.get(file['raw_url'], headers=headers)
            if content_response.status_code == 200:
                issues = scan_code(filename, content_response.text)
                all_issues.extend(issues)
    
    return all_issues

# ============================================================
# 📝 GITHUB INTERACTIONS
# ============================================================
def create_check_run(repo_full_name, head_sha, issues):
    """Create a GitHub Check Run with scan results."""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Determine conclusion
    critical_count = len([i for i in issues if i['severity'] == 'CRITICAL'])
    high_count = len([i for i in issues if i['severity'] == 'HIGH'])
    
    if critical_count > 0:
        conclusion = "failure"
    elif high_count > 0:
        conclusion = "neutral"
    else:
        conclusion = "success"
    
    # Build summary
    summary = f"## 🛡️ Security Scan Results\n\n"
    summary += f"| Severity | Count |\n|----------|-------|\n"
    summary += f"| 🔴 Critical | {critical_count} |\n"
    summary += f"| 🟠 High | {high_count} |\n"
    summary += f"| 🟡 Medium | {len([i for i in issues if i['severity'] == 'MEDIUM'])} |\n"
    summary += f"| Total | {len(issues)} |\n\n"
    
    if issues:
        summary += "### ⚠️ Issues Found\n\n"
        for i, issue in enumerate(issues[:10], 1):  # Limit to 10
            summary += f"**{i}. {issue['type'].replace('_', ' ').title()}** ({issue['severity']})\n"
            summary += f"- File: `{issue['file']}` (Line {issue['line']})\n"
            summary += f"- {issue['description']}\n"
            if issue.get('fix'):
                summary += f"- 💡 Suggested fix available\n"
            summary += "\n"
    else:
        summary += "### ✅ No vulnerabilities detected!\n"
    
    # Create annotations for each issue
    annotations = []
    for issue in issues[:50]:  # GitHub limit
        annotations.append({
            "path": issue['file'],
            "start_line": issue['line'],
            "end_line": issue['line'],
            "annotation_level": "failure" if issue['severity'] == 'CRITICAL' else "warning",
            "title": f"{issue['type'].replace('_', ' ').title()}",
            "message": issue['description'],
            "raw_details": f"Fix: {issue['fix']}" if issue.get('fix') else ""
        })
    
    data = {
        "name": "AutoPatch-Bot Security Scan",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": f"Security Scan: {len(issues)} issues found",
            "summary": summary,
            "annotations": annotations
        }
    }
    
    url = f"https://api.github.com/repos/{repo_full_name}/check-runs"
    response = requests.post(url, headers=headers, json=data)
    
    return response.status_code == 201

def post_pr_comment(repo_full_name, pr_number, issues):
    """Post a comment on the PR with scan results."""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Build comment
    critical_count = len([i for i in issues if i['severity'] == 'CRITICAL'])
    high_count = len([i for i in issues if i['severity'] == 'HIGH'])
    
    if not issues:
        comment = """## 🛡️ AutoPatch-Bot Security Scan

✅ **No vulnerabilities detected!** Your code looks secure.

---
*Powered by AutoPatch-Bot - AI Security Scanner*
"""
    else:
        # Severity emoji/badge
        if critical_count > 0:
            badge = "🔴 **CRITICAL ISSUES FOUND**"
        elif high_count > 0:
            badge = "🟠 **High severity issues found**"
        else:
            badge = "🟡 **Medium/Low issues found**"
        
        comment = f"""## 🛡️ AutoPatch-Bot Security Scan

{badge}

### Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical_count} |
| 🟠 High | {high_count} |
| 🟡 Medium | {len([i for i in issues if i['severity'] == 'MEDIUM'])} |
| **Total** | **{len(issues)}** |

### Vulnerabilities Found

"""
        for i, issue in enumerate(issues[:15], 1):
            severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(issue['severity'], "⚪")
            comment += f"""
<details>
<summary>{severity_icon} <b>{issue['type'].replace('_', ' ').title()}</b> in <code>{issue['file']}</code> (Line {issue['line']})</summary>

**Description:** {issue['description']}

**Vulnerable Code:**
```
{issue['code']}
```
"""
            if issue.get('fix'):
                comment += f"""
**Suggested Fix:**
```
{issue['fix']}
```
"""
            comment += "\n</details>\n"
        
        if len(issues) > 15:
            comment += f"\n*... and {len(issues) - 15} more issues*\n"
        
        comment += """
---
*Powered by AutoPatch-Bot - AI Security Scanner*
"""
    
    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    response = requests.post(url, headers=headers, json={"body": comment})
    
    return response.status_code == 201

def create_fix_pr(repo_full_name, pr_number, issues):
    """Create a new PR with security fixes."""
    if not issues:
        return None
    
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Get the PR info
    pr_url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
    pr_response = requests.get(pr_url, headers=headers)
    
    if pr_response.status_code != 200:
        return None
    
    pr_data = pr_response.json()
    base_branch = pr_data['head']['ref']
    
    # Create a new branch for fixes
    fix_branch = f"autopatch-security-fixes-{pr_number}"
    
    # Get the latest commit SHA
    ref_url = f"https://api.github.com/repos/{repo_full_name}/git/refs/heads/{base_branch}"
    ref_response = requests.get(ref_url, headers=headers)
    
    if ref_response.status_code != 200:
        return None
    
    base_sha = ref_response.json()['object']['sha']
    
    # Create the new branch
    create_ref_url = f"https://api.github.com/repos/{repo_full_name}/git/refs"
    create_ref_data = {
        "ref": f"refs/heads/{fix_branch}",
        "sha": base_sha
    }
    
    ref_create_response = requests.post(create_ref_url, headers=headers, json=create_ref_data)
    
    if ref_create_response.status_code not in [201, 422]:  # 422 = already exists
        app.logger.error(f"Failed to create branch: {ref_create_response.status_code}")
        return None
    
    # Apply fixes to files
    fixes_applied = 0
    for issue in issues:
        if not issue.get('fix'):
            continue
        
        # Get current file content
        file_url = f"https://api.github.com/repos/{repo_full_name}/contents/{issue['file']}?ref={fix_branch}"
        file_response = requests.get(file_url, headers=headers)
        
        if file_response.status_code != 200:
            continue
        
        file_data = file_response.json()
        import base64
        content = base64.b64decode(file_data['content']).decode('utf-8')
        
        # Apply fix
        if issue['code'] in content:
            new_content = content.replace(issue['code'], issue['fix'])
            
            # Update file
            update_url = f"https://api.github.com/repos/{repo_full_name}/contents/{issue['file']}"
            update_data = {
                "message": f"🔒 Fix {issue['type'].replace('_', ' ')} in {issue['file']}",
                "content": base64.b64encode(new_content.encode()).decode(),
                "sha": file_data['sha'],
                "branch": fix_branch
            }
            
            update_response = requests.put(update_url, headers=headers, json=update_data)
            if update_response.status_code == 200:
                fixes_applied += 1
    
    if fixes_applied == 0:
        return None
    
    # Create PR with fixes
    pr_create_url = f"https://api.github.com/repos/{repo_full_name}/pulls"
    pr_create_data = {
        "title": f"🔒 Security Fixes for PR #{pr_number}",
        "body": f"""## 🛡️ AutoPatch-Bot Security Fixes

This PR contains automated security fixes for vulnerabilities detected in PR #{pr_number}.

### Fixes Applied: {fixes_applied}

Please review the changes carefully before merging.

---
*Generated by AutoPatch-Bot*
""",
        "head": fix_branch,
        "base": base_branch
    }
    
    pr_create_response = requests.post(pr_create_url, headers=headers, json=pr_create_data)
    
    if pr_create_response.status_code == 201:
        return pr_create_response.json()['html_url']
    
    return None

# ============================================================
# 🌐 WEBHOOK ENDPOINTS
# ============================================================
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "AutoPatch-Bot",
        "version": "2.0",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/webhook', methods=['POST'])
def webhook():
    """GitHub webhook handler."""
    # Verify signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_webhook_signature(request.data, signature):
        app.logger.warning("Invalid webhook signature")
        return jsonify({"error": "Invalid signature"}), 401
    
    event = request.headers.get('X-GitHub-Event')
    payload = request.json
    
    app.logger.info(f"Received {event} event")
    
    # Handle Pull Request events
    if event == 'pull_request':
        action = payload.get('action')
        
        if action in ['opened', 'synchronize', 'reopened']:
            repo_full_name = payload['repository']['full_name']
            pr_number = payload['pull_request']['number']
            head_sha = payload['pull_request']['head']['sha']
            
            app.logger.info(f"🔍 Scanning PR #{pr_number} in {repo_full_name}")
            
            # Scan the PR
            issues = scan_pr_files(repo_full_name, pr_number)
            
            app.logger.info(f"Found {len(issues)} issues")
            
            # Create check run
            create_check_run(repo_full_name, head_sha, issues)
            
            # Post comment
            post_pr_comment(repo_full_name, pr_number, issues)
            
            # Create fix PR if critical issues found
            critical_issues = [i for i in issues if i.get('fix')]
            if critical_issues:
                fix_pr_url = create_fix_pr(repo_full_name, pr_number, critical_issues)
                if fix_pr_url:
                    app.logger.info(f"Created fix PR: {fix_pr_url}")
            
            return jsonify({
                "status": "scanned",
                "issues_found": len(issues),
                "pr": pr_number
            })
    
    # Handle check_suite events (for re-runs)
    elif event == 'check_suite':
        if payload.get('action') == 'rerequested':
            repo_full_name = payload['repository']['full_name']
            # Find associated PRs and rescan
            app.logger.info(f"Check suite re-requested for {repo_full_name}")
    
    return jsonify({"status": "ok"})

@app.route('/scan', methods=['POST'])
def manual_scan():
    """Manual scan endpoint."""
    data = request.json
    
    repo = data.get('repo')
    pr_number = data.get('pr_number')
    
    if not repo or not pr_number:
        return jsonify({"error": "Missing repo or pr_number"}), 400
    
    issues = scan_pr_files(repo, pr_number)
    
    return jsonify({
        "repo": repo,
        "pr_number": pr_number,
        "issues_found": len(issues),
        "issues": issues
    })

# ============================================================
# 🚀 MAIN
# ============================================================
if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════╗
║     🛡️  AutoPatch-Bot v2.0: GitHub PR Security Scanner       ║
╠══════════════════════════════════════════════════════════════╣
║  Endpoints:                                                  ║
║    POST /webhook     - GitHub webhook receiver               ║
║    POST /scan        - Manual scan trigger                   ║
║    GET  /health      - Health check                          ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Check configuration
    if not GITHUB_TOKEN:
        print("⚠️  GITHUB_TOKEN not set - GitHub API calls will fail")
    if not GEMINI_API_KEY:
        print("⚠️  GEMINI_API_KEY not set - AI fixes disabled")
    
    print(f"\n🚀 Starting server on http://localhost:5000")
    print("📌 Webhook URL: http://your-server:5000/webhook\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)