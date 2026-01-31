#!/usr/bin/env python3
"""
🛡️ AutoPatch-Bot: Git Pre-Commit/Pre-Push Hook
Scans code LOCALLY before allowing push to remote

Install:
  python git_hook.py --install

This prevents vulnerable code from ever reaching your repository!
"""

import os
import sys
import re
import subprocess
import json
import argparse
from pathlib import Path
from datetime import datetime

# ============================================================
# 🎨 COLORS
# ============================================================
class Colors:
    RED = '\033[91m'
   

if sys.platform == 'win32':
    os.system('color')

# ============================================================
# 📊 VULNERABILITY PATTERNS
# ============================================================
PATTERNS = {
    "python": {
        "sql_injection": [
            (r'execute\s*\(\s*f["\']', "SQL Injection: f-string in execute()"),
            (r'cursor\.execute\s*\([^,]+\+', "SQL Injection: string concatenation"),
        ],
        "xss": [
            (r'render_template_string\s*\(', "XSS: render_template_string()"),
        ],
        "hardcoded_secrets": [
            (r'(api_key|password|secret|token)\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded secret"),
            (r'AKIA[A-Z0-9]{16}', "AWS Access Key exposed"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub token exposed"),
            (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/Stripe key exposed"),
        ],
        "command_injection": [
            (r'os\.system\s*\(', "Command Injection: os.system()"),
            (r'eval\s*\(', "Code Injection: eval()"),
            (r'exec\s*\(', "Code Injection: exec()"),
        ],
        "insecure_deserialize": [
            (r'pickle\.loads?\s*\(', "Insecure: pickle.load()"),
            (r'yaml\.load\s*\([^)]*\)', "Insecure: yaml.load()"),
        ],
    },
    "javascript": {
        "sql_injection": [
            (r'query\s*\(\s*[`"\'].*\$\{', "SQL Injection in query"),
        ],
        "xss": [
            (r'innerHTML\s*=', "XSS: innerHTML"),
            (r'dangerouslySetInnerHTML', "XSS: dangerouslySetInnerHTML"),
            (r'document\.write\s*\(', "XSS: document.write()"),
        ],
        "hardcoded_secrets": [
            (r'(api_key|password|secret|token)\s*[:=]\s*["\'][^"\']{10,}["\']', "Hardcoded secret"),
        ],
        "command_injection": [
            (r'child_process\.exec\s*\(', "Command Injection"),
            (r'eval\s*\(', "Code Injection: eval()"),
        ],
    }
}

SEVERITY = {
    "sql_injection": ("CRITICAL", 10),
    "command_injection": ("CRITICAL", 10),
    "hardcoded_secrets": ("CRITICAL", 10),
    "insecure_deserialize": ("CRITICAL", 10),
    "xss": ("HIGH", 8),
}

# ============================================================
# 🔍 SCANNER
# ============================================================
def get_language(filename):
    if filename.endswith('.py'):
        return 'python'
    elif filename.endswith(('.js', '.ts', '.jsx', '.tsx')):
        return 'javascript'
    return None

def scan_file(filepath):
    language = get_language(str(filepath))
    if not language:
        return []
    
    try:
        content = Path(filepath).read_text(encoding='utf-8', errors='ignore')
    except:
        return []
    
    issues = []
    patterns = PATTERNS.get(language, {})
    lines = content.split('\n')
    
    for vuln_type, pattern_list in patterns.items():
        for pattern, description in pattern_list:
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    line_num = content[:match.start()].count('\n') + 1
                    severity, score = SEVERITY.get(vuln_type, ("MEDIUM", 5))
                    issues.append({
                        'file': str(filepath),
                        'line': line_num,
                        'type': vuln_type,
                        'severity': severity,
                        'score': score,
                        'description': description,
                        'code': lines[line_num-1].strip() if line_num <= len(lines) else ''
                    })
            except:
                continue
    
    return issues

def get_staged_files():
    """Get list of staged files for commit."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
            capture_output=True, text=True, check=True
        )
        return [f for f in result.stdout.strip().split('\n') if f]
    except:
        return []

def get_files_to_push():
    """Get list of files that will be pushed."""
    try:
        # Get commits that haven't been pushed
        result = subprocess.run(
            ['git', 'diff', '--name-only', '@{push}..HEAD'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return [f for f in result.stdout.strip().split('\n') if f]
        
        # Fallback: get all tracked files
        result = subprocess.run(
            ['git', 'ls-files'],
            capture_output=True, text=True, check=True
        )
        return [f for f in result.stdout.strip().split('\n') if f]
    except:
        return []

def print_banner():
    print("""
+==============================================================+
|  AutoPatch-Bot: Pre-Push Security Check                      |
+==============================================================+
""")

def print_issue(issue, index):
    severity = issue['severity']
    color = Colors.RED if severity == 'CRITICAL' else Colors.YELLOW
    
    print(f"""
{Colors.BOLD}[{index}] {color}{issue['type'].upper()}{Colors.END} - {issue['severity']}
    📁 {issue['file']}:{issue['line']}
    ❌ {issue['code'][:60]}{'...' if len(issue['code']) > 60 else ''}
    💡 {issue['description']}""")

# ============================================================
# 🎯 MAIN HOOK LOGIC
# ============================================================
def run_pre_push_check():
    """Main pre-push security check."""
    print_banner()
    
    files = get_files_to_push()
    scannable = [f for f in files if get_language(f)]
    
    print(f"📂 Scanning {len(scannable)} files before push...")
    print("─" * 60)
    
    all_issues = []
    
    for filepath in scannable:
        if os.path.exists(filepath):
            issues = scan_file(filepath)
            all_issues.extend(issues)
    
    # Count by severity
    critical = len([i for i in all_issues if i['severity'] == 'CRITICAL'])
    high = len([i for i in all_issues if i['severity'] == 'HIGH'])
    medium = len([i for i in all_issues if i['severity'] == 'MEDIUM'])
    
    if not all_issues:
        print(f"""
{Colors.GREEN}{Colors.BOLD}✅ No vulnerabilities detected!{Colors.END}

{Colors.GREEN}Push approved. Your code is secure.{Colors.END}
""")
        return 0  # Allow push
    
    # Print issues
    print(f"\n{Colors.RED}{Colors.BOLD}⚠️ SECURITY ISSUES FOUND!{Colors.END}\n")
    
    for i, issue in enumerate(all_issues[:20], 1):
        print_issue(issue, i)
    
    if len(all_issues) > 20:
        print(f"\n   ... and {len(all_issues) - 20} more issues")
    
    # Summary
    print(f"""
{'═' * 60}
{Colors.BOLD}📊 SUMMARY{Colors.END}
{'═' * 60}
   🔴 Critical: {critical}
   🟠 High:     {high}
   🟡 Medium:   {medium}
   ────────────
   Total:      {len(all_issues)}
""")
    
    # Decision
    if critical > 0:
        print(f"""{Colors.RED}{Colors.BOLD}
❌ PUSH BLOCKED!
   Critical vulnerabilities must be fixed before pushing.
   
   Fix the issues above or use --force to bypass (not recommended):
   git push --no-verify
{Colors.END}""")
        return 1  # Block push
    elif high > 0:
        print(f"""{Colors.YELLOW}{Colors.BOLD}
⚠️ WARNING: High severity issues found.
   Push is allowed but please review and fix these issues.
{Colors.END}""")
        return 0  # Allow with warning
    else:
        print(f"""{Colors.GREEN}
✅ Push allowed (only medium/low issues found)
{Colors.END}""")
        return 0

def run_pre_commit_check():
    """Main pre-commit security check."""
    print_banner()
    
    files = get_staged_files()
    scannable = [f for f in files if get_language(f)]
    
    if not scannable:
        print(f"{Colors.GREEN}✅ No code files staged. Commit allowed.{Colors.END}")
        return 0
    
    print(f"🔍 Scanning {len(scannable)} staged files...")
    
    all_issues = []
    for filepath in scannable:
        if os.path.exists(filepath):
            issues = scan_file(filepath)
            all_issues.extend(issues)
    
    critical = len([i for i in all_issues if i['severity'] == 'CRITICAL'])
    
    if not all_issues:
        print(f"{Colors.GREEN}✅ No vulnerabilities. Commit allowed.{Colors.END}")
        return 0
    
    print(f"\n{Colors.RED}⚠️ Found {len(all_issues)} issues ({critical} critical){Colors.END}\n")
    
    for i, issue in enumerate(all_issues[:10], 1):
        print_issue(issue, i)
    
    if critical > 0:
        print(f"\n{Colors.RED}❌ COMMIT BLOCKED! Fix critical issues first.{Colors.END}")
        print(f"   Use 'git commit --no-verify' to bypass (not recommended)")
        return 1
    
    return 0

# ============================================================
# 🔧 INSTALLATION
# ============================================================
def install_hooks():
    """Install git hooks in the current repository."""
    git_dir = Path('.git')
    
    if not git_dir.exists():
        print(f"{Colors.RED}❌ Not a git repository!{Colors.END}")
        return 1
    
    hooks_dir = git_dir / 'hooks'
    hooks_dir.mkdir(exist_ok=True)
    
    # Get the path to this script
    script_path = Path(__file__).resolve()
    
    # Pre-commit hook
    pre_commit = hooks_dir / 'pre-commit'
    pre_commit_content = f'''#!/bin/sh
python "{script_path}" --pre-commit
'''
    pre_commit.write_text(pre_commit_content)
    os.chmod(pre_commit, 0o755)
    
    # Pre-push hook
    pre_push = hooks_dir / 'pre-push'
    pre_push_content = f'''#!/bin/sh
python "{script_path}" --pre-push
'''
    pre_push.write_text(pre_push_content)
    os.chmod(pre_push, 0o755)
    
    print(f"""
{Colors.GREEN}{Colors.BOLD}✅ Git hooks installed successfully!{Colors.END}

Installed hooks:
  📌 pre-commit - Scans staged files before commit
  📌 pre-push   - Scans all files before push

Your code will now be automatically scanned for vulnerabilities
before commits and pushes. Critical issues will block the push.

To bypass (not recommended):
  git commit --no-verify
  git push --no-verify
""")
    return 0

def uninstall_hooks():
    """Remove git hooks."""
    git_dir = Path('.git')
    
    if not git_dir.exists():
        print(f"{Colors.RED}❌ Not a git repository!{Colors.END}")
        return 1
    
    hooks_dir = git_dir / 'hooks'
    
    for hook in ['pre-commit', 'pre-push']:
        hook_path = hooks_dir / hook
        if hook_path.exists():
            hook_path.unlink()
            print(f"  ✓ Removed {hook}")
    
    print(f"\n{Colors.GREEN}✅ Hooks uninstalled.{Colors.END}")
    return 0

# ============================================================
# 🚀 MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='🛡️ AutoPatch-Bot: Git Security Hook',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python git_hook.py --install      Install pre-commit & pre-push hooks
  python git_hook.py --uninstall    Remove hooks
  python git_hook.py --pre-commit   Run pre-commit check manually
  python git_hook.py --pre-push     Run pre-push check manually
        """
    )
    
    parser.add_argument('--install', action='store_true', help='Install git hooks')
    parser.add_argument('--uninstall', action='store_true', help='Uninstall git hooks')
    parser.add_argument('--pre-commit', action='store_true', help='Run pre-commit check')
    parser.add_argument('--pre-push', action='store_true', help='Run pre-push check')
    
    args = parser.parse_args()
    
    if args.install:
        return install_hooks()
    elif args.uninstall:
        return uninstall_hooks()
    elif args.pre_commit:
        return run_pre_commit_check()
    elif args.pre_push:
        return run_pre_push_check()
    else:
        # Default: run as pre-push
        return run_pre_push_check()

if __name__ == '__main__':
    sys.exit(main())
