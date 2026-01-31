import os
import json
import logging
from flask import Flask, request
from github import Github
import google.generativeai as genai

# --- 🔑 CONFIGURATION ---
# PASTE YOUR KEYS HERE
GITHUB_TOKEN = "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" 
GEMINI_KEY = "AIzaSyDMb_7hRT51XMcJYmZNSN9Abtd0zV9j95Q"

# --- SETUP ---
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
# Silence werkzeug logs to focus on application logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


# Login to GitHub
gh = Github(GITHUB_TOKEN)
# Login to Gemini
genai.configure(api_key=GEMINI_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

def scan_code(filename, patch_content):
    """Sends the code to Gemini to find bugs."""
    prompt = f"""
    You are a Security Bot. Review this code diff from {filename}.
    Check for: SQL Injection, XSS, Hardcoded Secrets.
    
    If you find a bug, return a JSON object exactly like this:
    {{
        "found": true,
        "bug_type": "SQL Injection (or other)",
        "explanation": "Briefly explain why this is dangerous.",
        "fixed_code": "Write the FIXED code snippet only"
    }}

    If clean, return: {{ "found": false }}

    CODE DIFF:
    {patch_content}
    """
    try:
        response = model.generate_content(prompt)
        text = response.text.replace("```json", "").replace("```", "").strip()
        return json.loads(text)
    except Exception as e:
        app.logger.error(f"   ❌ AI Error: {e}")
        return {"found": False}

@app.route('/webhook', methods=['POST'])
def webhook():
    payload = request.json
    
    # 1. Check if the event is a Pull Request
    if payload.get('action') in ['opened', 'synchronize']:
        repo_full_name = payload['repository']['full_name']
        pr_number = payload['number']

        # 🎯 TARGET CHECK: Only act if it's your test repo
        # if repo_full_name == "adithya-retheep/vulnerable-app-test":
        app.logger.info(f"\n🚀 INCIDENT DETECTED in: {repo_full_name} (PR #{pr_number})")
        
        # 2. Get the actual code files from GitHub
        repo = gh.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        
        files = pr.get_files()
        for file in files:
            # Only scan Python/JS files
            if file.filename.endswith(('.py', '.js', '.ts')):
                app.logger.info(f"   🔍 Scanning file: {file.filename}...")
                
                # 3. Send to Gemini
                result = scan_code(file.filename, file.patch)
                
                # 4. Post the Fix if bug found
                if result.get('found'):
                    app.logger.warning(f"   ⚠️ FOUND VULNERABILITY: {result['bug_type']}")
                    
                    msg = (
                        f"### 🛡️ Security Alert: {result['bug_type']}\n"
                        f"{result['explanation']}\n\n"
                        f"**Suggested Fix:**\n"
                        f"```suggestion\n{result['fixed_code']}\n```"
                    )
                    
                    # Post the comment
                    pr.create_issue_comment(f"**File: {file.filename}**\n{msg}")
                    app.logger.info("   ✅ Fix sent to GitHub!")
                else:
                    app.logger.info("   ✅ Code looks clean.")
        # else:
        #     app.logger.info(f"Ignoring event from {repo_full_name}")

    return "OK", 200

if __name__ == '__main__':
    app.run(port=5000)