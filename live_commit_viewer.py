import subprocess
import time
import os
import sys

# --- Configuration ---
# This script will monitor the Git repository it is located in.
BRANCH = "main"                   # The branch to monitor
CHECK_INTERVAL_SECONDS = 10       # How often to check for new commits

def run_git_command(cmd, repo_path="."):
    """Runs a Git command in the specified repository path and returns the output."""
    try:
        # We must be inside the repository directory to run git commands
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print("Error: 'git' command not found. Please ensure Git is installed and in your PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error executing git command: {' '.join(cmd)}")
        print(f"Stderr: {e.stderr}")
        return None

def check_for_new_commits(repo_path, branch):
    """
    Fetches new commits and returns a formatted string with details of new commits.
    This includes the diff (patch) showing the exact file and line changes.
    """
    print(f"Checking for new commits on branch '{branch}'...")
    
    # 1. Fetch latest changes from the remote repository
    run_git_command(["git", "fetch"], repo_path=repo_path)
    
    # 2. Get the log of new commits that are on the remote branch but not yet in our local HEAD
    # The format string provides all the requested details.
    # The -p flag provides the patch (the diff of changes).
    log_format = (
        f"\n--- \n"
        f"Date:   %ad\n"
        f"Author: %an\n"
        f"Subject: %s\n"
        f"Body:\n%b"
    )
    
    log_command = [
        "git", "log",
        "-p",  # Show the patch (diff) for each commit
        f"--pretty=format:{log_format}",
        "--date=iso",
        f"HEAD..origin/{branch}"
    ]
    
    new_commits_details = run_git_command(log_command, repo_path=repo_path)
    
    return new_commits_details

def main():
    """Main loop to continuously check for commits."""
    repo_path = os.path.dirname(os.path.abspath(__file__))
    print(f"Starting live commit viewer for repository: {repo_path}")
    print(f"Monitoring branch: '{BRANCH}'")
    print(f"Checking every {CHECK_INTERVAL_SECONDS} seconds. Press Ctrl+C to stop.")

    while True:
        try:
            new_commits = check_for_new_commits(repo_path, BRANCH)
            if new_commits and new_commits.strip():
                print("\n\n>>> New Commits Found <<<")
                print(new_commits)
                print(">>> End of New Commits <<<
")
            else:
                print("No new commits found.")
            
            time.sleep(CHECK_INTERVAL_SECONDS)
        except Exception as e:
            print(f"An unexpected error occurred in the main loop: {e}")
            time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nLive commit viewer stopped by user.")
        sys.exit(0)

