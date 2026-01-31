import subprocess
import argparse
import sys
import os
import time

# --- Configuration ---
BRANCH_TO_MONITOR = "main"
CHECK_INTERVAL_SECONDS = 10

def run_git_command(cmd, repo_path="."):
    """Runs a Git command and returns its output."""
    try:
        return subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        ).stdout
    except FileNotFoundError:
        print("Error: 'git' command not found. Please ensure Git is installed and in your PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        # This can happen if the file doesn't exist, which is a valid case on first run
        # We'll return None and let the calling function handle it.
        return None

def main():
    """Main loop to continuously monitor a file for changes."""
    parser = argparse.ArgumentParser(
        description="Live monitor for a specific file on a Git branch. Fetches and displays updates as they happen."
    )
    parser.add_argument(
        "filename",
        help="The path of the file to monitor within the repository."
    )
    args = parser.parse_args()
    
    file_to_monitor = args.filename
    repo_path = "."  # Assumes the script is run from the root of the repository

    print(f"--- Starting Live Monitor ---")
    print(f"Repository: {os.path.abspath(repo_path)}")
    print(f"File to watch: {file_to_monitor}")
    print(f"Branch: {BRANCH_TO_MONITOR}")
    print(f"Checking for updates every {CHECK_INTERVAL_SECONDS} seconds...")
    print(f"Press Ctrl+C to stop.\n")

    try:
        while True:
            print(f"[{time.strftime('%H:%M:%S')}] Checking for updates...")
            
            # 1. Fetch the latest from the remote
            run_git_command(["git", "fetch"], repo_path=repo_path)
            
            # 2. Check for new commits that affect the specified file
            log_format = (
                f"%n---%n"
                f"Commit: %H%n"
                f"Author: %an%n"
                f"Date:   %ad%n"
                f"Subject: %s%n"
            )
            log_command = [
                "git", "log",
                f"HEAD..origin/{BRANCH_TO_MONITOR}",
                "-p",  # Show the patch to see the changes
                f"--pretty=format:{log_format}",
                "--date=iso",
                "--", file_to_monitor  # The '--' ensures the next argument is a file path
            ]
            
            new_commits_log = run_git_command(log_command, repo_path=repo_path)

            if new_commits_log and new_commits_log.strip():
                print(f"\n\n>>> New Commits Found for {file_to_monitor} <<<")
                print(new_commits_log)
                
                # 3. After showing the commits, show the new full version of the file
                print(f"\n--- Updated Code for {file_to_monitor} ---")
                show_command = ["git", "show", f"origin/{BRANCH_TO_MONITOR}:{file_to_monitor}"]
                full_code = run_git_command(show_command, repo_path=repo_path)
                
                if full_code:
                    print(full_code)
                else:
                    print(f"Could not retrieve the new full content of {file_to_monitor}.")
                
                print(f"--- End of Update ---\n")
                
                # IMPORTANT: We must now update our local HEAD to match the remote,
                # so we don't report the same commit again in the next loop.
                print(f"Fast-forwarding local branch to match remote...")
                run_git_command(["git", "merge", "--ff-only", f"origin/{BRANCH_TO_MONITOR}"], repo_path=repo_path)

            else:
                print("No new commits for this file.")

            time.sleep(CHECK_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n\nLive monitor stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
