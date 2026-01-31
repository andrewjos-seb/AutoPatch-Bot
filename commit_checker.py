//erger
import subprocess
import time
import os

REPO_DIR = "AutoPatch-Bot-clone"  # Directory of the repository to monitor
BRANCH = "main"                   # Branch to monitor
CHECK_INTERVAL_SECONDS = 10       # How often to check for new commits

def check_for_new_commits(repo_path, branch):
    """
    Fetches new commits and returns details of commits on the remote
    that are not yet in the local HEAD, including diff and stats.
    """
    try:
        # Store original working directory
       
        
        # Change to the repository directory
        # Ensure repo_path is absolute or relative to the script's execution directory
        abs_repo_path = os.path.abspath(repo_path)
        if not os.path.isdir(abs_repo_path):
            print(f"Error: Repository directory not found at {abs_repo_path}")
            return None
        os.chdir(abs_repo_path)

        # Fetch latest changes from the remote
        subprocess.run(["git", "fetch"], capture_output=True, text=True, check=True)

        # Get new commits (full details with diff and stats)
        # HEAD..origin/main will show commits in origin/main that are not in HEAD
        cmd = ["git", "log", f"origin/{branch}", "-p", "--stat", f"HEAD..origin/{branch}"]
        result = subprocess.run(cmd, capture_output=True, text=True)

        # Switch back to original directory
        os.chdir(original_cwd)

       
    except subprocess.CalledProcessError as e:
        print(f"Error executing git command in {repo_path}: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        # Switch back to original directory in case of error during chdir
        os.chdir(original_cwd)
        return None
    except FileNotFoundError:
        print(f"Error: Git command not found. Please ensure Git is installed and in your PATH.")
        # Switch back to original directory in case of error during chdir
        os.chdir(original_cwd)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Switch back to original directory in case of error during chdir
        os.chdir(original_cwd)
        return None

def main():
    print(f"Starting live commit checker for '{REPO_DIR}/{BRANCH}'...")
    print(f"Checking every {CHECK_INTERVAL_SECONDS} seconds. Press Ctrl+C to stop.")

    while True:
        new_commits_details = check_for_new_commits(REPO_DIR, BRANCH)
        if new_commits_details:
            print(f"\n--- New commits found on {REPO_DIR}/{BRANCH} ---")
            print(new_commits_details)
            print(f"--- End of new commits ---\n")
        else:
            print("No new commits.")

        time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCommit checker stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
