import subprocess
import argparse
import sys
import os

def get_file_content_from_github(repo_path, branch, file_path):
    """
    Fetches and returns the content of a specific file from a remote Git branch.
    """
    print(f"Fetching content of '{file_path}' from branch '{branch}'...")

    try:
        # 1. Fetch latest updates from the remote to ensure we have the latest objects
        fetch_command = ["git", "fetch"]
        subprocess.run(
            fetch_command,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )

        # 2. Use 'git show' to get the content of the file from the specific remote branch
        # The syntax 'origin/main:path/to/file' fetches the file from that specific tree
        show_command = ["git", "show", f"origin/{branch}:{file_path}"]
        result = subprocess.run(
            show_command,
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
        print(f"\n--- ERROR ---")
        if "exists on disk" in e.stderr or "does not exist" in e.stderr:
            print(f"File '{file_path}' not found in the '{branch}' branch on the remote repository.")
        else:
            print(f"An error occurred while trying to fetch the file.")
            print(f"Error details: {e.stderr}")
        print("---------------\\n")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def main():
    """
    Main function to parse arguments and display the file content.
    """
    # The script should be run from within the cloned repository directory.
    repo_path = "." 

    parser = argparse.ArgumentParser(
        description="Fetch and display the content of a file from the 'main' branch of this Git repository."
    )
    parser.add_argument(
        "filename",
        help="The name of the file you want to display from the 'main' branch."
    )
    
    args = parser.parse_args()
    
    file_content = get_file_content_from_github(repo_path, "main", args.filename)
    
    if file_content is not None:
        print(f"\n--- File: {args.filename} ---")
        print(file_content)
        print(f"--- End of File: {args.filename} ---")

if __name__ == "__main__":
    main()
