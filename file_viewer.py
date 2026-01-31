import subprocess
import argparse
import sys
import os

def run_git_command(cmd, repo_path="."):
    """Runs a Git command in the specified repository path and returns the output."""
    try:
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
        # Don't print an error here for ls-tree, as it might just mean no files found
        if cmd[1] != 'ls-tree':
            print(f"Error executing git command: {' '.join(cmd)}")
            print(f"Stderr: {e.stderr}")
        return None

def find_file_in_repo(repo_path, branch, partial_filename):
    """Searches for a file in the repository and returns its full path."""
    print(f"Searching for a file matching '{partial_filename}' in branch '{branch}'...")
    
    # 1. Fetch latest updates from the remote
    run_git_command(["git", "fetch"], repo_path=repo_path)
    
    # 2. Get a list of all files in the remote branch
    ls_tree_command = ["git", "ls-tree", "-r", f"origin/{branch}", "--name-only"]
    all_files_output = run_git_command(ls_tree_command, repo_path=repo_path)
    
    if not all_files_output:
        print("Could not retrieve file list from the repository.")
        return None
        
    all_files = all_files_output.strip().split('\n')
    
    # 3. Find matching files
    matches = [f for f in all_files if partial_filename in f]
    
    if not matches:
        print(f"No file found matching '{partial_filename}'.")
        return None
    
    if len(matches) > 1:
        print(f"Found multiple matches for '{partial_filename}':")
        for match in matches:
            print(f" - {match}")
        print("Please be more specific or use the full file path.")
        return None
        
    return matches[0]

def get_file_content_from_github(repo_path, branch, file_path):
    """Fetches and returns the content of a specific file from a remote Git branch."""
    print(f"Fetching content of '{file_path}' from branch '{branch}'...")
    
    show_command = ["git", "show", f"origin/{branch}:{file_path}"]
    content = run_git_command(show_command, repo_path=repo_path)
    
    if content is None:
        print(f"\n--- ERROR ---")
        print(f"Could not fetch content for file '{file_path}'. It may not exist in the remote branch.")
        print("---------------\n")
    
    return content

def main():
    """Main function to parse arguments and display the file content."""
    repo_path = "." 

    parser = argparse.ArgumentParser(
        description="Search for a file in the 'main' branch of this repository and display its content."
    )
    parser.add_argument(
        "filename",
        help="The full or partial name of the file you want to search for and display."
    )
    
    args = parser.parse_args()
    
    full_file_path = find_file_in_repo(repo_path, "main", args.filename)
    
    if full_file_path:
        file_content = get_file_content_from_github(repo_path, "main", full_file_path)
        if file_content is not None:
            print(f"\n--- File: {full_file_path} ---")
            print(file_content)
            print(f"--- End of File: {full_file_path} ---")

if __name__ == "__main__":
    main()