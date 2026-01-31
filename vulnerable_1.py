
import os
import sqlite3
import yaml  # Insecure Dependency Usage: Using an old, vulnerable version of PyYAML
import time
from flask import Flask, request, render_template_string

# --- Vulnerability 1: Hardcoded Secrets / Credentials ---
# Never hardcode secrets. Use environment variables or a secret management system.
API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Hardcoded secret
DATABASE_PASSWORD = "supersecretpassword123"    # Hardcoded secret

app = Flask(__name__)

# --- Vulnerability 2: SQL Injection ---
# Use parameterized queries (e.g., with '?' as a placeholder) to prevent SQL injection.
def get_user_by_username(username):
    """
    Retrieves a user from the database by their username.
    This function is vulnerable to SQL injection.
    Example of a malicious username: ' OR 1=1 --
    """
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query) # Vulnerable line
    user = cursor.fetchone()
    conn.close()
    return user

# --- Vulnerability 3: Cross-Site Scripting (XSS) ---
# Always sanitize user input before rendering it in HTML.
@app.route('/search')
def search():
    """
    A search endpoint that is vulnerable to reflected XSS.
    Example of a malicious query: <script>alert('XSS');</script>
    """
    query = request.args.get('query', '')
    return render_template_string(f"<h1>Search Results for: {query}</h1>") # Vulnerable line

# --- Vulnerability 4: Insecure Dependency Usage ---
# PyYAML version 5.3.1 and older are vulnerable to arbitrary code execution.
# To fix, update to the latest version: pip install --upgrade PyYAML
def load_yaml_data(data):
    """
    Loads YAML data using a vulnerable version of PyYAML.
    A malicious YAML can execute arbitrary code.
    """
    return yaml.load(data, Loader=yaml.FullLoader) # Vulnerable line

# --- Vulnerability 5: Race Condition / Concurrency Issue ---
# This function can have a race condition if executed concurrently.
# Use locks or other synchronization primitives to protect shared resources.
balance = 100
def withdraw(amount):
    """
    A simple withdrawal function with a race condition.
    If two threads call this function at the same time, they might both
    read the same balance before either one can update it, leading to
    an incorrect balance.
    """
    global balance
    if balance >= amount:
        time.sleep(0.1)  # Simulate a delay
        balance -= amount
        return True
    return False

# --- Vulnerability 6: Command Injection ---
# Never use os.system with user-provided input.
# Use safer alternatives like the 'subprocess' module with shell=False.
@app.route('/list_files')
def list_files():
    """
    An endpoint that is vulnerable to command injection.
    Example of a malicious directory: .; ls -la
    """
    directory = request.args.get('directory', '.')
    os.system("ls " + directory) # Vulnerable line
    return "Command executed."

# --- Vulnerability 7: Insecure Authentication Handling ---
# This is a very basic and insecure way to handle authentication.
# Always hash and salt passwords. Use a proper authentication library.
def is_authenticated(username, password):
    """
    Insecure authentication check. Passwords should never be stored in plaintext.
    """
    if username == "admin" and password == DATABASE_PASSWORD: # Insecure check
        return True
    return False

# --- Vulnerability 8: Sensitive Data Exposure ---
# Avoid logging or printing sensitive data.
def process_user_data(user_data):
    """
    This function exposes sensitive user data to logs.
    """
    print("Processing user data:", user_data) # Sensitive data exposure
    # ... process data ...
    return "Data processed."

# --- Vulnerability 9: Blocking Operations / Performance Bottleneck ---
# This function performs a blocking operation that can slow down the entire application.
# Use asynchronous requests or a background task queue.
def get_external_data():
    """
    A function with a blocking operation.
    """
    time.sleep(5)  # Simulates a long-running network request
    return "Data from external service."

# --- Vulnerability 10: Inefficient Algorithm (High Time Complexity) ---
# This function uses an inefficient algorithm (O(n^2)) to find a pair of numbers.
# For large lists, this can be very slow.
def find_pair_with_sum(numbers, target):
    """
    Finds a pair of numbers in a list that sum to a target value.
    This implementation has a time complexity of O(n^2).
    A more efficient approach would be to use a hash map (O(n)).
    """
    for i in range(len(numbers)):
        for j in range(len(numbers)):
            if i != j and numbers[i] + numbers[j] == target:
                return (numbers[i], numbers[j])
    return None

if __name__ == '__main__':
    # Example of using some of the vulnerable functions
    print("--- Example of Vulnerabilities ---")

    # SQL Injection Example
    # malicious_username = "' OR 1=1 --"
    # print(f"Attempting to log in as: {malicious_username}")
    # print("User found:", get_user_by_username(malicious_username))

    # Insecure Dependency Usage Example
    malicious_yaml = "!!python/object/apply:os.system ['echo Vulnerable YAML']"
    load_yaml_data(malicious_yaml)

    # Insecure Authentication Example
    print("Admin authenticated:", is_authenticated("admin", "supersecretpassword123"))

    # Sensitive Data Exposure Example
    user_info = {"username": "testuser", "password": "password123", "credit_card": "1234-5678-9012-3456"}
    process_user_data(user_info)

    # Inefficient Algorithm Example
    large_list = list(range(1000))
    print("Finding pair in a large list:", find_pair_with_sum(large_list, 1997))

    # Running the Flask app (for XSS and Command Injection)
    # To test, run this script and visit:
    # http://127.0.0.1:5000/search?query=<script>alert('XSS')</script>
    # http://127.0.0.1:5000/list_files?directory=.;%20echo%20'Command%20Injection'
    app.run(debug=True)

# This is a new comment added to create a change.
# Adding another comment to break the loop.
