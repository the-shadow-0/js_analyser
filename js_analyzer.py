import re
import os

# Display banner
def display_banner():
    banner =    "=============================================="
    banner += "\n           Welcome to JS_analyzer             "
    banner += "\n     A Powerful Tool for Security Research    "
    banner += "\n                   Developed by the_shadow_0  "
    banner += "\n=============================================="
    print(banner)

# Define patterns for various vulnerabilities
patterns = {
    # Sensitive keywords for secrets
    "api_key": re.compile(r'["\']?(key|api_key|token|secret)["\']?\s*[:=]\s*["\']?([\w-]+)["\']?'),
    
    # Potential XSS vulnerabilities
    "unsafe_eval": re.compile(r'\beval\s*\('),
    "unsafe_function": re.compile(r'\bFunction\s*\('),
    "unsafe_setTimeout": re.compile(r'setTimeout\s*\(\s*["\'].*["\']\s*,'),
    "unsafe_setInterval": re.compile(r'setInterval\s*\(\s*["\'].*["\']\s*,'),
    "document_write": re.compile(r'\bdocument\.write\s*\('),
    "innerHTML": re.compile(r'\binnerHTML\b\s*=\s*'),
    "outerHTML": re.compile(r'\bouterHTML\b\s*=\s*'),

    # API Calls and Request Methods
    "xhr": re.compile(r'\b(new XMLHttpRequest|fetch)\b'),

    # Insecure HTTP URLs
    "insecure_http": re.compile(r'http://[^\s]+'),  # Matches URLs starting with http://

    # Local and session storage usage (potentially storing sensitive data)
    "local_storage": re.compile(r'\blocalStorage\b\s*\.\s*setItem\s*\('),
    "session_storage": re.compile(r'\bsessionStorage\b\s*\.\s*setItem\s*\('),

    # Weak random number generation (e.g., Math.random)
    "weak_random": re.compile(r'\bMath\.random\s*\(\s*\)'),

    # JWT token patterns (basic structure of JWT)
    "jwt_token": re.compile(r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),

    # Hardcoded IP addresses
    "hardcoded_ip": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),

    # Weak encryption algorithms
    "weak_encryption": re.compile(r'\b(md5|sha1|base64_encode|base64_decode)\b'),

    # Prototype pollution
    "prototype_pollution": re.compile(r'(\.\s*__proto__\s*=|\.\s*constructor\s*\()'),

    # Open redirect pattern (location assignments with potentially unvalidated inputs)
    "open_redirect": re.compile(r'(window\.location|document\.location)\s*=\s*')
}

def analyze_js_file(filepath, output_file):
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            content = file.read()
    except (IOError, UnicodeDecodeError):
        # Silently skip files that can't be opened or read
        return
    
    issues_found = []

    # Search for patterns indicating vulnerabilities
    for issue_name, pattern in patterns.items():
        matches = pattern.findall(content)
        if matches:
            issues_found.append(f"{issue_name} found: {matches}")

    # Write results to the output file if issues are found
    if issues_found:
        with open(output_file, "a") as f:
            f.write(f"\nPotential vulnerabilities in {filepath}:\n" + "\n".join(issues_found) + "\n")
    else:
        with open(output_file, "a") as f:
            f.write(f"No issues found in {filepath}.\n")

def main():
    display_banner()  # Display banner at the start

    output_file = "results_js.txt"
    # Clear the output file before writing new results
    open(output_file, "w").close()
    
    # Define the directory containing JavaScript files
    directory = "js_files"
    
    print("Starting JavaScript analysis...\n")
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".js"):
                filepath = os.path.join(root, file)
                print(f"Analyzing {filepath}...")
                analyze_js_file(filepath, output_file)

if __name__ == "__main__":
    main()
