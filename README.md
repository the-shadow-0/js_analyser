# js_analyser
JavaScript Vulnerability Analyzer

This script analyzes JavaScript files for potential security vulnerabilities, searching for hardcoded secrets, weak encryption algorithms, prototype pollution risks, unsafe DOM manipulations, and other common issues that may lead to security flaws in web applications.
Key Features

    Sensitive Data Detection: Finds hardcoded API keys, tokens, JWTs, and other sensitive information.
    HTTP URL Checks: Identifies insecure http:// URLs, which should typically be https://.
    DOM Manipulation Risks: Flags risky DOM manipulations (innerHTML, outerHTML, document.write, etc.) that could lead to XSS vulnerabilities.
    Prototype Pollution: Detects patterns that could lead to prototype pollution.
    Weak Random Number Generation: Flags weak RNG usage, such as Math.random() for security purposes.
    Weak Encryption Algorithms: Alerts for insecure hashing algorithms like md5, sha1, or improper use of Base64 for sensitive data.
    Other Vulnerabilities: Identifies open redirects, hardcoded IPs, unsafe usage of setTimeout and setInterval functions, and more.

Requirements

    Python 3.x

Setup

    Clone or Download the Script: Download the script and place it in your working directory.
    Prepare Your JavaScript Files: Place all JavaScript files you want to analyze in a folder named js_files in the same directory as the script.

Usage :

    Run the script from your terminal:

    python3 js_analyzer.py

    The script will output results to a file called results_js.txt in the same directory.

    Each JavaScript file analyzed will show any detected vulnerabilities, or it will note if no issues were found.

Example Output :

The results file (results_js.txt) will contain entries like the following:

    Potential vulnerabilities in js_files/api.js:
    api_key found: [('api_key', 'abc123xyz')]
    jwt_token found: ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9']
    insecure_http found: ['http://example.com']
    prototype_pollution found: ['.__proto__=']

No issues found in js_files/utility.js.

Each entry includes:

    The file analyzed
    A description of the potential vulnerability
    The specific matches or code fragments where possible vulnerabilities were found

Pattern Descriptions

    API Keys and Tokens: Hardcoded keys and tokens.
    JWT Tokens: Exposed JSON Web Tokens in code.
    Insecure URLs: HTTP URLs that may indicate insecure endpoints.
    Weak Random Generators: Use of Math.random() instead of secure RNG.
    Unsafe DOM Manipulations: Methods like innerHTML or document.write can lead to XSS.
    Prototype Pollution: JavaScript objects modified unsafely.
    Weak Encryption: Alerts for insecure algorithms like MD5 and SHA1.

Modifying the Script

If you wish to add more patterns or customize existing ones:

    Open the script js_analyzer.py.
    Add new regular expressions to the patterns dictionary as needed.

Disclaimer

This script is a basic static analysis tool and does not guarantee the identification of all vulnerabilities. Always conduct a thorough, manual review and testing in a controlled environment.
