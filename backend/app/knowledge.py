"""CWE -> OWASP Top 10 (2021) mapping plus plain-language exploit scenarios and fixes.

Used to fill "how it could be exploited" and "recommended fix" when a scanner does not
provide them. Text only: the tool never changes the scanned code.
"""

A01 = "A01:2021 - Broken Access Control"
A02 = "A02:2021 - Cryptographic Failures"
A03 = "A03:2021 - Injection"
A04 = "A04:2021 - Insecure Design"
A05 = "A05:2021 - Security Misconfiguration"
A06 = "A06:2021 - Vulnerable and Outdated Components"
A07 = "A07:2021 - Identification and Authentication Failures"
A08 = "A08:2021 - Software and Data Integrity Failures"
A09 = "A09:2021 - Security Logging and Monitoring Failures"
A10 = "A10:2021 - Server-Side Request Forgery"

# cwe number -> (owasp, exploitation, fix)
KB: dict[int, tuple[str, str, str]] = {
    22: (A01, "An attacker supplies a path such as ../../etc/passwd to read or overwrite files outside the intended directory.",
         "Resolve the final path and verify it stays inside an allow-listed base directory; reject '..' and absolute paths; prefer IDs over user-supplied file names."),
    23: (A01, "Relative path sequences let an attacker escape the intended directory.",
         "Canonicalise paths and enforce a base directory check before any file access."),
    77: (A03, "Attacker-controlled input is interpreted as part of a command, letting them run extra commands.",
         "Avoid building commands from input; pass arguments as a list without a shell and allow-list permitted values."),
    78: (A03, "An attacker injects shell metacharacters (; | && $()) to execute arbitrary OS commands with the application's privileges.",
         "Never pass user input to a shell. Use an API that takes an argument list (no shell=True / exec string), and validate input against an allow-list."),
    79: (A03, "An attacker injects JavaScript that runs in other users' browsers, stealing sessions or performing actions as them.",
         "Contextually encode output, use the framework's auto-escaping, avoid raw HTML sinks (innerHTML, dangerouslySetInnerHTML, |safe), and add a Content-Security-Policy."),
    89: (A03, "An attacker alters the SQL query (e.g. ' OR 1=1 --) to read, modify or delete data, or bypass login.",
         "Use parameterised queries / prepared statements or the ORM's query builder; never concatenate or format input into SQL."),
    90: (A03, "Crafted input changes the LDAP filter to bypass authentication or enumerate the directory.",
         "Escape LDAP special characters or use parameterised LDAP APIs."),
    91: (A03, "Injected XML changes document structure or logic.", "Validate and encode input before inserting it into XML."),
    94: (A03, "Attacker input is evaluated as code, giving remote code execution.",
         "Remove dynamic code evaluation (eval, exec, Function, template compilation of user input); use safe parsers or lookup tables instead."),
    95: (A03, "Input reaches eval-like functions, letting an attacker execute arbitrary code.",
         "Do not eval input. Use JSON parsing or explicit allow-listed operations."),
    113: (A03, "CRLF in input splits HTTP headers, enabling response splitting or cache poisoning.",
          "Strip or reject CR/LF characters in values written to headers."),
    117: (A09, "Injected newlines forge log entries and hide attacker activity.", "Encode or strip control characters before logging user input."),
    200: (A01, "Sensitive information is returned to users who should not see it, helping further attacks.",
          "Return only required fields, apply authorisation to every response, and avoid verbose errors."),
    209: (A04, "Stack traces or internal error details reveal internals that help an attacker.",
          "Log details server-side; return generic error messages to clients."),
    250: (A04, "Running with excessive privileges turns any other bug into full system compromise.",
          "Run with the least privilege needed (non-root user, dropped capabilities)."),
    259: (A07, "A hard-coded password can be read from the code and used to log in.", "Load passwords from a secrets manager or environment; rotate the exposed value."),
    269: (A04, "Improper privilege management lets users gain rights they should not have.", "Enforce least privilege and review role assignment logic."),
    276: (A01, "Overly broad default permissions let other users read or modify resources.", "Set restrictive default permissions."),
    284: (A01, "Missing access control lets users reach functions or data they are not authorised for.",
          "Enforce server-side authorisation on every request, deny by default."),
    285: (A01, "Missing authorisation checks let users perform privileged actions.", "Add server-side authorisation checks for every protected operation."),
    287: (A07, "Authentication can be bypassed or forged, letting an attacker act as another user.",
          "Use a well-tested authentication framework; validate every credential and token server-side."),
    295: (A07, "TLS certificate validation is disabled, so a network attacker can intercept or alter traffic (man-in-the-middle).",
          "Keep certificate verification enabled; pin or trust a specific CA bundle if needed."),
    306: (A07, "A critical function has no authentication, so anyone can call it.", "Require authentication for every sensitive endpoint."),
    311: (A02, "Sensitive data is not encrypted and can be read if storage or traffic is accessed.", "Encrypt sensitive data at rest and in transit."),
    312: (A04, "Sensitive data is stored in clear text and exposed if storage is read.", "Encrypt or avoid storing sensitive data; hash passwords with a slow KDF."),
    319: (A02, "Data sent over plain HTTP can be sniffed or modified on the network.", "Use HTTPS/TLS for all traffic and enable HSTS."),
    321: (A07, "A hard-coded cryptographic key lets anyone with the code decrypt or forge data.", "Load keys from a secrets manager; rotate the exposed key."),
    326: (A02, "Weak key sizes can be brute-forced.", "Use modern key sizes (RSA >= 2048, AES-256, etc.)."),
    327: (A02, "A broken or risky algorithm (e.g. DES, RC4, ECB mode) lets attackers decrypt or tamper with data.",
          "Use modern authenticated encryption (AES-GCM, ChaCha20-Poly1305) via a vetted library."),
    328: (A02, "Weak hashes (MD5, SHA-1) allow collisions or fast cracking of hashed values.",
          "Use SHA-256+ for integrity and bcrypt/scrypt/Argon2 for passwords."),
    329: (A02, "Predictable IVs weaken encryption.", "Generate a fresh random IV/nonce for every encryption."),
    330: (A02, "Predictable random values (tokens, IDs, passwords) can be guessed by an attacker.",
          "Use a cryptographically secure generator (secrets, crypto.randomBytes, SecureRandom)."),
    338: (A02, "A non-cryptographic PRNG makes security tokens guessable.", "Use a CSPRNG for anything security-sensitive."),
    345: (A08, "Data authenticity is not verified, allowing forged data to be accepted.", "Verify signatures/MACs before trusting data."),
    347: (A02, "Signatures are not properly verified, so forged tokens are accepted (e.g. JWT with alg=none).",
          "Always verify signatures with an explicit algorithm allow-list."),
    352: (A01, "An attacker's site makes a logged-in user's browser send state-changing requests (CSRF).",
          "Use anti-CSRF tokens or SameSite cookies, and require non-simple requests for state changes."),
    362: (A04, "Race conditions let concurrent requests bypass checks (e.g. double spending).", "Use atomic operations, locks or transactions."),
    377: (A01, "Insecure temporary files can be read or hijacked by other local users.", "Use secure temp-file APIs (mkstemp) with restrictive permissions."),
    400: (A04, "Unbounded resource use lets an attacker exhaust CPU/memory (denial of service).", "Apply limits, timeouts and rate limiting."),
    434: (A04, "An attacker uploads a dangerous file (e.g. a web shell) that is later executed or served.",
          "Validate type and size, store outside the web root with random names, and never execute uploads."),
    470: (A03, "Input selects classes or methods via reflection, letting an attacker invoke unintended code.", "Map input to an allow-list of permitted classes/methods."),
    489: (A05, "Debug features left enabled expose internals or code execution consoles.", "Disable debug mode and debug endpoints in production."),
    502: (A08, "Deserialising untrusted data (pickle, Java/PHP serialization, YAML load) can execute attacker code.",
          "Do not deserialise untrusted data with native serializers; use JSON with schema validation or safe loaders."),
    521: (A07, "Weak password requirements make accounts easy to brute-force.", "Enforce strong password policy and MFA."),
    522: (A04, "Credentials are stored or sent insecurely and can be stolen.", "Hash passwords with a slow KDF and send credentials only over TLS."),
    532: (A09, "Sensitive data written to logs can be read by anyone with log access.", "Mask or omit secrets and personal data from logs."),
    546: (A04, "Suspicious comments indicate unfinished or insecure code.", "Review and resolve the flagged code."),
    548: (A01, "Directory listing exposes files to attackers.", "Disable directory listing."),
    601: (A01, "An attacker crafts a link that redirects users to a malicious site, aiding phishing.",
          "Only redirect to relative paths or an allow-list of domains."),
    611: (A05, "XML external entities let an attacker read local files or make server-side requests (XXE).",
          "Disable DTDs and external entity resolution in the XML parser."),
    614: (A05, "Cookies without the Secure flag can leak over plain HTTP.", "Set Secure on all session cookies."),
    639: (A01, "Changing an ID in the request lets a user access another user's records (IDOR).",
          "Check that the authenticated user owns or may access the referenced object on every request."),
    643: (A03, "Crafted input alters XPath queries to bypass checks or read data.", "Use parameterised XPath or escape input."),
    668: (A01, "A resource is exposed to the wrong sphere (e.g. bound to all interfaces).", "Restrict exposure to the intended audience."),
    676: (A04, "Use of a dangerous function makes memory or logic errors likely.", "Replace with a safe alternative."),
    693: (A05, "A protection mechanism is missing or misconfigured.", "Enable the recommended protection."),
    732: (A01, "Overly permissive permissions let other users or processes read or modify sensitive resources.",
          "Grant the minimum permissions required."),
    798: (A07, "Anyone with access to the code or its history can use the hard-coded credential to access the related system.",
          "Revoke and rotate the credential now, remove it from the code and Git history, and load secrets from a secrets manager or environment variables."),
    862: (A01, "Missing authorisation lets any authenticated (or anonymous) user perform the action.",
          "Add an authorisation check on the server before the action, deny by default."),
    863: (A01, "Incorrect authorisation logic lets users access data or functions beyond their role.",
          "Centralise and test authorisation rules; check ownership and role on every request."),
    915: (A08, "Mass assignment lets an attacker set fields such as isAdmin or owner_id.",
          "Bind only allow-listed fields from requests."),
    916: (A02, "Passwords hashed with a fast algorithm can be cracked quickly.", "Use bcrypt, scrypt or Argon2 with a per-user salt."),
    918: (A10, "The server can be made to request internal URLs (cloud metadata, internal services).",
          "Allow-list destination hosts, block internal IP ranges and disable redirects."),
    942: (A05, "A permissive CORS policy lets malicious sites read authenticated responses.", "Allow only trusted origins; never reflect arbitrary Origin with credentials."),
    943: (A03, "Injected operators change NoSQL queries to bypass authentication or read data.", "Validate input types and use query builders that do not accept operator objects from users."),
    1004: (A05, "Cookies without HttpOnly can be stolen by injected JavaScript.", "Set HttpOnly on session cookies."),
    1021: (A04, "The page can be framed by another site (clickjacking).", "Send X-Frame-Options or CSP frame-ancestors."),
    1104: (A06, "Unmaintained components keep receiving no security fixes.", "Replace or upgrade unmaintained components."),
    1236: (A03, "Spreadsheet formula injection runs when exported data is opened.", "Prefix cells beginning with = + - @ with a quote when exporting."),
    1321: (A08, "Prototype pollution lets an attacker inject properties into all objects, altering logic or leading to RCE.",
           "Block __proto__/constructor keys when merging objects, use Map or Object.create(null)."),
    1333: (A04, "A crafted string makes the regular expression backtrack catastrophically (ReDoS).", "Rewrite the regex without nested quantifiers or use a linear-time engine."),
    1336: (A03, "User input in a server-side template is evaluated, allowing code execution (SSTI).", "Never compile templates from user input; pass input as data."),
}

# Defaults by check when the CWE is unknown.
CHECK_DEFAULTS = {
    "code": ("A04:2021 - Insecure Design",
             "Depending on reachability, an attacker may abuse this weakness to compromise confidentiality, integrity or availability.",
             "Review the flagged code and apply the secure coding practice described in the rule."),
    "deps": (A06,
             "If the vulnerable code path is reachable, an attacker can exploit the publicly known vulnerability in this component.",
             "Upgrade the component to a fixed version."),
    "secrets": (A07, KB[798][1], KB[798][2]),
    "iac": (A05,
            "The insecure configuration weakens the deployed environment and can be abused once the infrastructure is built from it.",
            "Apply the configuration change described in the resolution."),
    "web": (A05,
            "The live site's configuration exposes information or weakens browser protections an attacker can rely on.",
            "Change the web server or application configuration as described."),
    "nuclei": (A05,
               "The running service matches a known vulnerability or misconfiguration pattern that attackers scan for automatically.",
               "Apply the vendor fix or configuration change referenced in the finding, then re-scan."),
}


def cwe_number(cwe: str | None) -> int | None:
    if not cwe:
        return None
    import re

    m = re.search(r"CWE-(\d+)", str(cwe), re.I)
    return int(m.group(1)) if m else None


def lookup(cwe: str | None, check: str) -> tuple[str, str, str]:
    n = cwe_number(cwe)
    if n is not None and n in KB:
        return KB[n]
    return CHECK_DEFAULTS.get(check, CHECK_DEFAULTS["code"])
