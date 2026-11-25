"""Built-in checks the external scanners miss: hardcoded passwords in Spring Boot config files
(low-entropy values that entropy-based secret scanners skip), risky Spring Boot settings and
Spring Security code patterns.

Read-only and offline: files are read as text, nothing is executed, nothing is changed.
Raw secret values are returned only so the caller can mask them; findings carry a fingerprint.
"""
from __future__ import annotations

import os
import re

from .grouping import secret_features
from .normalize import make_finding, read_snippet
from .secret_display import display

MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 3000
SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", "out", ".gradle", ".idea", ".mvn", "vendor",
             "__pycache__", ".venv", "venv"}
_CONFIG_FILE = re.compile(r"^(application|bootstrap)([-.][\w.-]+)?\.(ya?ml|properties)$", re.I)
_TEST_PATH = re.compile(r"(^|/)(src/test|test|tests|__tests__)/", re.I)


def _walk(root: str, want):
    count = 0
    base = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".vapt-ignored")]
        for name in filenames:
            if not want(name):
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
                with open(full, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield os.path.relpath(full, base).replace(os.sep, "/"), text


# ---------------------------------------------------------------- config parsing


def _unquote(val: str) -> str:
    val = val.strip()
    if val[:1] in "\"'":
        q = val[0]
        end = val.find(q, 1)
        return val[1:end] if end > 0 else val[1:]
    return re.split(r"\s+#", val, 1)[0].strip()


def yaml_entries(text: str):
    """(line, dotted.key.path, scalar value) for simple `key: value` lines, tracking nesting by
    indentation. Lists, block scalars and flow mappings are skipped. Enough for Spring config."""
    stack: list[tuple[int, str]] = []
    block_indent = None
    for no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None:
            if not stripped or indent > block_indent:
                continue
            block_indent = None
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("---"):
            stack = []
            continue
        if stripped.startswith(("- ", "[", "{")) or stripped == "-":
            continue
        m = re.match(r"""^(["']?)([^"'#\s][^:#]*?)\1\s*:(?:\s+(.*))?$""", stripped)
        if not m:
            continue
        key, val = m.group(2).strip(), (m.group(3) or "").strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        head = val[:1]
        if not val or head == "#" or head in ("|", ">", "&", "*", "{", "["):
            if head in ("|", ">"):
                block_indent = indent
            stack.append((indent, key))
            continue
        yield no, ".".join([k for _, k in stack] + [key]), _unquote(val)


def properties_entries(text: str):
    cont = False
    for no, line in enumerate(text.splitlines(), 1):
        if cont:
            cont = line.rstrip().endswith("\\")
            continue
        s = line.strip()
        if not s or s[0] in "#!":
            continue
        cont = s.endswith("\\")
        m = re.match(r"^([^=:\s]+)\s*[=:]\s*(.*)$", s)
        if m:
            yield no, m.group(1), m.group(2).strip()


def config_entries(rel: str, text: str):
    return properties_entries(text) if rel.lower().endswith(".properties") else yaml_entries(text)


def norm_key(key: str) -> str:
    """Spring relaxed binding: case, '-' and '_' do not matter."""
    return re.sub(r"[-_]", "", key.lower())


# ---------------------------------------------------------------- hardcoded passwords in config

# Matched against the last key segment with '-' and '_' removed (Spring relaxed binding).
_SECRET_KEY = re.compile(r"(passwords?|passwds?|pwds?|secrets?|credentials?|apikeys?|accesskeys?|privatekeys?|token|"
                         r"passphrases?|authkeys?|signingkeys?)$|^(password|secret)", re.I)
_NOT_SECRET_KEY = re.compile(r"(url|uri|endpoint|expir\w*|validity|ttl|length|size|header|name|type|path|file|"
                             r"location|enabled|encoder|algorithm|policy|prefix|suffix|timeout|duration|time|"
                             r"seconds|regex|pattern|format|mode|count|attempts|strength|issuer|audience|required|"
                             r"param|parameter|field|column|property|ref|id|cron|interval|days|hours|minutes)$",
                             re.I)
_NOT_A_VALUE = re.compile(r"^(x+|\*+|\.+|-+|null|none|nil|~|true|false|yes|no|n/?a|tbd|todo|changeme_?later|"
                          r"placeholder|your[-_ ].*|<.*>|\[.*\]|example.*|dummy|sample|\d{1,6})$", re.I)
_REFERENCE = re.compile(r"^(classpath|file|https?|jdbc|redis|mongodb|ldap|vault|aws-secretsmanager|sm)[:@]", re.I)
_PLACEHOLDER = re.compile(r"^\$\{([^}:]+)(?::([^}]*))?\}$")
_HASH = re.compile(r"^\$(2[abxy]?|argon2(id|i|d)?|pbkdf2[-\w]*|scrypt)\$")  # hashes are reported by Semgrep
_ENCRYPTED = re.compile(r"^(ENC\(.*\)|\{cipher\}.*|\{bcrypt\}.*|\{noop\}\$\{.*)$", re.I)


def config_secret_value(key: str, value: str) -> tuple[str, bool] | None:
    """(literal value, is_default_fallback) when a secret-named key holds a literal, else None."""
    last = re.sub(r"[-_]", "", key.rsplit(".", 1)[-1])
    if not _SECRET_KEY.search(last) or _NOT_SECRET_KEY.search(last):
        return None
    value = (value or "").strip()
    fallback = False
    m = _PLACEHOLDER.match(value)
    if m:
        if not m.group(2):
            return None
        value, fallback = m.group(2).strip(), True
    if not value or "${" in value or len(value) < 4 or len(value.split()) > 2:
        return None
    if _NOT_A_VALUE.match(value) or _REFERENCE.match(value) or _ENCRYPTED.match(value) or _HASH.match(value):
        return None
    return value, fallback


def scan_config_secrets(root: str) -> tuple[list[dict], dict[str, str]]:
    findings, secrets = [], {}
    for rel, text in _walk(root, lambda n: bool(_CONFIG_FILE.match(n))):
        for line, key, value in config_entries(rel, text):
            hit = config_secret_value(key, value)
            if not hit:
                continue
            raw, fallback = hit
            secrets.setdefault(raw, display(raw, rule_id="password", name=key))
            # a list of credentials ('pw1,pw2'): each item is masked wherever it appears on its own
            for item in re.split(r"\s*[,;|]\s*", raw):
                if len(item) >= 4 and item != raw:
                    secrets.setdefault(item, display(item, rule_id="password", name=key))
            test = bool(_TEST_PATH.search("/" + rel))
            how = (f"as the default fallback in `${{...:default}}` for `{key}`" if fallback
                   else f"as the value of `{key}`")
            findings.append(make_finding(
                severity="Low" if test else "High",
                title=f"Hardcoded password in config: {key}",
                file_path=rel, line=line, snippet=read_snippet(root, rel, line),
                description=(f"A literal credential is set {how} in {rel}. Spring config files are "
                             "committed and shipped with the application, so everyone with access to the "
                             "code or the built artifact has this credential."
                             + (" This is test configuration, so it is rated Low; make sure the value is not "
                                "also used by a real environment." if test else "")),
                check="secrets", scanner="vapt", rule_id="vapt-config-password", cwe="CWE-798",
                exploitation=("Anyone who can read this repository or unpack the built JAR can read the value and "
                              f"use it wherever `{key}` is accepted (database, keystore, mail or API login)."),
                recommendation=(f"Remove the literal and read `{key}` from an environment variable or a secret "
                                "store, e.g. `" + key.rsplit(".", 1)[-1] + ": ${" + re.sub(r"\W", "_", key).upper()
                                + "}` with no default. Then change the credential: it must be treated as leaked."),
            ) | secret_features(raw, key) | {"_secret_fallback": fallback, "_secret_config_key": key})
    return findings, secrets


# ---------------------------------------------------------------- risky Spring Boot settings

# (id, normalised key, value test, severity, title, cwe, what, exploit, fix)
SPRING_SETTINGS = [
    ("actuator-exposed", "management.endpoints.web.exposure.include",
     lambda v: "*" in v or re.search(r"\b(heapdump|env|configprops|threaddump|jolokia|logfile|shutdown)\b", v),
     "High", "Sensitive Spring Boot Actuator endpoints exposed over HTTP", "CWE-215",
     "Actuator endpoints such as /actuator/heapdump, /actuator/env and /actuator/configprops are exposed "
     "over HTTP by this setting.",
     "/actuator/heapdump downloads the JVM memory, which contains passwords, tokens and session data in "
     "clear text; /actuator/env and /actuator/configprops reveal configuration. If these paths are reachable "
     "without authentication, an attacker can take credentials from them directly.",
     "Expose only what monitoring needs: `management.endpoints.web.exposure.include: health,info`. Put "
     "any other endpoint behind Spring Security with an admin role, or on a separate management port "
     "(`management.server.port`) that is not reachable from the internet."),
    ("actuator-security-off", "management.security.enabled", lambda v: v.lower() == "false",
     "High", "Spring Boot Actuator security disabled", "CWE-306",
     "management.security.enabled=false (Spring Boot 1.x) turns off authentication for all Actuator endpoints.",
     "Every Actuator endpoint, including environment, heap dump and shutdown where enabled, is open to anyone "
     "who can reach the application.",
     "Remove the setting (Boot 1.x defaults to secured) and upgrade to a supported Spring Boot version."),
    ("h2-console", "spring.h2.console.enabled", lambda v: v.lower() == "true",
     "High", "H2 database web console enabled", "CWE-489",
     "The H2 web console is enabled. It is a development tool that accepts arbitrary SQL and JDBC URLs.",
     "If reachable, an attacker can run SQL against the database and, through crafted JDBC URLs, execute code "
     "on the server.",
     "Set `spring.h2.console.enabled: false` in every profile that can be deployed; enable it only in a local "
     "development profile."),
    ("env-show-values", "management.endpoint.env.show-values", lambda v: v.lower() == "always",
     "Medium", "Actuator shows unmasked configuration values", "CWE-215",
     "/actuator/env returns configuration values without masking.",
     "Anyone who can call the endpoint sees passwords and keys from the configuration.",
     "Use `show-values: never` (the default) or `when-authorized` with an admin role."),
    ("configprops-show-values", "management.endpoint.configprops.show-values", lambda v: v.lower() == "always",
     "Medium", "Actuator shows unmasked configuration properties", "CWE-215",
     "/actuator/configprops returns bound properties without masking.",
     "Anyone who can call the endpoint sees passwords and keys from the configuration.",
     "Use `show-values: never` (the default) or `when-authorized` with an admin role."),
    ("health-details", "management.endpoint.health.show-details", lambda v: v.lower() == "always",
     "Low", "Actuator health endpoint shows full details to everyone", "CWE-200",
     "/actuator/health returns component details (database, disk, mail server, versions) to unauthenticated users.",
     "The details tell an attacker which database, cache and mail servers the application uses.",
     "Use `show-details: when-authorized`."),
    ("error-stacktrace", "server.error.include-stacktrace", lambda v: v.lower().replace("_", "-") in ("always", "on-param"),
     "Medium", "Stack traces returned in HTTP error responses", "CWE-209",
     "Error responses include the Java stack trace (always, or when the client adds ?trace=true).",
     "Stack traces reveal class names, library versions and code paths that help an attacker target known flaws.",
     "Set `server.error.include-stacktrace: never` (the default)."),
    ("error-message", "server.error.include-message", lambda v: v.lower() == "always",
     "Low", "Exception messages returned in HTTP error responses", "CWE-209",
     "Error responses include the exception message.",
     "Exception messages can reveal SQL, file paths or internal host names.",
     "Use `server.error.include-message: never` (the default) and return your own error text."),
    ("cookie-not-secure", "server.servlet.session.cookie.secure", lambda v: v.lower() == "false",
     "Medium", "Session cookie sent without the Secure flag", "CWE-614",
     "The session cookie is explicitly allowed over plain HTTP.",
     "On any HTTP request (for example a link or redirect to http://) the session cookie travels unencrypted "
     "and can be captured on the network.",
     "Set `server.servlet.session.cookie.secure: true` and serve the application only over HTTPS."),
    ("cookie-not-httponly", "server.servlet.session.cookie.http-only", lambda v: v.lower() == "false",
     "Medium", "Session cookie readable by JavaScript", "CWE-1004",
     "HttpOnly is disabled for the session cookie.",
     "Any cross-site scripting flaw can then read the session cookie and take over the user's session.",
     "Set `server.servlet.session.cookie.http-only: true` (the default)."),
    ("debug-mode", "debug", lambda v: v.lower() == "true",
     "Low", "Spring Boot debug mode enabled", "CWE-489",
     "`debug: true` turns on debug logging for the core framework.",
     "Debug logs can contain request details, configuration and internal state; they also slow the service.",
     "Remove `debug: true` from deployable profiles."),
    ("db-no-tls", "spring.datasource.url",
     lambda v: re.search(r"[?&;](useSSL=false|sslmode=disable|ssl-mode=DISABLED|sslMode=DISABLED|encrypt=false)", v, re.I),
     "Low", "Database connection without TLS", "CWE-319",
     "The JDBC URL turns TLS off for the database connection.",
     "Credentials and data travel unencrypted between the application and the database; anyone on that network "
     "path can read or change them.",
     "Enable TLS on the database and use `sslMode=REQUIRED` (MySQL) / `sslmode=require` (PostgreSQL), or "
     "`VERIFY_IDENTITY` / `verify-full` to also check the server certificate."),
]
_SETTINGS_BY_KEY = {norm_key(s[1]): s for s in SPRING_SETTINGS}


# ---------------------------------------------------------------- Spring Security code patterns

# (id, regex over the whole file, severity, title, cwe, what, exploit, fix)
JAVA_RULES = [
    ("csrf-disabled",
     re.compile(r"\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)"
                r"|\.csrf\s*\(\s*(?:AbstractHttpConfigurer\s*::\s*disable|(\w+)\s*->\s*\1\s*\.\s*disable\s*\(\s*\))\s*\)"),
     "Medium", "CSRF protection disabled in Spring Security", "CWE-352",
     "Spring Security's CSRF protection is switched off.",
     "If the application authenticates browsers with a session or any cookie, another website can make a "
     "logged-in user's browser send state-changing requests (change password, transfer, delete) without "
     "their knowledge. This is safe only for a stateless API that authenticates every request with a token "
     "in the Authorization header and never with cookies.",
     "If any cookie or session authenticates users, remove `.csrf(...disable())` and use "
     "`CookieCsrfTokenRepository.withHttpOnlyFalse()` for single-page apps. If the API is truly stateless "
     "(token in the Authorization header only), keep it disabled and set "
     "`sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))`."),
    ("permit-all-everything",
     re.compile(r"anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)"
                r"|(?:requestMatchers|antMatchers|mvcMatchers)\s*\(\s*\"/\*\*\"\s*\)\s*\.\s*permitAll\s*\(\s*\)"),
     "High", "Every request allowed without authentication", "CWE-862",
     "The security configuration allows all requests (`anyRequest().permitAll()` or `\"/**\"` permitAll).",
     "Any endpoint that is not explicitly protected elsewhere is reachable without logging in; new endpoints "
     "are public by default.",
     "End the chain with `.anyRequest().authenticated()` and list the public paths explicitly with "
     "`requestMatchers(\"/login\", \"/public/**\").permitAll()`."),
    ("cors-wildcard",
     re.compile(r"(?:allowedOrigins|allowedOriginPatterns|addAllowedOrigin|addAllowedOriginPattern)\s*\(\s*\"\*\"\s*\)"
                r"|setAllowedOrigin(?:Pattern)?s\s*\(\s*(?:List\.of|Arrays\.asList|Collections\.singletonList)\s*\(\s*\"\*\"\s*\)"
                r"|@CrossOrigin\s*\(\s*(?:origins\s*=\s*)?\"\*\"\s*\)"),
     "Low", "CORS allows any origin", "CWE-942",
     "Cross-origin requests are allowed from any website.",
     "Any website can call this API from a visitor's browser and read the responses. Combined with "
     "credentials (cookies) this lets a malicious site read the user's data.",
     "List the exact front-end origins instead of \"*\" (e.g. `allowedOrigins(\"https://app.example.com\")`)."),
]
_CREDENTIALS = re.compile(r"(?:allowCredentials|setAllowCredentials)\s*\(\s*true\s*\)")


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _strip_comments(text: str) -> str:
    """Blank out comments (keeping line numbers) so commented-out code is not reported."""
    text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


_IV_SPEC = re.compile(r"new\s+(?:IvParameterSpec|GCMParameterSpec)\s*\(")
STATIC_IV = ("Medium", "IV for encryption is not random", "CWE-329",
             "The initialization vector (IV) passed to an encrypting cipher does not come from a secure random "
             "generator: it is fixed, empty or derived from a password or key.",
             "With a repeated or predictable IV, the same plaintext always encrypts to the same ciphertext, so an "
             "attacker can see when values repeat and, in CBC mode, learn about or tamper with the first block. "
             "With AES-GCM, reusing an IV with the same key breaks both confidentiality and integrity.",
             "Generate a new IV for every encryption with `SecureRandom.nextBytes(iv)` (12 bytes for AES-GCM, 16 "
             "for CBC) and store it next to the ciphertext; it does not need to be secret. Do not derive it from "
             "the key or passphrase (for example OpenSSL's EVP_BytesToKey) and never use a constant.")


def _call_args(code: str, start: int) -> str:
    """Text between the '(' at code[start-1] and its matching ')'."""
    depth, i = 1, start
    while i < len(code) and depth:
        depth += {"(": 1, ")": -1}.get(code[i], 0)
        i += 1
    return code[start:i - 1]


def static_iv_lines(code: str) -> list[int]:
    """Lines where an IV spec is built for ENCRYPT_MODE from something that is not SecureRandom output."""
    lines = code.splitlines()
    out = []
    for m in _IV_SPEC.finditer(code):
        args = [a.strip() for a in _call_args(code, m.end()).split(",")]
        iv = args[-1] if "GCMParameterSpec" not in m.group(0) else (args[1] if len(args) > 1 else args[-1])
        iv = iv.split("(", 1)[0].strip() if iv.endswith(")") and "(" in iv and not iv.startswith("new") else iv
        no = _line_of(code, m.start())
        window = "\n".join(lines[max(0, no - 11):no + 10])
        if "ENCRYPT_MODE" not in window or "DECRYPT_MODE" in lines[no - 1]:
            continue
        if re.match(r"^[\w.]+$", iv) and re.search(r"\.nextBytes\(\s*" + re.escape(iv) + r"\s*\)", code):
            continue
        if re.match(r"^[\w.]+$", iv) and re.search(r"(SecureRandom|generateIv|randomIv|newIv)", code) \
                and re.search(r"\b" + re.escape(iv.rsplit(".", 1)[-1]) + r"\s*=\s*[\w.]*(?:random|generate)\w*\(",
                              code, re.I):
            continue
        out.append(no)
    return out


def scan_spring(root: str) -> tuple[list[dict], dict]:
    """Findings (one per rule, every location listed) and coverage counts."""
    hits: dict[str, list[tuple[str, int, str]]] = {}  # rule id -> [(file, line, note)]
    meta: dict[str, tuple] = {}
    cfg_files = java_files = 0
    for rel, text in _walk(root, lambda n: bool(_CONFIG_FILE.match(n))):
        cfg_files += 1
        if _TEST_PATH.search("/" + rel):
            continue
        for line, key, value in config_entries(rel, text):
            rule = _SETTINGS_BY_KEY.get(norm_key(key))
            if rule and rule[2](value):
                hits.setdefault(rule[0], []).append((rel, line, f"{key}: {value}"[:200]))
                meta[rule[0]] = rule[3:]
    for rel, text in _walk(root, lambda n: n.endswith(".java")):
        java_files += 1
        if _TEST_PATH.search("/" + rel):
            continue
        code = _strip_comments(text)
        for rid, rx, *rest in JAVA_RULES:
            for m in rx.finditer(code):
                note = ""
                if rid == "cors-wildcard" and _CREDENTIALS.search(code):
                    note = "credentials"
                hits.setdefault(rid, []).append((rel, _line_of(code, m.start()), note))
                meta[rid] = tuple(rest)
        for no in static_iv_lines(code):
            hits.setdefault("static-iv", []).append((rel, no, ""))
            meta["static-iv"] = STATIC_IV
    findings = []
    for rid, locs in hits.items():
        severity, title, cwe, what, exploit, fix = meta[rid]
        if rid == "cors-wildcard" and any(n == "credentials" for _, _, n in locs):
            severity = "Medium"
            what += " The same file also allows credentials, so cookies are sent with those requests."
        locs = sorted(set(locs))
        first = locs[0]
        desc = what
        if len(locs) > 1:
            desc += f"\n\nFound in {len(locs)} locations."
        f = make_finding(severity=severity, title=title, file_path=first[0], line=first[1],
                         snippet=read_snippet(root, first[0], first[1]), description=desc, check="code",
                         scanner="vapt", rule_id=f"vapt.spring.{rid}", cwe=cwe, exploitation=exploit,
                         recommendation=fix)
        if len(locs) > 1:
            f["locations"] = [{"file": p, "line": n} for p, n, _ in locs]
        f["_fp_key"] = f"spring|{rid}"
        findings.append(f)
    return findings, {"config_files": cfg_files, "java_files": java_files}
