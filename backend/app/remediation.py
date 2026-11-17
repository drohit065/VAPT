"""Concrete, copy-ready fixes for common findings.

Runs in the worker after grouping. It reads the scanned files only to tailor the text (the base
image of a Dockerfile, whether a file also decrypts, how a SpEL expression is evaluated); it never
changes them. Code blocks are written as ``` fences so the UI and the PDF can render them as code.
"""
from __future__ import annotations

import os
import re

FENCE = "```"


def code_block(body: str, lang: str = "") -> str:
    return f"{FENCE}{lang}\n{body.strip(chr(10))}\n{FENCE}"


def split_blocks(text: str) -> list[tuple[str, str]]:
    """[("text"|"code", content), ...] from text with ``` fences. An unclosed fence is plain text."""
    out: list[tuple[str, str]] = []
    rest = text or ""
    while True:
        start = rest.find(FENCE)
        end = rest.find("\n" + FENCE, start + 3) if start >= 0 else -1
        if start < 0 or end < 0:
            if rest.strip():
                out.append(("text", rest.strip("\n")))
            return out
        if rest[:start].strip():
            out.append(("text", rest[:start].strip("\n")))
        body = rest[start + 3:end]
        body = body.split("\n", 1)[1] if "\n" in body else ""  # drop the language tag line
        out.append(("code", body))
        rest = rest[end + 1 + len(FENCE):]


# ---------------------------------------------------------------- dependency upgrade wording per ecosystem

ECOSYSTEM_FIX = {
    "maven": "Maven has no lockfile: change the version in pom.xml (or in the <dependencyManagement> section or "
             "parent BOM that manages it), then rebuild with `mvn -U verify` and re-run your tests. "
             "`mvn dependency:tree -Dincludes=<groupId>:<artifactId>` shows which version is actually resolved.",
    "gradle": "Change the version in build.gradle (or the platform/BOM or version catalog that manages it), then "
              "rebuild with `gradle build --refresh-dependencies` and re-run your tests. If you use dependency "
              "locking, refresh it with `gradle dependencies --write-locks`.",
    "npm": "Update package.json, run `npm install` to regenerate package-lock.json (or `yarn install` / "
           "`pnpm install` for their lockfiles) and re-run your tests.",
    "pip": "Update the pinned version in requirements.txt / pyproject.toml, regenerate the lockfile if you use one "
           "(`pip-compile`, `poetry lock`, `uv lock`), reinstall and re-run your tests.",
    "go": "Run `go get <module>@<version>` and `go mod tidy`, then re-run your tests.",
    "cargo": "Run `cargo update -p <crate> --precise <version>` (or raise the version in Cargo.toml), then re-run "
             "your tests.",
    "composer": "Run `composer require <package>:<version>` (updates composer.lock), then re-run your tests.",
    "ruby": "Raise the version in the Gemfile, run `bundle update <gem>`, then re-run your tests.",
    "nuget": "Update the PackageReference version in the project file, run `dotnet restore`, then re-run your tests.",
    "os": "This is an operating-system package in the image: rebuild on an updated base image tag, or upgrade the "
          "package in the Dockerfile (`apk upgrade <pkg>`, `apt-get install --only-upgrade <pkg>` or "
          "`dnf upgrade <pkg>`), then re-scan the image.",
    "other": "Update the declared version, rebuild and re-run your tests.",
}

_TRIVY_TYPE = {
    "pom": "maven", "jar": "maven", "gradle": "gradle", "sbt": "maven", "npm": "npm", "yarn": "npm",
    "pnpm": "npm", "node-pkg": "npm", "bun": "npm", "pip": "pip", "pipenv": "pip", "poetry": "pip", "uv": "pip",
    "python-pkg": "pip", "conda-pkg": "pip", "gomod": "go", "gobinary": "go", "cargo": "cargo",
    "rustbinary": "cargo", "composer": "composer", "composer-vendor": "composer", "bundler": "ruby",
    "gemspec": "ruby", "nuget": "nuget", "dotnet-core": "nuget", "packages-props": "nuget",
}


def ecosystem(path: str, trivy_class: str = "", trivy_type: str = "") -> str:
    if trivy_class == "os-pkgs":
        return "os"
    if trivy_type in _TRIVY_TYPE:
        return _TRIVY_TYPE[trivy_type]
    p = (path or "").lower().rsplit("/", 1)[-1]
    if p == "pom.xml" or p.endswith(".jar") or p.endswith(".war"):
        return "maven"
    if "gradle" in p:
        return "gradle"
    if p in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"):
        return "npm"
    if p.startswith("requirements") or p in ("pipfile.lock", "poetry.lock", "pyproject.toml", "uv.lock"):
        return "pip"
    if p in ("go.mod", "go.sum"):
        return "go"
    if p in ("cargo.lock", "cargo.toml"):
        return "cargo"
    if p in ("composer.json", "composer.lock"):
        return "composer"
    if p in ("gemfile", "gemfile.lock"):
        return "ruby"
    if p.endswith(".csproj") or p == "packages.lock.json":
        return "nuget"
    return "other"


def _read(root: str | None, rel: str, limit: int = 1_000_000) -> str | None:
    if not root or not rel:
        return None
    base = os.path.realpath(root)
    path = os.path.realpath(os.path.join(root, rel))
    if not path.startswith(base + os.sep) or not os.path.isfile(path):
        return None
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


_IMPORT = re.compile(r"^\s*(import|from|package|using|#include)\b|^\s*(const|let|var)\s+\w+\s*=\s*require\(")


def _lines_matching(text: str, rx: re.Pattern, cap: int = 5) -> list[int]:
    """Line numbers where rx matches actual code (import lines are skipped)."""
    return [i for i, line in enumerate(text.splitlines(), 1) if rx.search(line) and not _IMPORT.match(line)][:cap]


def _rule_tail(f: dict) -> str:
    rid = f.get("rule_id") or ""
    return rid.rsplit(".", 1)[-1] if f.get("check") == "code" else rid


def _fmt_lines(nums: list[int]) -> str:
    return ", ".join(str(n) for n in nums)


# ---------------------------------------------------------------- Dockerfile: run as non-root

_FROM = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.I)
_RUNTIME = re.compile(r"^\s*(ENTRYPOINT|CMD)\b", re.I)
_EXPOSE = re.compile(r"^\s*EXPOSE\s+(.+)", re.I)
ROOT_RULE = re.compile(r"^AVD-DS-0002$|missing-user(-entrypoint)?$", re.I)


def dockerfile_final_stage(text: str) -> dict:
    """Base image of the final stage (following `FROM <earlier stage>` aliases), the line of its
    first ENTRYPOINT/CMD, and the privileged ports it exposes."""
    lines = text.splitlines()
    stages = []  # (image, alias, line index)
    for i, line in enumerate(lines):
        m = _FROM.match(line)
        if m:
            stages.append((m.group(1), (m.group(2) or "").lower(), i))
    if not stages:
        return {"image": None, "runtime_line": None, "low_ports": []}
    image, _, start = stages[-1]
    aliases = {alias: img for img, alias, _ in stages if alias}
    seen = set()
    while image.lower() in aliases and image.lower() not in seen:
        seen.add(image.lower())
        image = aliases[image.lower()]
    runtime_line, low_ports = None, []
    for i in range(start + 1, len(lines)):
        if runtime_line is None and _RUNTIME.match(lines[i]):
            runtime_line = i + 1
        m = _EXPOSE.match(lines[i])
        if m:
            low_ports += [int(p) for p in re.findall(r"\b(\d{1,5})(?:/\w+)?\b", m.group(1)) if int(p) < 1024]
    return {"image": image, "runtime_line": runtime_line, "low_ports": low_ports}


def base_family(image: str | None) -> str:
    img = (image or "").lower()
    if not img or "$" in img:
        return "unknown"
    if img == "scratch":
        return "scratch"
    if "distroless" in img or img.startswith("cgr.dev/chainguard/"):
        return "distroless"
    if "alpine" in img or re.match(r"(.*/)?busybox(:|$)", img):
        return "alpine"
    if re.search(r"(^|/)(ubi\d*(-minimal|-micro)?|centos|rockylinux|almalinux|fedora|oraclelinux|amazonlinux|"
                 r"redhat)|amazoncorretto|[-:]oracle\b|[-:]ubi\d*\b", img):
        return "rhel"
    if re.search(r"debian|ubuntu|[-:]slim\b|bookworm|bullseye|buster|trixie|jammy|focal|noble", img):
        return "debian"
    # Docker Hub official images whose default variant is Debian/Ubuntu. A custom or private image
    # (e.g. "registry/team/openjdk-17") says nothing reliable about its distribution.
    official = re.fullmatch(r"(?:docker\.io/)?(?:library/)?([a-z0-9._-]+)(?::[\w.-]+)?(?:@sha256:\w+)?", img)
    if official and official.group(1) in ("eclipse-temurin", "node", "python", "golang", "ruby", "php", "nginx",
                                          "httpd", "maven", "gradle", "tomcat", "buildpack-deps", "perl", "rust"):
        return "debian"
    return "unknown"


USER_SNIPPETS = {
    "debian": "RUN addgroup --system app && adduser --system --ingroup app app\nUSER app",
    "alpine": "RUN addgroup -S app && adduser -S -G app app\nUSER app",
    "rhel": "RUN groupadd --system app && useradd --system --gid app --no-create-home app\nUSER app",
    "distroless": "USER nonroot:nonroot",
    "scratch": "USER 65532:65532",
}


def docker_user_fix(f: dict, root: str | None) -> tuple[str, str]:
    path = f.get("file_path") or "Dockerfile"
    text = _read(root, path) or ""
    stage = dockerfile_final_stage(text) if text else {"image": None, "runtime_line": None, "low_ports": []}
    family = base_family(stage["image"])
    parts = []
    if family == "unknown":
        lead = (f"The final stage of {path} is based on {stage['image']}; the image name does not say which "
                "Linux distribution it uses, so use the variant that matches it. "
                if stage["image"] else f"Create an unprivileged user in the final stage of {path} and switch to it. ")
        parts.append(lead + "Debian/Ubuntu-based:")
        parts.append(code_block(USER_SNIPPETS["debian"], "dockerfile"))
        parts.append("Alpine-based:")
        parts.append(code_block(USER_SNIPPETS["alpine"], "dockerfile"))
        parts.append("Red Hat, Oracle Linux or Amazon Linux-based (no `adduser`):")
        parts.append(code_block(USER_SNIPPETS["rhel"], "dockerfile"))
        parts.append("To check, run `docker run --rm --entrypoint cat <image> /etc/os-release`.")
    else:
        label = {"debian": "Debian/Ubuntu", "alpine": "Alpine", "rhel": "Red Hat-family",
                 "distroless": "distroless", "scratch": "scratch"}[family]
        lead = (f"The final stage of {path} is based on {stage['image']} ({label}). "
                if stage["image"] else "")
        if family == "distroless":
            parts.append(lead + "Distroless images already contain an unprivileged `nonroot` user (UID 65532); "
                         "switch to it, or use the `:nonroot` tag of the image:")
        elif family == "scratch":
            parts.append(lead + "A scratch image has no user database, so switch to a numeric unprivileged UID:")
        else:
            parts.append(lead + "Create an unprivileged user and switch to it:")
        parts.append(code_block(USER_SNIPPETS[family], "dockerfile"))
        if family == "debian":
            parts.append("If `adduser` is not installed in the image, use "
                         "`RUN groupadd --system app && useradd --system --gid app --no-create-home app` instead.")
        elif family == "rhel":
            parts.append("On minimal images without `useradd` (ubi-minimal, some Amazon Linux based images), "
                         "install it first: `microdnf install -y shadow-utils` (or `dnf`/`yum`).")
    where = ("Place these lines after the steps that need root (package installs, COPY) and before "
             + (f"the ENTRYPOINT/CMD on line {stage['runtime_line']}." if stage["runtime_line"] else "ENTRYPOINT/CMD."))
    parts.append(where + " Files copied earlier stay owned by root, which is fine if the application only reads "
                 "them. If it writes to a directory (logs, uploads, temp files), give the user ownership, e.g. "
                 "`COPY --chown=app:app ...` or `RUN mkdir -p /app/logs && chown -R app:app /app/logs`.")
    if stage["low_ports"]:
        parts.append(f"The image exposes port(s) {_fmt_lines(sorted(set(stage['low_ports'])))} (below 1024). Docker "
                     "20.10+ lets non-root processes bind them; on older engines or restricted Kubernetes "
                     "clusters, listen on a port of 1024 or higher instead.")
    parts.append("On Kubernetes also set `securityContext: {runAsNonRoot: true, allowPrivilegeEscalation: false}`.")
    exploit = ("The application process runs as root inside the container. If an attacker gets code execution "
               "through any other flaw (for example a vulnerable dependency or an injection), they are root in "
               "the container: they can change the application's files, read every mounted secret, install "
               "tools, and have a much easier path to the host through a kernel or container-runtime "
               "vulnerability or a mounted Docker socket or host path.")
    return exploit, "\n\n".join(parts)


# ---------------------------------------------------------------- CBC -> GCM

CBC_RULE = re.compile(r"cbc-padding-oracle|(^|[-_.])cbc([-_.]|$)", re.I)

JAVA_GCM = """\
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class AesGcm {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int IV_BYTES = 12;    // 96-bit nonce: new random value for every message
    private static final int TAG_BITS = 128;

    public static byte[] encrypt(SecretKey key, byte[] plaintext) throws GeneralSecurityException {
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);
        // store the IV in front of the ciphertext; it is not secret
        return ByteBuffer.allocate(IV_BYTES + ciphertext.length).put(iv).put(ciphertext).array();
    }

    public static byte[] decrypt(SecretKey key, byte[] message) throws GeneralSecurityException {
        ByteBuffer buf = ByteBuffer.wrap(message);
        byte[] iv = new byte[IV_BYTES];
        buf.get(iv);
        byte[] ciphertext = new byte[buf.remaining()];
        buf.get(ciphertext);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        return cipher.doFinal(ciphertext);      // throws AEADBadTagException if the data was modified
    }
}"""

PYTHON_GCM = """\
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)                      # new random 96-bit nonce for every message
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

def decrypt(key: bytes, message: bytes) -> bytes:
    return AESGCM(key).decrypt(message[:12], message[12:], None)   # raises InvalidTag if modified"""

NODE_GCM = """\
const crypto = require('crypto');

function encrypt(key, plaintext) {             // key: 32-byte Buffer
  const iv = crypto.randomBytes(12);            // new random 96-bit nonce for every message
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

function decrypt(key, message) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, message.subarray(0, 12));
  decipher.setAuthTag(message.subarray(12, 28));
  return Buffer.concat([decipher.update(message.subarray(28)), decipher.final()]);  // throws if modified
}"""

_DECRYPT = {
    "java": re.compile(r"DECRYPT_MODE"),
    "python": re.compile(r"\.decryptor\(|\bdecrypt\("),
    "node": re.compile(r"createDecipheriv"),
}


def _lang(path: str) -> str | None:
    ext = os.path.splitext(path or "")[1].lower()
    return {".java": "java", ".kt": "java", ".scala": "java", ".groovy": "java", ".py": "python",
            ".js": "node", ".mjs": "node", ".cjs": "node", ".ts": "node"}.get(ext)


def cbc_fix(f: dict, root: str | None) -> tuple[str, str]:
    path = f.get("file_path") or ""
    lang = _lang(path)
    text = _read(root, path)
    decrypt_lines = _lines_matching(text, _DECRYPT[lang]) if text and lang else []
    exploit = ("AES in CBC mode without a MAC is exploitable as a padding oracle, and only on the decrypt side: "
               "an attacker who can submit modified ciphertext to code that decrypts it, and can tell whether "
               "the padding was valid (a different error, status code or response time), can decrypt the data "
               "byte by byte and forge new ciphertext without knowing the key. Encrypting alone is not "
               "exploitable this way.")
    if decrypt_lines:
        exploit += (f" {path} also decrypts (line {_fmt_lines(decrypt_lines)}): check where that ciphertext "
                    "comes from. If a client can send or modify it (a token, cookie, URL parameter, form field or "
                    "webhook payload), treat this as exploitable; if only data the server stored itself is "
                    "decrypted, the practical risk is low, though CBC still gives no integrity protection.")
    elif text and lang:
        exploit += (f" No decryption call was found in {path}; check where this ciphertext is decrypted, since "
                    "that is where the padding oracle would be.")
    parts = ["Switch to authenticated encryption, AES-GCM, with a new random 12-byte IV for every message "
             "stored next to the ciphertext. Never reuse an IV with the same key."]
    snippet = {"java": JAVA_GCM, "python": PYTHON_GCM, "node": NODE_GCM}.get(lang or "")
    if snippet:
        parts.append(code_block(snippet, lang))
    else:
        parts.append("Use the AES-GCM (or ChaCha20-Poly1305) API of your platform's standard crypto library.")
    parts.append("Existing data: values already encrypted with CBC cannot be decrypted with GCM. Migrate them: "
                 "add a format marker (for example a version byte) to new values, keep the old CBC decrypt path "
                 "only to read and re-encrypt existing records, then remove it.")
    parts.append("If the CBC format is fixed by a third party (for example a provider's webhook or API format) and "
                 "cannot change, verify the provider's HMAC or signature over the ciphertext before decrypting, "
                 "and return the same generic error for every decryption failure.")
    return exploit, "\n\n".join(parts)


# ---------------------------------------------------------------- SpEL

SPEL_RULE = re.compile(r"spel-injection$", re.I)

SPEL_SIMPLE = """\
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

ExpressionParser parser = new SpelExpressionParser();
// Read-only data binding: property access only. No T(...) type references, no constructors,
// no bean references and no method calls, so expressions cannot run arbitrary code.
EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
Boolean result = parser.parseExpression(expression).getValue(context, rootObject, Boolean.class);"""

SPEL_RULES = """\
enum Operator { GT, GTE, LT, LTE, EQ }

record Rule(String field, Operator operator, double threshold) {}

static boolean matches(Rule rule, double value) {
    return switch (rule.operator()) {
        case GT -> value > rule.threshold();
        case GTE -> value >= rule.threshold();
        case LT -> value < rule.threshold();
        case LTE -> value <= rule.threshold();
        case EQ -> value == rule.threshold();
    };
}"""

_STANDARD_CTX = re.compile(r"\bStandardEvaluationContext\b")
_SIMPLE_CTX = re.compile(r"\bSimpleEvaluationContext\b")


def spel_fix(f: dict, root: str | None) -> tuple[str, str]:
    path = f.get("file_path") or ""
    text = _read(root, path) or ""
    standard = _lines_matching(text, _STANDARD_CTX)
    exploit = ("If any part of the expression string comes from a request, a database row, a file or another "
               "source an attacker can influence, it is evaluated with full SpEL power: an expression such as "
               "T(java.lang.Runtime).getRuntime().exec('...') runs operating-system commands on the server "
               "(remote code execution). getValue() without an explicit context, and StandardEvaluationContext, "
               "both allow this. If the expression is a fixed string in the code, it is not exploitable.")
    if standard:
        exploit += f" {path} uses StandardEvaluationContext (line {_fmt_lines(standard)})."
    elif text and not _SIMPLE_CTX.search(text):
        exploit += f" {path} does not use SimpleEvaluationContext, so the default full context applies."
    parts = ["Option 1: evaluate with a restricted context (Spring 4.3.15 / 5.0.5 and later):",
             code_block(SPEL_SIMPLE, "java"),
             "Expressions that call methods stop working under this context; test the existing expressions.",
             "Option 2 (preferred when expressions are rules such as scores or thresholds): stop evaluating "
             "expression strings and store a fixed model instead, a field, an operator from an allow-list "
             "and a threshold:",
             code_block(SPEL_RULES, "java"),
             "Whichever option you choose, do not build expression strings by concatenating user input."]
    return exploit, "\n\n".join(parts)


# ---------------------------------------------------------------- secrets

ROTATE_STEP = {
    "gcp_sa": "delete this key in Google Cloud (IAM > Service accounts > Keys) and create a new one only if needed",
    "aws_secret": "deactivate and delete this access key in AWS IAM (Users > Security credentials), check "
                  "CloudTrail for its use, then create a new key or switch to an IAM role",
    "aws_key_id": "deactivate and delete this access key in AWS IAM (Users > Security credentials), check "
                  "CloudTrail for its use, then create a new key or switch to an IAM role",
    "private_key": "generate a new key pair, deploy the new public key or certificate, and revoke the old "
                   "certificate if one was issued",
    "gcp_api_key": "regenerate or delete the key in Google Cloud Console (APIs & Services > Credentials) and add "
                   "API and application restrictions to the new one",
    "azure_secret": "delete this client secret in Microsoft Entra ID (App registrations > Certificates & secrets) "
                    "and create a new one",
    "openai": "revoke the key in the OpenAI dashboard (API keys), check its usage for unexpected calls, and "
              "create a new key",
    "anthropic": "revoke the key in the Anthropic Console (API keys), check its usage, and create a new key",
    "slack": "revoke or regenerate the token in the Slack app settings",
    "github": "revoke the token in GitHub (Settings > Developer settings, or the organisation's token list) "
              "and check the audit log",
    "stripe": "roll the key in the Stripe Dashboard (Developers > API keys)",
    "jwt": "revoke the token, or rotate the signing key that issued it if it is long-lived",
    "password_hash": "change the password this hash belongs to: a committed hash can be cracked offline",
    "password": "change this password on the system it belongs to (database user, mail account, keystore or "
                "login) and update every deployment that uses it",
    "generic": "revoke this credential with its provider and issue a new one",
}


def env_name(key: str) -> str:
    return re.sub(r"_+", "_", re.sub(r"\W", "_", key or "")).strip("_").upper() or "SECRET"


def secret_fix(kind: str, locs: list[tuple[str, int | None]], in_history: bool,
               config_keys: list[tuple[str, bool]] | None = None) -> str:
    """config_keys: (property key, value is a ${VAR:default} fallback) for secrets found in Spring config."""
    n = len(locs)
    parts = ["Rotate immediately: " + ROTATE_STEP.get(kind, ROTATE_STEP["generic"]) + ". The value must be "
             "treated as leaked; removing it from the code does not undo that."]
    listing = [loc[0] + (f":{loc[1]}" if loc[1] else "") for loc in locs[:50]]
    if n > 50:
        listing.append(f"... and {n - 50} more (see Locations)")
    parts.append(f"Then remove it from the code at {'all ' + str(n) + ' locations' if n > 1 else 'this location'}:\n"
                 + "\n".join("- " + x for x in listing))
    if config_keys:
        keys = sorted(set(config_keys))[:10]
        lines = []
        for key, _ in keys:
            leaf = key.rsplit(".", 1)[-1]
            lines.append((f"# {key}\n" if leaf != key else "") + f"{leaf}: ${{{env_name(key)}}}")
        lead = ("Replace the literal with a placeholder that has no default" if not any(fb for _, fb in keys) else
                "Replace the literal with a placeholder and delete the default after the colon, so no value is "
                "built in")
        names = ", ".join(sorted({env_name(k) for k, _ in keys}))
        parts.append(f"{lead}, and set {names} in each environment or load it from a secrets manager:\n"
                     + code_block("\n".join(lines), "yaml"))
    else:
        parts.append("Load it at runtime from a secrets manager or an environment variable instead.")
    if in_history:
        parts.append("It is also in the Git history. After rotating, purge it from history with git filter-repo "
                     "(`git filter-repo --replace-text <file>`) or BFG (`bfg --replace-text <file>`), force-push, "
                     "and ask everyone to re-clone. Rotation is the actual fix; purging only removes the copy.")
    return "\n\n".join(parts)


# ---------------------------------------------------------------- entry point

def _without_code(rec: str, first: str) -> str:
    text = [part for kind, part in split_blocks(rec) if kind == "text"]
    return "\n\n".join([text[0], f"The code example is shown once, under the same finding at {first}.", *text[1:]])


def apply_remediation(findings: list[dict], root: str | None) -> int:
    """Replace generic fix text with concrete fixes. Call it on the final, sorted list: a long code
    example is shown under the first finding of its kind only. Returns the number changed."""
    changed = 0
    first_example: dict[str, str] = {}
    for f in findings:
        tail = _rule_tail(f)
        rules = [tail] + [r.rsplit(".", 1)[-1] for r in (f.get("_rules") or [])]
        example = None
        if f.get("check") in ("code", "iac") and (ROOT_RULE.search(tail) or (f.get("_fp_key") or "").endswith(
                "|container-root-user")):
            exploit, rec = docker_user_fix(f, root)
        elif f.get("check") == "code" and any(CBC_RULE.search(r) for r in rules):
            exploit, rec = cbc_fix(f, root)
            example = "cbc:" + (_lang(f.get("file_path") or "") or "")
        elif f.get("check") == "code" and SPEL_RULE.search(tail):
            exploit, rec = spel_fix(f, root)
            example = "spel"
        elif f.get("check") == "secrets" and not f.get("_secret_fp"):
            # ungrouped secret (no value fingerprint): one location
            exploit = f.get("exploitation")
            rec = secret_fix("generic", [(f.get("file_path") or "", f.get("line"))], bool(f.get("_in_history")))
        else:
            continue
        if example and FENCE in rec:
            loc = (f.get("file_path") or "") + (f":{f['line']}" if f.get("line") else "")
            if example in first_example:
                rec = _without_code(rec, first_example[example])
            else:
                first_example[example] = loc
        f["exploitation"], f["recommendation"] = exploit, rec
        changed += 1
    return changed
