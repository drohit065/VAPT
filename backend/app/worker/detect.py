"""Detect languages and frameworks from file extensions and manifests (read-only)."""
import json
import os
import re

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build",
             "target", ".next", ".terraform", "bower_components", ".idea", ".vscode"}

EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
    ".scala": "Scala", ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".vb": "VB.NET",
    ".c": "C", ".h": "C/C++", ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".rs": "Rust",
    ".swift": "Swift", ".m": "Objective-C", ".dart": "Dart", ".lua": "Lua", ".pl": "Perl",
    ".r": "R", ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".clj": "Clojure",
    ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell", ".sql": "SQL", ".html": "HTML",
    ".vue": "Vue", ".svelte": "Svelte", ".tf": "Terraform (HCL)", ".sol": "Solidity",
    ".groovy": "Groovy", ".yaml": "YAML", ".yml": "YAML",
}
# Languages that are config/markup only: listed, but after real code.
SECONDARY = {"YAML", "HTML", "SQL", "Shell"}

JS_FRAMEWORKS = {
    "react": "React", "next": "Next.js", "vue": "Vue", "nuxt": "Nuxt", "@angular/core": "Angular",
    "svelte": "Svelte", "express": "Express", "@nestjs/core": "NestJS", "koa": "Koa",
    "fastify": "Fastify", "hapi": "hapi", "@hapi/hapi": "hapi", "electron": "Electron",
    "react-native": "React Native", "sequelize": "Sequelize", "mongoose": "Mongoose",
    "prisma": "Prisma", "typeorm": "TypeORM", "jsonwebtoken": "jsonwebtoken",
}
PY_FRAMEWORKS = {"django": "Django", "flask": "Flask", "fastapi": "FastAPI", "tornado": "Tornado",
                 "pyramid": "Pyramid", "sqlalchemy": "SQLAlchemy", "celery": "Celery",
                 "aiohttp": "aiohttp", "starlette": "Starlette"}
TEXT_RULES = [
    # (manifest file name, regex, framework)
    ("pom.xml", r"spring-boot", "Spring Boot"), ("pom.xml", r"springframework", "Spring"),
    ("build.gradle", r"spring", "Spring"), ("build.gradle.kts", r"spring", "Spring"),
    ("pom.xml", r"quarkus", "Quarkus"), ("build.gradle", r"android", "Android"),
    ("go.mod", r"gin-gonic/gin", "Gin"), ("go.mod", r"labstack/echo", "Echo"),
    ("go.mod", r"gofiber/fiber", "Fiber"), ("go.mod", r"gorilla/mux", "Gorilla"),
    ("Gemfile", r"\brails\b", "Ruby on Rails"), ("Gemfile", r"\bsinatra\b", "Sinatra"),
    ("composer.json", r"laravel/framework", "Laravel"), ("composer.json", r"symfony/", "Symfony"),
    ("Cargo.toml", r"\bactix-web\b", "Actix Web"), ("Cargo.toml", r"\baxum\b", "Axum"),
    ("Cargo.toml", r"\brocket\b", "Rocket"), ("pubspec.yaml", r"flutter", "Flutter"),
]
MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "pom.xml",
             "build.gradle", "build.gradle.kts", "go.mod", "Gemfile", "composer.json", "Cargo.toml",
             "pubspec.yaml"}
MAX_MANIFEST_BYTES = 1024 * 1024


def _read(path: str) -> str:
    try:
        if os.path.islink(path) or os.path.getsize(path) > MAX_MANIFEST_BYTES:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def detect(root: str) -> dict:
    lang_counts: dict[str, int] = {}
    frameworks: set[str] = set()
    manifests: list[str] = []
    has_docker = has_tf = False

    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            ext = os.path.splitext(name)[1].lower()
            lang = EXT_LANG.get(ext)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + 1
            lower = name.lower()
            if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
                has_docker = True
            if lower in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                frameworks.add("Docker Compose")
            if ext == ".tf":
                has_tf = True
            if ext == ".csproj":
                text = _read(full)
                frameworks.add("ASP.NET Core" if "Microsoft.AspNetCore" in text or "Sdk.Web" in text else ".NET")
            if name in MANIFESTS:
                manifests.append(os.path.relpath(full, root))
                _framework_from_manifest(name, full, frameworks)

    if has_docker:
        frameworks.add("Docker")
    if has_tf:
        frameworks.add("Terraform")

    primary = sorted(((n, c) for n, c in lang_counts.items() if n not in SECONDARY), key=lambda x: -x[1])
    secondary = sorted(((n, c) for n, c in lang_counts.items() if n in SECONDARY), key=lambda x: -x[1])
    languages = [{"name": n, "files": c} for n, c in primary + secondary]
    return {"languages": languages, "frameworks": sorted(frameworks), "manifests": sorted(manifests)[:50]}


def _framework_from_manifest(name: str, path: str, frameworks: set[str]) -> None:
    text = _read(path)
    if not text:
        return
    if name == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return
        deps = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            if isinstance(data.get(key), dict):
                deps.update(data[key])
        for pkg, fw in JS_FRAMEWORKS.items():
            if pkg in deps:
                frameworks.add(fw)
        return
    if name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py"):
        low = text.lower()
        for pkg, fw in PY_FRAMEWORKS.items():
            if re.search(rf"(^|[\s\"'\[,]){re.escape(pkg)}([\s=<>~!\[\]\"',;]|$)", low, re.M):
                frameworks.add(fw)
        return
    for fname, pattern, fw in TEXT_RULES:
        if fname == name and re.search(pattern, text, re.I):
            frameworks.add(fw)
