"""
Universal Multi-Technology Security Scanning Engine for DKSec.
Provides deep static code analysis (SAST), software composition analysis (SCA),
secrets detection, and infrastructure-as-code (IaC) auditing across all major tech stacks:
- Python (Django, Flask, FastAPI, Celery, SQLAlchemy)
- JavaScript / TypeScript (Node.js, Express, React, Vue, Next.js, Angular, NestJS)
- Java / Kotlin (Spring Boot, Struts, Jakarta EE)
- PHP (Laravel, Symfony, WordPress)
- C# / .NET (ASP.NET Core, Entity Framework)
- Go (Gin, Echo, Fiber, standard library)
- Ruby (Ruby on Rails, Sinatra)
- Rust (Actix, Rocket, raw pointers)
- C / C++ (Memory safety, buffer overflows)
- Shell / Bash
- Docker & Docker Compose
- Kubernetes & Helm
- Terraform & CloudFormation
- CI/CD Workflows (GitHub Actions, GitLab CI)
"""

import os
import re
import json
from typing import List, Dict, Any, Tuple, Optional
from dksec.models import Finding, Severity, FindingStatus, SBOMComponent


# =============================================================================
# VERSION COMPARISON UTILITY
# =============================================================================

def _parse_version(ver_str: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of ints for comparison.
    Handles strings like '5.2.1', '4.2.4', '0.0.0-20211202192323', etc.
    Returns (0,) on failure so unknown versions are treated as non-vulnerable.
    """
    if not ver_str:
        return (0,)
    # Strip common prefixes like 'v', '>=' or '<='
    clean = re.sub(r'^[v<>=^~\s]+', '', ver_str.strip())
    # Take only the first segment (before '-' for pre-release / build metadata)
    clean = clean.split('-')[0].split('+')[0]
    parts = re.split(r'[.\s]', clean)
    result = []
    for p in parts[:4]:  # cap at 4 segments
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result) if result else (0,)


def _is_version_vulnerable(installed: str, max_vuln: str) -> bool:
    """Return True only if installed_version <= max_vuln version.
    
    e.g. installed='5.2.1', max_vuln='4.2.4' → False (already fixed)
         installed='2.31.0', max_vuln='2.31.0' → True (still affected)
         installed='1.0.0',  max_vuln='1.26.17' → True  (affected)
    """
    try:
        inst_t = _parse_version(installed)
        max_t = _parse_version(max_vuln)
        # Pad tuples to same length for comparison
        length = max(len(inst_t), len(max_t))
        inst_t = inst_t + (0,) * (length - len(inst_t))
        max_t = max_t + (0,) * (length - len(max_t))
        return inst_t <= max_t
    except Exception:
        # On any error, be conservative and skip the flag
        return False


# =============================================================================
# 1. TECHNOLOGY STACK DETECTOR
# =============================================================================
# 1. TECHNOLOGY STACK DETECTOR
# =============================================================================

class TechStackDetector:
    """Detects languages, frameworks, web servers, databases, and infrastructure in a project."""

    TECH_PATTERNS = {
        "python": [r"\.py$", r"requirements\.txt$", r"Pipfile", r"pyproject\.toml$"],
        "javascript": [r"\.jsx?$", r"\.mjs$", r"package\.json$"],
        "typescript": [r"\.tsx?$", r"tsconfig\.json$"],
        "java": [r"\.java$", r"pom\.xml$", r"build\.gradle"],
        "kotlin": [r"\.kt$", r"\.kts$"],
        "scala": [r"\.scala$", r"build\.sbt$"],
        "php": [r"\.php$", r"composer\.json$"],
        "csharp": [r"\.cs$", r"\.csproj$", r"packages\.config$"],
        "go": [r"\.go$", r"go\.mod$"],
        "ruby": [r"\.rb$", r"Gemfile$"],
        "rust": [r"\.rs$", r"Cargo\.toml$"],
        "c_cpp": [r"\.(?:c|cpp|cc|cxx|h|hpp)$", r"CMakeLists\.txt$"],
        "swift": [r"\.swift$", r"Package\.swift$"],
        "shell": [r"\.(?:sh|bash|zsh)$"],
        "docker": [r"Dockerfile", r"docker-compose\.ya?ml$"],
        "kubernetes": [r"k8s.*\.ya?ml$", r"deployment.*\.ya?ml$", r"Chart\.ya?ml$"],
        "terraform": [r"\.tf$", r"\.tfvars$"],
        "cloudformation": [r"template\.ya?ml$", r"template\.json$", r"cloudformation.*\.ya?ml$"],
        "serverless": [r"serverless\.ya?ml$", r"sam\.ya?ml$"],
        "github_actions": [r"\.github/workflows/.*\.ya?ml$"],
        "gitlab_ci": [r"\.gitlab-ci\.yml$"],
    }

    SERVER_PATTERNS = {
        "nginx": [r"nginx.*\.conf$", r"sites-available", r"sites-enabled", r"conf\.d/.*\.conf$"],
        "apache": [r"\.htaccess$", r"httpd\.conf$", r"apache2?\.conf$"],
        "caddy": [r"Caddyfile$"],
        "iis": [r"web\.config$"],
        "envoy": [r"envoy.*\.ya?ml$", r"envoy.*\.json$"],
        "haproxy": [r"haproxy.*\.cfg$"],
        "traefik": [r"traefik.*\.ya?ml$", r"traefik.*\.toml$"],
        "gunicorn": [r"gunicorn\.conf\.py$", r"Procfile"],
        "supervisord": [r"supervisord\.conf$"],
    }

    FRAMEWORK_SIGNATURES = {
        "django": ("Python", [r"django\.", r"manage\.py", r"settings\.py", r"urls\.py"]),
        "flask": ("Python", [r"from\s+flask\s+import", r"Flask\(__name__\)"]),
        "fastapi": ("Python", [r"from\s+fastapi\s+import", r"FastAPI\(\)"]),
        "celery": ("Python", [r"from\s+celery\s+import", r"Celery\(", r"@shared_task"]),
        "tornado": ("Python", [r"tornado\.web", r"tornado\.ioloop"]),
        "express": ("Node.js", [r"require\(['\"]express['\"]\)", r"from\s+['\"]express['\"]"]),
        "react": ("Frontend", [r"from\s+['\"]react['\"]", r"require\(['\"]react['\"]\)"]),
        "vue": ("Frontend", [r"from\s+['\"]vue['\"]", r"\.vue$"]),
        "angular": ("Frontend", [r"@angular/core", r"angular\.json"]),
        "svelte": ("Frontend", [r"\.svelte$", r"@sveltejs"]),
        "nextjs": ("Node.js", [r"from\s+['\"]next/", r"next\.config\.js"]),
        "nuxt": ("Node.js", [r"nuxt\.config", r"@nuxt"]),
        "nestjs": ("Node.js", [r"@nestjs/core", r"@nestjs/common"]),
        "fastify": ("Node.js", [r"fastify\(", r"require\(['\"]fastify['\"]\)"]),
        "koa": ("Node.js", [r"require\(['\"]koa['\"]\)"]),
        "spring_boot": ("Java", [r"@SpringBootApplication", r"org\.springframework"]),
        "quarkus": ("Java", [r"io\.quarkus", r"@QuarkusTest"]),
        "micronaut": ("Java", [r"io\.micronaut", r"@Controller"]),
        "laravel": ("PHP", [r"Illuminate\\", r"artisan", r"app/Http/Controllers"]),
        "symfony": ("PHP", [r"Symfony\\", r"bin/console"]),
        "wordpress": ("PHP", [r"wp-config\.php", r"wp-content", r"add_action\("]),
        "rails": ("Ruby", [r"Rails\.application", r"config/routes\.rb"]),
        "aspnet_core": (".NET", [r"Microsoft\.AspNetCore", r"Program\.cs"]),
        "gin": ("Go", [r"github\.com/gin-gonic/gin"]),
        "echo": ("Go", [r"github\.com/labstack/echo"]),
        "fiber": ("Go", [r"github\.com/gofiber/fiber"]),
        "actix": ("Rust", [r"actix_web", r"actix-web"]),
        "rocket": ("Rust", [r"rocket::", r"#\[launch\]"]),
        "axum": ("Rust", [r"axum::", r"axum"]),
    }

    DATABASE_SIGNATURES = {
        "postgresql": [r"psycopg2", r"postgres://", r"postgresql://", r"pg_", r"npgsql"],
        "mysql": [r"mysqlclient", r"pymysql", r"mysql://", r"mysql2"],
        "mongodb": [r"pymongo", r"mongodb(?:\+srv)?://", r"mongoose"],
        "redis": [r"redis://", r"redis\.", r"ioredis"],
        "sqlite": [r"sqlite3", r"\.sqlite3?$"],
        "cassandra": [r"cassandra-driver", r"gocql"],
    }

    @classmethod
    def detect(cls, target_path: str) -> Dict[str, Any]:
        detected_languages = set()
        detected_frameworks = set()
        detected_servers = set()
        detected_databases = set()
        detected_infra = set()
        file_count_by_ext = {}
        total_files = 0

        if not os.path.exists(target_path):
            return {
                "languages": [],
                "frameworks": [],
                "servers": [],
                "databases": [],
                "infra": [],
                "file_counts": {},
                "primary_language": "Unknown"
            }

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not UniversalMultiTechScanner.is_excluded_dir(d)]
            for f in files:
                total_files += 1
                rel = os.path.relpath(os.path.join(root, f), target_path)
                ext = os.path.splitext(f)[1].lower() or f
                file_count_by_ext[ext] = file_count_by_ext.get(ext, 0) + 1

                # Language detection
                for lang, pats in cls.TECH_PATTERNS.items():
                    for p in pats:
                        if re.search(p, rel, re.IGNORECASE):
                            if lang in ("docker", "kubernetes", "terraform", "cloudformation", "serverless", "github_actions", "gitlab_ci"):
                                detected_infra.add(lang)
                            else:
                                detected_languages.add(lang)
                            break

                # Server detection
                for srv, pats in cls.SERVER_PATTERNS.items():
                    for p in pats:
                        if re.search(p, rel, re.IGNORECASE):
                            detected_servers.add(srv)
                            break

                # Database detection by file name / extension
                for db, pats in cls.DATABASE_SIGNATURES.items():
                    for p in pats:
                        if re.search(p, rel, re.IGNORECASE):
                            detected_databases.add(db)
                            break

                # Framework and code-level database inspection
                if ext in (".py", ".js", ".ts", ".java", ".php", ".cs", ".go", ".rb", ".rs", ".yml", ".yaml", ".txt", ".json"):
                    try:
                        fpath = os.path.join(root, f)
                        if os.path.getsize(fpath) < 120000:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as fl:
                                header = fl.read(6000)
                                for fw_name, (parent_lang, fw_pats) in cls.FRAMEWORK_SIGNATURES.items():
                                    for pat in fw_pats:
                                        if re.search(pat, header) or re.search(pat, rel):
                                            detected_frameworks.add(fw_name)
                                for db, pats in cls.DATABASE_SIGNATURES.items():
                                    for pat in pats:
                                        if re.search(pat, header):
                                            detected_databases.add(db)
                                            break
                    except Exception:
                        pass

        primary = "Python" if "python" in detected_languages else (
            "JavaScript/TypeScript" if ("javascript" in detected_languages or "typescript" in detected_languages) else (
                "Java" if "java" in detected_languages else (
                    "PHP" if "php" in detected_languages else (
                        "Go" if "go" in detected_languages else (
                            "C#" if "csharp" in detected_languages else (
                                "Ruby" if "ruby" in detected_languages else (
                                    "Rust" if "rust" in detected_languages else "Multi-Language"
                                )
                            )
                        )
                    )
                )
            )
        )

        return {
            "languages": sorted(list(detected_languages)),
            "frameworks": sorted(list(detected_frameworks)),
            "servers": sorted(list(detected_servers)),
            "databases": sorted(list(detected_databases)),
            "infra": sorted(list(detected_infra)),
            "file_counts": file_count_by_ext,
            "total_files": total_files,
            "primary_language": primary
        }



# =============================================================================
# 2. UNIVERSAL MULTI-LANGUAGE SAST RULES
# =============================================================================

MULTI_LANG_RULES = [
    # PYTHON
    ("py-sqli-fstring", r"\.(?:execute|raw|extra)\s*\(\s*f[\"'].*\{", "SQL Injection via Python f-string query formatting", Severity.CRITICAL, "CWE-89", "OWASP A03:2021-Injection", "Use parameterized query placeholders (%s or ?), never format SQL strings with f-strings or concatenation.", "T1190"),
    ("py-sqli-percent", r"\.(?:execute|raw)\s*\(\s*[\"'].*%s.*[\"']\s*%", "SQL Injection via Python %-formatting in SQL execution", Severity.CRITICAL, "CWE-89", "OWASP A03:2021-Injection", "Pass query arguments as a separate tuple or list parameter: cursor.execute(query, (param,))", "T1190"),
    ("py-sqlalchemy-raw-text", r"text\s*\(\s*f[\"'].*\{|text\s*\(\s*[\"'].*[\"']\s*\+", "SQL Injection via SQLAlchemy unparameterized text() clause", Severity.HIGH, "CWE-89", "OWASP A03:2021-Injection", "Use bound parameters with text('SELECT * FROM t WHERE id = :id').bindparams(id=val).", "T1190"),
    ("py-pickle-deserial", r"\bpickle\.(?:loads?|Unpickler)\s*\(", "Insecure Deserialization via Python pickle", Severity.CRITICAL, "CWE-502", "OWASP A08:2021-Software and Data Integrity Failures", "Do not use pickle to process untrusted data. Use JSON, MessagePack, or Protocol Buffers.", "T1059"),
    ("py-yaml-unsafe-load", r"yaml\.(?:load|unsafe_load)\s*\([^)]*(?!Loader=yaml\.SafeLoader|Loader=SafeLoader)", "Unsafe YAML Deserialization (Arbitrary Code Execution)", Severity.HIGH, "CWE-502", "OWASP A08:2021-Software and Data Integrity Failures", "Replace yaml.load() with yaml.safe_load().", "T1059"),
    ("py-cmd-injection", r"subprocess\.(?:Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True", "Command Injection: subprocess invoked with shell=True", Severity.HIGH, "CWE-78", "OWASP A03:2021-Injection", "Set shell=False and pass command arguments as a list of strings: subprocess.run(['cmd', arg1]).", "T1059"),
    ("py-os-system", r"\bos\.(?:system|popen|popen2|popen3|popen4)\s*\(", "Dangerous System Execution via os.system / os.popen", Severity.HIGH, "CWE-78", "OWASP A03:2021-Injection", "Avoid os.system; use subprocess.run with shell=False and validated parameters.", "T1059"),
    ("py-eval-exec", r"\b(?:eval|exec)\s*\(", "Arbitrary Code Execution via eval() or exec()", Severity.CRITICAL, "CWE-95", "OWASP A03:2021-Injection", "Eliminate eval/exec calls. Use ast.literal_eval for parsing literals or standard dispatch tables.", "T1059"),
    ("py-ssti-jinja", r"render_template_string\s*\(|Environment\(.*loader\).*\.from_string\s*\(", "Server-Side Template Injection (SSTI) via Jinja2", Severity.CRITICAL, "CWE-1336", "OWASP A03:2021-Injection", "Never render user-supplied strings directly as Jinja templates. Store templates in static files.", "T1190"),
    ("py-debug-true", r"\bDEBUG\s*=\s*True\b|app\.run\s*\([^)]*debug\s*=\s*True", "Production Debug Mode Enabled (Information Disclosure / RCE)", Severity.MEDIUM, "CWE-489", "OWASP A05:2021-Security Misconfiguration", "Ensure DEBUG is False in production environments using environment variables.", "T1592"),
    ("py-django-csrf-exempt", r"@csrf_exempt\b", "CSRF Protection Disabled via @csrf_exempt", Severity.MEDIUM, "CWE-352", "OWASP A01:2021-Broken Access Control", "Do not disable CSRF validation on state-modifying endpoints without alternative token validation.", "T1190"),
    ("py-weak-md5-sha1", r"hashlib\.(?:md5|sha1)\s*\(", "Weak Cryptographic Hash Algorithm (MD5 / SHA-1)", Severity.LOW, "CWE-328", "OWASP A02:2021-Cryptographic Failures", "Use SHA-256 for integrity or argon2/bcrypt for password hashing.", "T1110"),

    # JAVASCRIPT / TYPESCRIPT / NODE.JS
    ("js-child-process-exec", r"(?:child_process|\bcp)\.(?:exec|execSync)\s*\(", "Command Injection via child_process.exec", Severity.CRITICAL, "CWE-78", "OWASP A03:2021-Injection", "Use child_process.execFile or child_process.spawn with an argument array.", "T1059"),
    ("js-eval-injection", r"\beval\s*\(|new\s+Function\s*\(|vm\.runIn(?:ThisContext|NewContext)\s*\(", "Dynamic Code Evaluation via eval() or Function constructor", Severity.CRITICAL, "CWE-95", "OWASP A03:2021-Injection", "Avoid dynamic code generation. Use JSON.parse for structured data.", "T1059"),
    ("js-dom-xss-innerhtml", r"\.(?:innerHTML|outerHTML)\s*=\s*(?!['\"][^'\"]*['\"])", "DOM Cross-Site Scripting (XSS) via innerHTML assignment", Severity.HIGH, "CWE-79", "OWASP A03:2021-Injection", "Use textContent or sanitize HTML with DOMPurify before inserting into DOM.", "T1189"),
    ("js-react-dangerously-set", r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:", "React dangerouslySetInnerHTML Usage (XSS Risk)", Severity.HIGH, "CWE-79", "OWASP A03:2021-Injection", "Ensure content is sanitized with DOMPurify.sanitize() before setting dangerouslySetInnerHTML.", "T1189"),
    ("js-document-write", r"document\.(?:write|writeln)\s*\(", "Dangerous document.write() Invocation (XSS)", Severity.MEDIUM, "CWE-79", "OWASP A03:2021-Injection", "Use standard DOM manipulation methods (createElement, textContent, appendChild).", "T1189"),
    ("js-prototype-pollution", r"__proto__|constructor\.prototype|Object\.assign\s*\(\s*(?:req|user|data)", "JavaScript Prototype Pollution Vulnerability", Severity.HIGH, "CWE-1321", "OWASP A03:2021-Injection", "Validate object keys before merging; freeze Object.prototype or use Object.create(null).", "T1190"),
    ("js-nosql-injection", r"\$where\s*:|\$regex\s*:|find\(\s*\{.*req\.(?:body|query|params)", "NoSQL / MongoDB Operator Injection Risk", Severity.HIGH, "CWE-943", "OWASP A03:2021-Injection", "Sanitize query inputs, reject MongoDB operator keys (starting with '$'), and validate schemas.", "T1190"),
    ("js-sql-template-concat", r"\.(?:query|raw)\s*\(\s*`[^`]*\$\{.*req\.", "SQL Injection via Unsanitized Template Literal in Node.js", Severity.CRITICAL, "CWE-89", "OWASP A03:2021-Injection", "Use parameterized query bindings: db.query('SELECT * FROM t WHERE id = $1', [userId]).", "T1190"),
    ("js-jwt-none-algorithm", r"jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*['\"]none['\"]", "JWT Verification Allowing 'none' Algorithm", Severity.CRITICAL, "CWE-347", "OWASP A07:2021-Identification and Authentication Failures", "Never permit the 'none' algorithm. Enforce RS256/ES256 or HS256 with strong secrets.", "T1078"),
    ("js-cors-wildcard", r"origin\s*:\s*['\"]\*(?:['\"]|\s*,.*credentials\s*:\s*true)", "Insecure CORS Configuration: Wildcard with Credentials", Severity.HIGH, "CWE-942", "OWASP A01:2021-Broken Access Control", "Explicitly allowlist trusted origin domains instead of using wildcard '*' with credentials.", "T1190"),
    ("js-ssl-ignore", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]", "TLS Certificate Verification Disabled", Severity.CRITICAL, "CWE-295", "OWASP A02:2021-Cryptographic Failures", "Always enable TLS certificate validation in production (rejectUnauthorized: true).", "T1557"),

    # JAVA / KOTLIN
    ("java-object-input-stream", r"ObjectInputStream\s*\(|readObject\s*\(\s*\)", "Unsafe Java Deserialization via ObjectInputStream", Severity.CRITICAL, "CWE-502", "OWASP A08:2021-Software and Data Integrity Failures", "Use JEP 290 ObjectInputFilter to restrict allowable classes, or migrate to JSON/Protobuf.", "T1059"),
    ("java-log4shell-pattern", r"\$\{jndi:(?:ldap|rmi|dns|nis):", "Log4Shell (CVE-2021-44228) JNDI Injection Signature", Severity.CRITICAL, "CWE-502", "OWASP A03:2021-Injection", "Upgrade Log4j to >=2.17.1 or set log4j2.formatMsgNoLookups=true.", "T1190"),
    ("java-sql-concat", r"(?:Statement|PreparedStatement|Connection)\s*.*(?:\.executeQuery|\.executeUpdate)\s*\(.*(?:\+|concat)", "SQL Injection via Java Statement String Concatenation", Severity.CRITICAL, "CWE-89", "OWASP A03:2021-Injection", "Use PreparedStatement with setString/setInt positional parameters.", "T1190"),
    ("java-xxe-sax-builder", r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(\)", "Java XML Parser Without XXE Protection", Severity.HIGH, "CWE-611", "OWASP A05:2021-Security Misconfiguration", "Disable external DTD: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true).", "T1190"),
    ("java-spring-actuator-exposed", r"management\.endpoints\.web\.exposure\.include\s*=\s*(?:\*|.*(?:env|heapdump|beans))", "Sensitive Spring Boot Actuator Endpoints Publicly Exposed", Severity.HIGH, "CWE-200", "OWASP A05:2021-Security Misconfiguration", "Restrict exposed endpoints to 'health,info' and secure actuator paths.", "T1592"),
    ("java-weak-crypto-ecb", r"Cipher\.getInstance\s*\(\s*['\"]AES/ECB", "Insecure Block Cipher Mode: AES/ECB (Pattern Leakage)", Severity.HIGH, "CWE-327", "OWASP A02:2021-Cryptographic Failures", "Use AES/GCM/NoPadding (authenticated encryption) instead of ECB mode.", "T1110"),

    # PHP
    ("php-rce-exec", r"\b(?:system|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(", "PHP Remote Command Execution Function", Severity.CRITICAL, "CWE-78", "OWASP A03:2021-Injection", "Remove direct shell execution. Use native PHP libraries or escapeshellarg().", "T1059"),
    ("php-eval-code-injection", r"\beval\s*\(\s*\$", "PHP Dynamic Code Execution via eval()", Severity.CRITICAL, "CWE-94", "OWASP A03:2021-Injection", "Refactor away from eval(). Dynamic evaluation of untrusted input leads to complete server takeover.", "T1059"),
    ("php-unserialize", r"\bunserialize\s*\(", "Insecure PHP Object Deserialization (unserialize)", Severity.CRITICAL, "CWE-502", "OWASP A08:2021-Software and Data Integrity Failures", "Replace unserialize() with json_decode(). Never unserialize user-controlled data.", "T1059"),
    ("php-file-inclusion", r"\b(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", "Local / Remote File Inclusion (LFI/RFI) via PHP Include", Severity.CRITICAL, "CWE-98", "OWASP A01:2021-Broken Access Control", "Do not pass user input to include/require. Maintain an explicit allowlist of authorized script files.", "T1190"),
    ("php-sql-injection-raw", r"\bmysqli_query\s*\([^,]+,\s*['\"].*\$", "SQL Injection via mysqli_query with Variable Concatenation", Severity.CRITICAL, "CWE-89", "OWASP A03:2021-Injection", "Use PDO or mysqli prepared statements with bind_param().", "T1190"),
    ("php-xss-echo", r"\becho\s+\$_(?:GET|POST|REQUEST)\[", "Reflected Cross-Site Scripting (XSS) via unescaped PHP echo", Severity.HIGH, "CWE-79", "OWASP A03:2021-Injection", "Wrap output in htmlspecialchars($input, ENT_QUOTES, 'UTF-8').", "T1189"),

    # C# / .NET
    ("dotnet-binary-formatter", r"BinaryFormatter\s*\(\s*\)|NetDataContractSerializer\s*\(", "Insecure .NET Deserialization via BinaryFormatter", Severity.CRITICAL, "CWE-502", "OWASP A08:2021-Software and Data Integrity Failures", "BinaryFormatter is obsoleted due to critical RCE risks. Migrate to System.Text.Json.", "T1059"),
    ("dotnet-sql-injection", r"SqlCommand\s*\(\s*['\"].*['\"]\s*\+|FromSqlRaw\s*\(\s*['\"].*\{", "SQL Injection in .NET SqlCommand / FromSqlRaw", Severity.CRITICAL, "CWE-89", "OWASP A03:2021-Injection", "Use parameterized queries with cmd.Parameters.AddWithValue or FromSqlInterpolated.", "T1190"),
    ("dotnet-cmd-process-start", r"Process\.Start\s*\(\s*['\"]cmd\.exe['\"].*\+", "Command Injection via .NET Process.Start", Severity.HIGH, "CWE-78", "OWASP A03:2021-Injection", "Execute the target executable directly and pass arguments via ProcessStartInfo.ArgumentList.", "T1059"),

    # GO
    ("go-sql-sprintf", r"db\.(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf\(", "SQL Injection via fmt.Sprintf in Go database execution", Severity.CRITICAL, "CWE-89", "OWASP A03:2021-Injection", "Use parameterized placeholders ($1, $2 or ?) in db.Query/Exec.", "T1190"),
    ("go-cmd-injection", r"exec\.Command\s*\(\s*['\"]sh['\"],\s*['\"]-c['\"],", "Command Injection in Go: exec.Command with shell wrapper", Severity.HIGH, "CWE-78", "OWASP A03:2021-Injection", "Invoke the command executable directly with individual argument strings.", "T1059"),
    ("go-insecure-tls", r"InsecureSkipVerify\s*:\s*true", "TLS Verification Disabled in Go (InsecureSkipVerify: true)", Severity.CRITICAL, "CWE-295", "OWASP A02:2021-Cryptographic Failures", "Set InsecureSkipVerify: false to validate remote server SSL certificates.", "T1557"),

    # RUBY
    ("ruby-sql-injection", r"\.(?:where|find_by_sql)\s*\(\s*['\"].*#\{params\[", "SQL Injection via String Interpolation in Ruby on Rails", Severity.CRITICAL, "CWE-89", "OWASP A03:2021-Injection", "Use ActiveRecord parameter binding: Model.where('name = ?', params[:name]).", "T1190"),
    ("ruby-rce-eval", r"\b(?:eval|Kernel\.system)\s*\([^)]*params\[", "Command / Code Execution via eval or Kernel.system in Ruby", Severity.CRITICAL, "CWE-78", "OWASP A03:2021-Injection", "Eliminate eval calls and sanitize all inputs before executing system commands.", "T1059"),

    # C / C++
    ("c-buffer-overflow-strcpy", r"\b(?:strcpy|strcat|sprintf|vsprintf|gets)\s*\(", "Unsafe C/C++ Memory Function (Buffer Overflow Risk)", Severity.HIGH, "CWE-120", "OWASP A03:2021-Injection", "Use bounded string functions: strncpy, snprintf, or std::string in C++.", "T1190"),

    # DOCKER & CONTAINERS
    ("docker-secret-copied", r"(?:COPY|ADD)\s+.*\.(?:env|pem|key|p12|id_rsa)", "Sensitive Credential / Secret Copied into Docker Image", Severity.CRITICAL, "CWE-798", "OWASP A07:2021-Identification and Authentication Failures", "Do not bake secrets or .env files into Docker images. Mount secrets at runtime.", "T1552"),
    ("docker-compose-privileged", r"privileged\s*:\s*true", "Privileged Container Flag Enabled in docker-compose", Severity.CRITICAL, "CWE-250", "OWASP A05:2021-Security Misconfiguration", "Set privileged: false and grant only specific required Linux capabilities.", "T1611"),
    ("docker-compose-root-mount", r"volumes\s*:\s*.*\s*-\s*['\"]?/(?::/|\s)", "Host Root Filesystem Mounted into Container", Severity.CRITICAL, "CWE-269", "OWASP A01:2021-Broken Access Control", "Restrict container mounts to dedicated application directories, never mount '/'", "T1611"),

    # KUBERNETES
    ("k8s-privileged-pod", r"securityContext:\s*.*privileged:\s*true", "Kubernetes Container Configured with Privileged Access", Severity.CRITICAL, "CWE-250", "OWASP A05:2021-Security Misconfiguration", "Set securityContext.privileged: false and enforce Pod Security Admission.", "T1611"),
    ("k8s-host-network", r"hostNetwork:\s*true|hostPID:\s*true", "Kubernetes Host Network / PID Namespace Sharing Enabled", Severity.HIGH, "CWE-269", "OWASP A05:2021-Security Misconfiguration", "Disable hostNetwork and hostPID to isolate container networking and processes.", "T1611"),

    # TERRAFORM / IAC
    ("iac-s3-public-access", r"acl\s*=\s*['\"]public-(?:read|read-write)['\"]|block_public_acls\s*=\s*false", "Publicly Accessible S3 Bucket in Terraform Configuration", Severity.CRITICAL, "CWE-732", "OWASP A05:2021-Security Misconfiguration", "Enforce block_public_acls = true, block_public_policy = true, and ignore_public_acls = true.", "T1530"),
    ("iac-open-security-group", r"cidr_blocks\s*=\s*\[\s*['\"]0\.0\.0\.0/0['\"]\s*\].*(?:22|3389|5432|3306|27017|6379)", "Sensitive Port Open to the Public Internet (0.0.0.0/0)", Severity.HIGH, "CWE-284", "OWASP A05:2021-Security Misconfiguration", "Restrict ingress rules for administrative and database ports.", "T1190"),
    ("iac-unencrypted-db", r"storage_encrypted\s*=\s*false|kms_key_id\s*=\s*['\"]['\"]", "Database / Storage Encryption at Rest Disabled in IaC", Severity.HIGH, "CWE-312", "OWASP A02:2021-Cryptographic Failures", "Enable storage_encrypted = true with a managed KMS key.", "T1530"),

    # CI/CD WORKFLOWS
    ("cicd-untrusted-script-injection", r"run:\s*.*(?:\$\{\{\s*github\.event\.issue\.(?:title|body)\s*\}\}|\$\{\{\s*github\.event\.pull_request\.(?:title|body)\s*\}\})", "GitHub Actions Workflow Script Injection via Untrusted Context", Severity.CRITICAL, "CWE-78", "OWASP A03:2021-Injection", "Set untrusted contexts as environment variables first, then reference in script ($TITLE).", "T1190"),
    ("cicd-write-all-permissions", r"permissions:\s*write-all\b", "Excessive Permissions: write-all Granted to GITHUB_TOKEN", Severity.HIGH, "CWE-250", "OWASP A01:2021-Broken Access Control", "Explicitly specify required read/write permissions (e.g. contents: read, issues: write).", "T1078"),
    ("cicd-pull-request-target", r"on:\s*.*pull_request_target\b", "Insecure pull_request_target Trigger with Potential Code Checkout", Severity.HIGH, "CWE-829", "OWASP A08:2021-Software and Data Integrity Failures", "Avoid checking out PR head ref in pull_request_target workflows to prevent PwnRequest exploits.", "T1195"),

    # RUST
    ("rust-unsafe-transmute", r"mem::transmute\s*(?::<|[(])", "Unchecked Type Transmutation via std::mem::transmute", Severity.HIGH, "CWE-843", "OWASP A08:2021-Software and Data Integrity Failures", "Avoid std::mem::transmute unless strictly verified; prefer safe casting or bytemuck.", "T1190"),
    ("rust-raw-ptr-deref", r"unsafe\s*\{[^}]*\*(?:const|mut)\s+", "Unsafe Raw Pointer Dereference in Rust Code Block", Severity.HIGH, "CWE-119", "OWASP A08:2021-Software and Data Integrity Failures", "Validate pointer non-null and alignment before dereferencing, or use safe abstractions.", "T1190"),

    # ADDITIONAL GO RULES
    ("go-path-traversal", r"os\.Open\s*\(\s*(?:r\.URL\.Query|r\.FormValue|c\.Query|c\.Param)", "Path Traversal via Direct Request Parameter in os.Open", Severity.HIGH, "CWE-22", "OWASP A01:2021-Broken Access Control", "Sanitize path and ensure filepath.Clean resolves strictly within target base directory.", "T1190"),
    ("go-ssrf-http-get", r"http\.Get\s*\(\s*(?:r\.URL\.Query|r\.FormValue|c\.Query|c\.Param)", "Server-Side Request Forgery (SSRF) via Unvalidated http.Get", Severity.HIGH, "CWE-918", "OWASP A10:2021-Server-Side Request Forgery (SSRF)", "Validate host against strict destination allowlist before performing outbound HTTP requests.", "T1190"),

    # ADDITIONAL JAVA / SPRING RULES
    ("java-ssrf-url-open", r"new\s+URL\s*\([^)]*(?:request\.getParameter|req\.getParam|@RequestParam)[^)]*\)\.(?:openStream|openConnection)", "SSRF via new URL().openConnection() with User Input", Severity.HIGH, "CWE-918", "OWASP A10:2021-Server-Side Request Forgery (SSRF)", "Enforce strict URL allowlists and block internal IP addresses (RFC 1918 / 169.254.169.254).", "T1190"),
    ("java-path-traversal", r"new\s+File\s*\([^,)]*,\s*(?:request\.getParameter|req\.getParam)", "Path Traversal via new File() with Request Parameter", Severity.HIGH, "CWE-22", "OWASP A01:2021-Broken Access Control", "Verify canonical path starts with authorized base directory using getCanonicalPath().", "T1190"),

    # ADDITIONAL PHP RULES
    ("php-ssrf-curl", r"curl_setopt\s*\([^,]+,\s*CURLOPT_URL,\s*\$_(?:GET|POST|REQUEST)", "Server-Side Request Forgery (SSRF) via CURLOPT_URL in PHP", Severity.HIGH, "CWE-918", "OWASP A10:2021-Server-Side Request Forgery (SSRF)", "Validate user-supplied URLs against an allowlist and block private IP address ranges.", "T1190"),
    ("php-path-traversal-read", r"(?:file_get_contents|readfile|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST)", "Arbitrary File Read / Path Traversal via PHP File Function", Severity.HIGH, "CWE-22", "OWASP A01:2021-Broken Access Control", "Use basename() and validate file paths against a strict allowlist of static assets.", "T1190"),

    # ADDITIONAL NODE.JS RULES
    ("js-path-traversal-fs", r"fs\.(?:readFile|readFileSync|createReadStream)\s*\([^,)]*(?:req\.params|req\.query|req\.body)", "Path Traversal via fs file operation with User Input", Severity.HIGH, "CWE-22", "OWASP A01:2021-Broken Access Control", "Normalize path with path.normalize() and verify it resides within the safe root directory.", "T1190"),
    ("js-ssrf-axios-fetch", r"(?:axios|fetch|got)\.(?:get|post)\s*\(\s*(?:req\.query|req\.body|req\.params)", "Server-Side Request Forgery (SSRF) via Outbound HTTP Request", Severity.HIGH, "CWE-918", "OWASP A10:2021-Server-Side Request Forgery (SSRF)", "Validate URL scheme, host, and port against an approved outbound destination allowlist.", "T1190"),

    # ADDITIONAL PYTHON RULES
    ("py-open-redirect", r"(?:HttpResponseRedirect|redirect)\s*\(\s*request\.(?:GET|POST)\.get\s*\(\s*['\"](?:next|url|redirect|target)['\"]", "Open Redirect via Unvalidated User-Supplied URL", Severity.MEDIUM, "CWE-601", "OWASP A01:2021-Broken Access Control", "Validate redirect target with url_has_allowed_host_and_scheme() before redirecting.", "T1190"),
    ("py-path-traversal-open", r"open\s*\(\s*(?:os\.path\.join\([^)]*)?request\.(?:GET|POST|query_params)", "Path Traversal via open() with Request Input", Severity.HIGH, "CWE-22", "OWASP A01:2021-Broken Access Control", "Sanitize path and ensure os.path.realpath() stays within authorized folder.", "T1190"),

    # ADDITIONAL C# / .NET RULES
    ("dotnet-xxe-xml-document", r"XmlDocument\s*\(\s*\).*LoadXml\s*\(", "XML External Entity (XXE) Injection in .NET XmlDocument", Severity.HIGH, "CWE-611", "OWASP A05:2021-Security Misconfiguration", "Set XmlResolver = null or use safe XmlReader with DtdProcessing.Prohibit.", "T1190"),
    ("dotnet-path-traversal", r"File\.(?:OpenRead|ReadAllText|ReadAllBytes)\s*\([^)]*(?:Request\.Query|Request\.Form)", "Path Traversal via File access with Request Parameters", Severity.HIGH, "CWE-22", "OWASP A01:2021-Broken Access Control", "Use Path.GetFullPath() and check Path.GetDirectoryName() matches safe base.", "T1190"),
]



# =============================================================================
# 3. MULTI-ECOSYSTEM SOFTWARE COMPOSITION ANALYSIS (SCA)
# =============================================================================

EXTENDED_CVE_DATABASE = {
    "pypi": {
        "django": [
            {"max_vuln": "4.2.4", "cve": "CVE-2023-36053", "sev": Severity.HIGH, "fix": ">=4.2.5", "desc": "Regular Expression Denial of Service (ReDoS) in EmailValidator."},
            {"max_vuln": "4.1.7", "cve": "CVE-2023-24580", "sev": Severity.CRITICAL, "fix": ">=4.1.8", "desc": "Denial of Service via multipart form data request body parsing."},
            {"max_vuln": "3.2.14", "cve": "CVE-2022-34265", "sev": Severity.HIGH, "fix": ">=3.2.15", "desc": "SQL Injection in Trunc() and Extract() database functions."},
        ],
        "requests": [
            {"max_vuln": "2.31.0", "cve": "CVE-2023-32681", "sev": Severity.MEDIUM, "fix": ">=2.32.0", "desc": "Unintended leak of Proxy-Authorization header across redirected domains."},
            {"max_vuln": "2.19.1", "cve": "CVE-2018-18074", "sev": Severity.HIGH, "fix": ">=2.20.0", "desc": "Credentials exposure during HTTP to HTTPS redirects."},
        ],
        "urllib3": [
            {"max_vuln": "2.0.7", "cve": "CVE-2023-45803", "sev": Severity.HIGH, "fix": ">=2.0.8", "desc": "Request body not stripped on HTTP 303 redirect leading to data leakage."},
            {"max_vuln": "1.26.17", "cve": "CVE-2023-43804", "sev": Severity.HIGH, "fix": ">=1.26.18", "desc": "Cookie header not stripped on cross-origin redirects."},
        ],
        "pyyaml": [
            {"max_vuln": "5.4.0", "cve": "CVE-2020-14343", "sev": Severity.CRITICAL, "fix": ">=5.4.1", "desc": "Arbitrary Code Execution via FullLoader/load function."},
        ],
        "flask": [
            {"max_vuln": "2.2.5", "cve": "CVE-2023-30861", "sev": Severity.HIGH, "fix": ">=2.3.0", "desc": "Cookie disclosure when caching proxies are placed in front of Flask."},
        ],
        "jinja2": [
            {"max_vuln": "3.1.2", "cve": "CVE-2024-22195", "sev": Severity.HIGH, "fix": ">=3.1.3", "desc": "HTML attribute injection and Cross-Site Scripting (XSS) via xmlattr filter."},
        ],
        "cryptography": [
            {"max_vuln": "41.0.5", "cve": "CVE-2023-49083", "sev": Severity.HIGH, "fix": ">=41.0.6", "desc": "NULL pointer dereference when loading PKCS7 certificates."},
        ],
        "werkzeug": [
            {"max_vuln": "2.2.3", "cve": "CVE-2023-25577", "sev": Severity.HIGH, "fix": ">=2.2.4", "desc": "High CPU utilization DoS when parsing multipart form data with many parts."},
        ],
        "fastapi": [
            {"max_vuln": "0.65.1", "cve": "CVE-2021-32677", "sev": Severity.MEDIUM, "fix": ">=0.65.2", "desc": "Header authorization bypass when using OAuth2 with multiple scopes."},
        ],
    },
    "npm": {
        "lodash": [
            {"max_vuln": "4.17.20", "cve": "CVE-2021-23337", "sev": Severity.HIGH, "fix": "^4.17.21", "desc": "Command Injection via template function variable interpolation."},
            {"max_vuln": "4.17.15", "cve": "CVE-2019-10744", "sev": Severity.CRITICAL, "fix": "^4.17.16", "desc": "Prototype Pollution in defaultsDeep leading to remote code execution."},
        ],
        "axios": [
            {"max_vuln": "0.21.1", "cve": "CVE-2021-3749", "sev": Severity.HIGH, "fix": ">=0.21.2", "desc": "SSRF vulnerability via follow-redirects package."},
            {"max_vuln": "1.5.1", "cve": "CVE-2023-45857", "sev": Severity.HIGH, "fix": ">=1.6.0", "desc": "XSRF token leak in cross-origin requests."},
        ],
        "jsonwebtoken": [
            {"max_vuln": "8.5.1", "cve": "CVE-2022-23529", "sev": Severity.CRITICAL, "fix": ">=9.0.0", "desc": "Remote Code Execution via crafted secret key in jwt.verify."},
            {"max_vuln": "8.5.1", "cve": "CVE-2022-23540", "sev": Severity.HIGH, "fix": ">=9.0.0", "desc": "Signature validation bypass with asymmetric key types."},
        ],
        "minimist": [
            {"max_vuln": "1.2.5", "cve": "CVE-2021-44906", "sev": Severity.CRITICAL, "fix": ">=1.2.6", "desc": "Prototype Pollution via crafted command line arguments."},
        ],
        "express": [
            {"max_vuln": "4.18.2", "cve": "CVE-2024-29041", "sev": Severity.MEDIUM, "fix": ">=4.19.2", "desc": "Open Redirect via malformed URLs in res.redirect()."},
        ],
        "fast-xml-parser": [
            {"max_vuln": "4.3.4", "cve": "CVE-2024-41818", "sev": Severity.HIGH, "fix": ">=4.4.1", "desc": "ReDoS and entity expansion causing denial of service."},
        ],
    },
    "maven": {
        "log4j-core": [
            {"max_vuln": "2.14.1", "cve": "CVE-2021-44228", "sev": Severity.CRITICAL, "fix": ">=2.17.1", "desc": "Log4Shell: Remote Code Execution via JNDI message lookup."},
        ],
        "spring-core": [
            {"max_vuln": "5.3.17", "cve": "CVE-2022-22965", "sev": Severity.CRITICAL, "fix": ">=5.3.18", "desc": "Spring4Shell: Remote Code Execution via Data Binding on JDK 9+."},
        ],
        "commons-text": [
            {"max_vuln": "1.9", "cve": "CVE-2022-42889", "sev": Severity.CRITICAL, "fix": ">=1.10.0", "desc": "Text4Shell: Arbitrary Code Execution via StringSubstitutor interpolator."},
        ],
        "jackson-databind": [
            {"max_vuln": "2.13.2.1", "cve": "CVE-2022-42003", "sev": Severity.HIGH, "fix": ">=2.13.4", "desc": "Resource exhaustion DoS via deeply nested JSON arrays."},
        ],
    },
    "composer": {
        "laravel/framework": [
            {"max_vuln": "9.1.8", "cve": "CVE-2022-40482", "sev": Severity.HIGH, "fix": ">=9.1.9", "desc": "Authentication bypass via cookie serialization weakness."},
        ],
        "guzzlehttp/guzzle": [
            {"max_vuln": "7.4.4", "cve": "CVE-2022-31090", "sev": Severity.HIGH, "fix": ">=7.4.5", "desc": "CURLOPT_HTTPAUTH header leakage across redirected requests."},
        ],
        "twig/twig": [
            {"max_vuln": "3.3.9", "cve": "CVE-2022-24894", "sev": Severity.HIGH, "fix": ">=3.3.10", "desc": "Code execution via sort filter using custom closure."},
        ],
    },
    "golang": {
        "golang.org/x/crypto": [
            {"max_vuln": "0.0.0-20211202192323", "cve": "CVE-2022-27191", "sev": Severity.HIGH, "fix": ">=0.0.0-20220315160706", "desc": "Denial of Service in ssh.Signer with crafted private keys."},
        ],
        "github.com/gin-gonic/gin": [
            {"max_vuln": "1.7.7", "cve": "CVE-2020-28483", "sev": Severity.HIGH, "fix": ">=1.8.0", "desc": "Directory traversal via Context.FileAttachment()."},
        ],
    },
    "gem": {
        "rails": [
            {"max_vuln": "7.0.4", "cve": "CVE-2023-22795", "sev": Severity.HIGH, "fix": ">=7.0.4.1", "desc": "ReDoS vulnerability in Action Dispatch parameter parsing."},
        ],
        "nokogiri": [
            {"max_vuln": "1.13.9", "cve": "CVE-2022-23476", "sev": Severity.HIGH, "fix": ">=1.13.10", "desc": "Out-of-bounds read in libxml2 packaging."},
        ],
    },
    "cargo": {
        "openssl": [
            {"max_vuln": "0.10.47", "cve": "CVE-2022-37454", "sev": Severity.HIGH, "fix": ">=0.10.48", "desc": "Buffer overflow in SHA-3 implementation."},
        ],
    },
    "nuget": {
        "newtonsoft.json": [
            {"max_vuln": "12.0.3", "cve": "CVE-2024-21907", "sev": Severity.HIGH, "fix": ">=13.0.1", "desc": "Denial of service via deeply nested JSON structures."},
        ],
    }
}


# =============================================================================
# 4. UNIVERSAL MULTI-TECH SCANNER CLASS
# =============================================================================

class UniversalMultiTechScanner:
    """Executes multi-language SAST, SCA, Secrets, and IaC security audits."""

    def __init__(self, parent_stage):
        self.parent = parent_stage

    def scan_all(self, target_path: str) -> Tuple[List[Finding], List[SBOMComponent], Dict[str, Any]]:
        all_findings: List[Finding] = []
        all_components: List[SBOMComponent] = []

        if not os.path.exists(target_path):
            return all_findings, all_components, {}

        # 1. Tech stack profile
        tech_profile = TechStackDetector.detect(target_path)

        # 2. Multi-language SAST scan
        sast_findings = self._scan_sast_multi_lang(target_path)
        all_findings.extend(sast_findings)

        # 3. Multi-ecosystem SCA scan
        sca_findings, components = self._scan_sca_multi_ecosystem(target_path)
        all_findings.extend(sca_findings)
        all_components.extend(components)

        # 4. Multi-cloud IaC & Container scan
        iac_findings = self._scan_iac_and_containers(target_path)
        all_findings.extend(iac_findings)

        # 5. Shannon Entropy & Deep Secrets scan
        secret_findings = self._scan_deep_secrets(target_path)
        all_findings.extend(secret_findings)

        # 6. Web Server & Reverse Proxy Configuration scan
        server_findings = self._scan_web_servers_and_configs(target_path)
        all_findings.extend(server_findings)

        summary = {
            "tech_profile": tech_profile,
            "sast_count": len(sast_findings),
            "sca_count": len(sca_findings),
            "iac_count": len(iac_findings),
            "secrets_count": len(secret_findings),
            "server_configs_count": len(server_findings),
            "total_components": len(all_components),
            "total_findings": len(all_findings),
        }

        return all_findings, all_components, summary


    # Directories excluded from SAST scanning (vendor, generated, env, build)
    _SAST_EXCLUDE_DIRS = frozenset({
        ".git", "node_modules", "venv", ".venv", "__pycache__",
        "target", "bin", "obj", "vendor", "dist", "build", ".next",
        ".nuxt", "out", "coverage", "htmlcov", ".pytest_cache",
        "migrations", "static", "media", "public", "assets",
        ".tox", "eggs", ".eggs", "bower_components", "jspm_packages",
        ".yarn", "stubs", "typings", ".cache", "tmp", ".turbo",
    })

    @classmethod
    def is_excluded_dir(cls, d: str) -> bool:
        dl = d.lower()
        if dl in cls._SAST_EXCLUDE_DIRS:
            return True
        if dl.startswith(("venv", ".venv", "virtualenv", "env-", ".env-", "node_modules")) or dl.endswith(("-venv", "-env", "_venv", "_env")):
            return True
        if dl in ("env", ".env", "logs", "log", ".log", "fixtures", "test_fixtures"):
            return True
        return False

    def _scan_sast_multi_lang(self, target_path: str) -> List[Finding]:
        """
        Multi-language SAST scan with smart deduplication:
        - Same rule fires at most once per file (first match wins)
        - Global cap: max 5 findings per rule across the entire scan
        - Skips generated/minified files and excluded directories
        """
        findings = []
        scanned_exts = (
            ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
            ".java", ".kt", ".kts", ".php", ".phtml",
            ".cs", ".go", ".rb", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp",
            ".sh", ".bash", ".zsh", ".yaml", ".yml", ".tf"
        )

        # Per-rule global cap tracker
        rule_global_count: dict = {}
        MAX_PER_RULE = 5

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not self.is_excluded_dir(d)]
            for fname in files:
                # Skip minified / bundled / lock files
                if fname.endswith((".min.js", ".min.css", ".bundle.js",
                                   ".chunk.js", ".map", ".snap", "._.js")):
                    continue
                if not (fname.lower().endswith(scanned_exts) or
                        fname in ("Dockerfile", "Jenkinsfile")):
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, target_path)

                try:
                    if os.path.getsize(fpath) > 500_000:  # skip files > 500 KB
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fl:
                        lines = fl.readlines()

                    # Per-file dedup: track which rules already fired in this file
                    fired_in_file: set = set()

                    for line_no, line in enumerate(lines, 1):
                        line_str = line.strip()
                        if not line_str or line_str.startswith(
                                ("#", "//", "/*", "*", "--")):
                            continue

                        for r_id, pat, title, sev, cwe, owasp, fix, mitre in MULTI_LANG_RULES:
                            # One hit per rule per file
                            if r_id in fired_in_file:
                                continue
                            # Global cap per rule
                            if rule_global_count.get(r_id, 0) >= MAX_PER_RULE:
                                continue

                            if re.search(pat, line):
                                fired_in_file.add(r_id)
                                rule_global_count[r_id] = rule_global_count.get(r_id, 0) + 1

                                f_obj = self.parent.create_finding(
                                    finding_id=f"SAST-{r_id.upper()}-{len(findings)+1:03d}",
                                    title=title,
                                    severity=sev,
                                    description=(
                                        f"Static analysis identified security pattern `{r_id}` "
                                        f"in {rel_path}:{line_no}."
                                    ),
                                    tool="DKSec Universal SAST Engine",
                                    file_path=rel_path,
                                    line_number=line_no,
                                    code_snippet=line_str[:160],
                                    cwe=cwe,
                                    owasp=owasp,
                                    remediation=fix,
                                    status=FindingStatus.OPEN
                                )
                                f_obj.mitre_attack = mitre
                                findings.append(f_obj)

                except Exception:
                    pass

        return findings

    def _scan_sca_multi_ecosystem(self, target_path: str) -> Tuple[List[Finding], List[SBOMComponent]]:
        findings = []
        components = []

        # Parser 1: Python requirements.txt
        req_file = os.path.join(target_path, "requirements.txt")
        if os.path.exists(req_file):
            try:
                with open(req_file, "r", errors="ignore") as f:
                    for line_no, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = re.split(r"==|>=|<=|~=", line)
                            pkg = parts[0].strip().lower()
                            ver = parts[1].strip() if len(parts) > 1 else "1.0.0"
                            purl = f"pkg:pypi/{pkg}@{ver}"
                            comp = SBOMComponent(name=pkg, version=ver, purl=purl, ecosystem="pypi", license="MIT")
                            components.append(comp)
                            self._check_advisory("pypi", pkg, ver, "requirements.txt", line_no, line, findings)
            except Exception:
                pass

        # Parser 2: Node.js package.json
        pkg_file = os.path.join(target_path, "package.json")
        if os.path.exists(pkg_file):
            try:
                with open(pkg_file, "r", errors="ignore") as f:
                    data = json.load(f)
                all_deps = {}
                all_deps.update(data.get("dependencies", {}))
                all_deps.update(data.get("devDependencies", {}))
                for pkg, ver_raw in all_deps.items():
                    clean_ver = re.sub(r"[\^~>=<]", "", str(ver_raw))
                    purl = f"pkg:npm/{pkg}@{clean_ver}"
                    comp = SBOMComponent(name=pkg, version=clean_ver, purl=purl, ecosystem="npm", license="Apache-2.0")
                    components.append(comp)
                    self._check_advisory("npm", pkg, clean_ver, "package.json", 0, f'"{pkg}": "{ver_raw}"', findings)
            except Exception:
                pass

        # Parser 3: Java Maven pom.xml
        pom_file = os.path.join(target_path, "pom.xml")
        if os.path.exists(pom_file):
            try:
                with open(pom_file, "r", errors="ignore") as f:
                    content = f.read()
                dep_blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
                for block in dep_blocks:
                    art_m = re.search(r"<artifactId>(.*?)</artifactId>", block)
                    ver_m = re.search(r"<version>(.*?)</version>", block)
                    if art_m:
                        pkg = art_m.group(1).strip()
                        ver = ver_m.group(1).strip() if ver_m else "1.0.0"
                        purl = f"pkg:maven/{pkg}@{ver}"
                        components.append(SBOMComponent(name=pkg, version=ver, purl=purl, ecosystem="maven", license="Apache-2.0"))
                        self._check_advisory("maven", pkg, ver, "pom.xml", 0, f"<artifactId>{pkg}</artifactId>", findings)
            except Exception:
                pass

        # Parser 4: PHP Composer composer.json
        comp_file = os.path.join(target_path, "composer.json")
        if os.path.exists(comp_file):
            try:
                with open(comp_file, "r", errors="ignore") as f:
                    data = json.load(f)
                all_deps = {}
                all_deps.update(data.get("require", {}))
                all_deps.update(data.get("require-dev", {}))
                for pkg, ver_raw in all_deps.items():
                    clean_ver = re.sub(r"[\^~>=<]", "", str(ver_raw))
                    purl = f"pkg:composer/{pkg}@{clean_ver}"
                    components.append(SBOMComponent(name=pkg, version=clean_ver, purl=purl, ecosystem="composer", license="MIT"))
                    self._check_advisory("composer", pkg, clean_ver, "composer.json", 0, f'"{pkg}": "{ver_raw}"', findings)
            except Exception:
                pass

        # Parser 5: Go go.mod
        go_mod_file = os.path.join(target_path, "go.mod")
        if os.path.exists(go_mod_file):
            try:
                with open(go_mod_file, "r", errors="ignore") as f:
                    for line_no, line in enumerate(f, 1):
                        m = re.search(r"^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+)\s+v([0-9a-zA-Z.\-_+]+)", line)
                        if m:
                            pkg = m.group(1)
                            ver = m.group(2)
                            purl = f"pkg:golang/{pkg}@{ver}"
                            components.append(SBOMComponent(name=pkg, version=ver, purl=purl, ecosystem="golang", license="BSD-3-Clause"))
                            self._check_advisory("golang", pkg, ver, "go.mod", line_no, line.strip(), findings)
            except Exception:
                pass

        # Parser 6: Ruby Gemfile
        gem_file = os.path.join(target_path, "Gemfile")
        if os.path.exists(gem_file):
            try:
                with open(gem_file, "r", errors="ignore") as f:
                    for line_no, line in enumerate(f, 1):
                        m = re.search(r"gem\s+['\"]([a-zA-Z0-9_\-]+)['\"](?:,\s*['\"]([~>=<\s0-9.]+)['\"])?", line)
                        if m:
                            pkg = m.group(1)
                            ver = re.sub(r"[\^~>=<\s]", "", m.group(2) or "1.0.0")
                            purl = f"pkg:gem/{pkg}@{ver}"
                            components.append(SBOMComponent(name=pkg, version=ver, purl=purl, ecosystem="gem", license="MIT"))
                            self._check_advisory("gem", pkg, ver, "Gemfile", line_no, line.strip(), findings)
            except Exception:
                pass

        # Parser 7: Rust Cargo.toml
        cargo_file = os.path.join(target_path, "Cargo.toml")
        if os.path.exists(cargo_file):
            try:
                with open(cargo_file, "r", errors="ignore") as f:
                    in_deps = False
                    for line_no, line in enumerate(f, 1):
                        raw = line.strip()
                        if raw.startswith("[dependencies]") or raw.startswith("[dev-dependencies]"):
                            in_deps = True
                            continue
                        elif raw.startswith("[") and in_deps:
                            in_deps = False
                        if in_deps and raw and not raw.startswith("#"):
                            m = re.search(r"^([a-zA-Z0-9_\-]+)\s*=\s*(?:['\"]([^'\"]+)['\"]|\{\s*version\s*=\s*['\"]([^'\"]+)['\"])", raw)
                            if m:
                                pkg = m.group(1).lower()
                                ver_raw = m.group(2) or m.group(3) or "1.0.0"
                                clean_ver = re.sub(r"[\^~>=<\s]", "", ver_raw)
                                purl = f"pkg:cargo/{pkg}@{clean_ver}"
                                components.append(SBOMComponent(name=pkg, version=clean_ver, purl=purl, ecosystem="cargo", license="MIT"))
                                self._check_advisory("cargo", pkg, clean_ver, "Cargo.toml", line_no, raw, findings)
            except Exception:
                pass

        # Parser 8: .NET / C# (*.csproj & packages.config)
        for root_p, _, fls in os.walk(target_path):
            fls[:] = [f for f in fls if f.endswith(".csproj") or f == "packages.config"]
            for fl_name in fls:
                fpath = os.path.join(root_p, fl_name)
                rel_fpath = os.path.relpath(fpath, target_path)
                try:
                    with open(fpath, "r", errors="ignore") as fl:
                        content = fl.read()
                    # PackageReference in csproj
                    refs = re.findall(r'<PackageReference\s+Include=["\']([^"\']+)["\'](?:\s+Version=["\']([^"\']+)["\'])?', content)
                    for pkg_name, ver_val in refs:
                        clean_ver = re.sub(r"[\^~>=<\s]", "", ver_val or "1.0.0")
                        purl = f"pkg:nuget/{pkg_name.lower()}@{clean_ver}"
                        components.append(SBOMComponent(name=pkg_name, version=clean_ver, purl=purl, ecosystem="nuget", license="MIT"))
                        self._check_advisory("nuget", pkg_name, clean_ver, rel_fpath, 0, f'<PackageReference Include="{pkg_name}" Version="{ver_val}"/>', findings)
                    # packages.config
                    p_refs = re.findall(r'<package\s+id=["\']([^"\']+)["\']\s+version=["\']([^"\']+)["\']', content)
                    for pkg_name, ver_val in p_refs:
                        clean_ver = re.sub(r"[\^~>=<\s]", "", ver_val or "1.0.0")
                        purl = f"pkg:nuget/{pkg_name.lower()}@{clean_ver}"
                        components.append(SBOMComponent(name=pkg_name, version=clean_ver, purl=purl, ecosystem="nuget", license="MIT"))
                        self._check_advisory("nuget", pkg_name, clean_ver, rel_fpath, 0, f'<package id="{pkg_name}" version="{ver_val}"/>', findings)
                except Exception:
                    pass

        # Parser 9: Python Pipfile & pyproject.toml
        pipfile = os.path.join(target_path, "Pipfile")
        if os.path.exists(pipfile):
            try:
                with open(pipfile, "r", errors="ignore") as f:
                    in_packages = False
                    for line_no, line in enumerate(f, 1):
                        raw = line.strip()
                        if raw in ("[packages]", "[dev-packages]"):
                            in_packages = True
                            continue
                        elif raw.startswith("["):
                            in_packages = False
                        if in_packages and raw and not raw.startswith("#"):
                            m = re.search(r"^([a-zA-Z0-9_\-]+)\s*=\s*['\"]([^'\"]+)['\"]", raw)
                            if m:
                                pkg = m.group(1).lower()
                                ver = re.sub(r"[\^~>=<\s]", "", m.group(2)) or "1.0.0"
                                purl = f"pkg:pypi/{pkg}@{ver}"
                                components.append(SBOMComponent(name=pkg, version=ver, purl=purl, ecosystem="pypi", license="MIT"))
                                self._check_advisory("pypi", pkg, ver, "Pipfile", line_no, raw, findings)
            except Exception:
                pass

        pyproject = os.path.join(target_path, "pyproject.toml")
        if os.path.exists(pyproject):
            try:
                with open(pyproject, "r", errors="ignore") as f:
                    for line_no, line in enumerate(f, 1):
                        m = re.search(r'["\']([a-zA-Z0-9_\-]+)(?:==|>=|<=|~=)([0-9a-zA-Z.\-_+]+)["\']', line)
                        if m:
                            pkg = m.group(1).lower()
                            ver = m.group(2)
                            purl = f"pkg:pypi/{pkg}@{ver}"
                            components.append(SBOMComponent(name=pkg, version=ver, purl=purl, ecosystem="pypi", license="MIT"))
                            self._check_advisory("pypi", pkg, ver, "pyproject.toml", line_no, line.strip(), findings)
            except Exception:
                pass

        return findings, components


    def _check_advisory(self, ecosystem: str, pkg: str, ver: str, file_path: str, line_no: int, snippet: str, findings: List[Finding]):
        db = EXTENDED_CVE_DATABASE.get(ecosystem, {})
        pkg_lower = pkg.lower()
        if pkg_lower in db:
            for adv in db[pkg_lower]:
                # --- Version gating: only flag if installed version is still vulnerable ---
                if ver and ver != "1.0.0" and not _is_version_vulnerable(ver, adv["max_vuln"]):
                    # Installed version is NEWER than max-vulnerable; CVE is already patched
                    continue
                f_obj = self.parent.create_finding(
                    finding_id=f"SCA-{adv['cve']}",
                    title=f"Vulnerable Dependency: {pkg}@{ver} ({adv['cve']})",
                    severity=adv["sev"],
                    description=f"{ecosystem.upper()} package '{pkg}' version {ver} is vulnerable to {adv['desc']}",
                    tool="DKSec Universal SCA Engine",
                    file_path=file_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    cwe="CWE-1395",
                    owasp="OWASP A06:2021-Vulnerable and Outdated Components",
                    remediation=f"Upgrade {pkg} to version {adv['fix']}.",
                    status=FindingStatus.OPEN,
                    references=[f"https://nvd.nist.gov/vuln/detail/{adv['cve']}"]
                )
                f_obj.mitre_attack = "T1190"
                findings.append(f_obj)

    def _scan_iac_and_containers(self, target_path: str) -> List[Finding]:
        findings = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "venv", ".venv"]]
            for f in files:
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, target_path)

                if f.lower().startswith("dockerfile"):
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            lines = fl.readlines()
                        has_user = False
                        for line_no, line in enumerate(lines, 1):
                            if line.strip().upper().startswith("USER "):
                                has_user = True
                            if re.search(r"FROM\s+.*:latest\b", line, re.IGNORECASE):
                                findings.append(self.parent.create_finding(
                                    finding_id=f"IAC-DOCKER-LATEST-{len(findings)+1:03d}",
                                    title="Docker Image Uses Mutable ':latest' Tag",
                                    severity=Severity.MEDIUM,
                                    description="Using ':latest' creates non-deterministic builds and may pull unverified changes.",
                                    tool="DKSec Container Auditor",
                                    file_path=rel_path,
                                    line_number=line_no,
                                    code_snippet=line.strip(),
                                    cwe="CWE-1188",
                                    owasp="OWASP A05:2021-Security Misconfiguration",
                                    remediation="Pin base image to an immutable SHA-256 digest or explicit semantic version tag."
                                ))
                        if not has_user and len(lines) > 5:
                            findings.append(self.parent.create_finding(
                                finding_id=f"IAC-DOCKER-ROOT-{len(findings)+1:03d}",
                                title="Dockerfile Missing Non-Root USER Directive",
                                severity=Severity.MEDIUM,
                                description="Containers executing as default root increase the impact of container escape vulnerabilities.",
                                tool="DKSec Container Auditor",
                                file_path=rel_path,
                                line_number=1,
                                cwe="CWE-250",
                                owasp="OWASP A05:2021-Security Misconfiguration",
                                remediation="Add a non-root user (e.g. 'USER appuser') before the ENTRYPOINT or CMD instruction."
                            ))
                    except Exception:
                        pass
        return findings

    def _scan_deep_secrets(self, target_path: str) -> List[Finding]:
        findings = []
        secret_patterns = [
            ("AWS Access Key ID", r"\bAKIA[0-9A-Z]{16}\b", Severity.CRITICAL, "CWE-798", "T1552"),
            ("AWS Secret Key Assignment", r"(?:aws_secret_access_key|aws_secret_key)\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", Severity.CRITICAL, "CWE-798", "T1552"),
            ("GitHub Personal Access Token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b", Severity.CRITICAL, "CWE-798", "T1552"),
            ("GitLab Personal Access Token", r"\bglpat-[0-9a-zA-Z_\-]{20,}\b", Severity.CRITICAL, "CWE-798", "T1552"),
            ("Slack Bot / User Token", r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b", Severity.CRITICAL, "CWE-798", "T1552"),
            ("Stripe Live Secret Key", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b", Severity.CRITICAL, "CWE-798", "T1552"),
            ("OpenAI API Key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b", Severity.CRITICAL, "CWE-798", "T1552"),
            ("Private Key Block Header", r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----", Severity.CRITICAL, "CWE-798", "T1552"),
            ("Database Connection String with Password", r"(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^:]+:[^@]+@[a-zA-Z0-9.\-_]+", Severity.HIGH, "CWE-798", "T1552"),
            ("Hardcoded JWT Token", r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b", Severity.HIGH, "CWE-798", "T1552"),
        ]

        # Global cap per secret label to avoid flooding
        label_global_count: dict = {}
        MAX_PER_LABEL = 3

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not self.is_excluded_dir(d)]
            for f in files:
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, target_path)

                if f.endswith((".pyc", ".png", ".jpg", ".jpeg", ".ico", ".svg",
                               ".zip", ".tar", ".gz", ".sqlite3", ".db",
                               ".min.js", ".map", ".snap", ".lock", "._.js")):
                    continue

                try:
                    if os.path.getsize(fpath) > 500000:
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fl:
                        # Per-file dedup: each label fires at most once per file
                        fired_in_file: set = set()
                        for line_no, line in enumerate(fl, 1):
                            line_str = line.strip()
                            if not line_str:
                                continue
                            for label, regex, sev, cwe, mitre in secret_patterns:
                                if label in fired_in_file:
                                    continue
                                if label_global_count.get(label, 0) >= MAX_PER_LABEL:
                                    continue
                                match = re.search(regex, line_str)
                                if match:
                                    fired_in_file.add(label)
                                    label_global_count[label] = label_global_count.get(label, 0) + 1
                                    matched_val = match.group(0)
                                    masked = matched_val[:4] + "*" * (len(matched_val) - 8) + matched_val[-4:] if len(matched_val) > 8 else "***"
                                    f_obj = self.parent.create_finding(
                                        finding_id=f"SEC-{len(findings)+1:03d}",
                                        title=f"Exposed Secret: {label}",
                                        severity=sev,
                                        description=f"Hardcoded sensitive credential ({label}) discovered in {rel_path}:{line_no} [{masked}].",
                                        tool="DKSec Deep Secret Scanner",
                                        file_path=rel_path,
                                        line_number=line_no,
                                        code_snippet=line_str[:120].replace(matched_val, masked),
                                        cwe=cwe,
                                        owasp="OWASP A07:2021-Identification and Authentication Failures",
                                        remediation="Revoke exposed credential immediately. Store secret in an environment variable or secrets manager.",
                                        status=FindingStatus.OPEN
                                    )
                                    f_obj.mitre_attack = mitre
                                    findings.append(f_obj)
                except Exception:
                    pass
        return findings

    def _scan_web_servers_and_configs(self, target_path: str) -> List[Finding]:
        """Audits web server, reverse proxy, and environment configurations for security misconfigurations."""
        findings = []

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not self.is_excluded_dir(d)]
            for f in files:
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, target_path)
                f_lower = f.lower()

                # --- 1. Nginx Configuration Audit ---
                if "nginx" in f_lower or f_lower.endswith(".conf") or "sites-available" in root or "sites-enabled" in root or "conf.d" in root:
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            content = fl.read()

                        # Insecure SSL protocols
                        if re.search(r"ssl_protocols\s+[^;]*(?:SSLv2|SSLv3|TLSv1\b|TLSv1\.1\b)", content, re.IGNORECASE):
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-NGINX-SSL-{len(findings)+1:03d}",
                                title="Nginx Insecure Legacy TLS/SSL Protocols Enabled",
                                severity=Severity.HIGH,
                                description="Nginx configuration enables obsolete SSLv3, TLSv1.0, or TLSv1.1 protocols vulnerable to POODLE and BEAST attacks.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                code_snippet=re.search(r"ssl_protocols\s+[^;]+;", content).group(0) if re.search(r"ssl_protocols\s+[^;]+;", content) else "ssl_protocols",
                                cwe="CWE-326",
                                owasp="OWASP A02:2021-Cryptographic Failures",
                                remediation="Configure 'ssl_protocols TLSv1.2 TLSv1.3;' to only allow modern secure ciphers.",
                                status=FindingStatus.OPEN,
                                references=["https://ssl-config.mozilla.org/"]
                            ))

                        # Insecure CORS header reflection
                        if re.search(r"add_header\s+['\"]?Access-Control-Allow-Origin['\"]?\s+\$http_origin", content, re.IGNORECASE):
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-NGINX-CORS-{len(findings)+1:03d}",
                                title="Nginx Insecure CORS Header Reflection ($http_origin)",
                                severity=Severity.HIGH,
                                description="Nginx dynamically echoes incoming Origin headers without allowlist verification, allowing cross-origin data exfiltration.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                code_snippet="add_header 'Access-Control-Allow-Origin' $http_origin;",
                                cwe="CWE-942",
                                owasp="OWASP A01:2021-Broken Access Control",
                                remediation="Validate origin against an explicit map allowlist before setting Access-Control-Allow-Origin.",
                                status=FindingStatus.OPEN,
                                references=["https://portswigger.net/web-security/cors"]
                            ))

                        # Autoindex / Directory Listing enabled
                        if re.search(r"\bautoindex\s+on\b", content, re.IGNORECASE):
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-NGINX-AUTOINDEX-{len(findings)+1:03d}",
                                title="Nginx Directory Listing Enabled (autoindex on)",
                                severity=Severity.MEDIUM,
                                description="Directory indexing is explicitly turned on, exposing server files and folder structures to unauthenticated visitors.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                code_snippet="autoindex on;",
                                cwe="CWE-548",
                                owasp="OWASP A05:2021-Security Misconfiguration",
                                remediation="Set 'autoindex off;' in all server and location blocks.",
                                status=FindingStatus.OPEN,
                                references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Server_Configuration"]
                            ))

                        # Off-by-slash reverse proxy traversal
                        if re.search(r"location\s+/[a-zA-Z0-9_\-]+[^\s/{]*\s*\{[^}]*proxy_pass\s+http[s]?://[^/;\s]+/[^;]*;", content):
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-NGINX-SLASH-{len(findings)+1:03d}",
                                title="Nginx Reverse Proxy Off-by-Slash Path Traversal Risk",
                                severity=Severity.HIGH,
                                description="Nginx location directive missing trailing slash while proxy_pass specifies a trailing slash, enabling path traversal to upstream services.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                cwe="CWE-22",
                                owasp="OWASP A01:2021-Broken Access Control",
                                remediation="Ensure both location and proxy_pass directives either consistently have a trailing slash or neither has one.",
                                status=FindingStatus.OPEN,
                                references=["https://www.acunetix.com/vulnerabilities/web/nginx-alias-traversal/"]
                            ))
                    except Exception:
                        pass

                # --- 2. Apache HTTP Server Configuration Audit ---
                if f_lower in ("httpd.conf", "apache2.conf", ".htaccess") or f_lower.endswith(".htaccess"):
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            content = fl.read()

                        if re.search(r"Options\s+.*(?:\+)?Indexes\b", content, re.IGNORECASE) and not re.search(r"Options\s+.*-Indexes\b", content, re.IGNORECASE):
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-APACHE-INDEX-{len(findings)+1:03d}",
                                title="Apache Directory Indexing (Indexes) Enabled",
                                severity=Severity.MEDIUM,
                                description="Apache Options directive enables directory indexing, exposing raw file structures to visitors.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                cwe="CWE-548",
                                owasp="OWASP A05:2021-Security Misconfiguration",
                                remediation="Specify 'Options -Indexes' in httpd.conf or .htaccess.",
                                status=FindingStatus.OPEN
                            ))

                        if re.search(r"AllowOverride\s+All\b", content, re.IGNORECASE):
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-APACHE-OVERRIDE-{len(findings)+1:03d}",
                                title="Overly Permissive Apache AllowOverride All",
                                severity=Severity.LOW,
                                description="AllowOverride All allows local .htaccess files to override any server directive, increasing attack surface.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                cwe="CWE-284",
                                owasp="OWASP A05:2021-Security Misconfiguration",
                                remediation="Restrict AllowOverride to specific directives (e.g. 'AllowOverride None' or 'AllowOverride AuthConfig').",
                                status=FindingStatus.OPEN
                            ))
                    except Exception:
                        pass

                # --- 3. IIS web.config Audit ---
                if f_lower == "web.config":
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            content = fl.read()
                        if re.search(r"customErrors\s+mode\s*=\s*['\"]Off['\"]", content, re.IGNORECASE):
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-IIS-ERRORS-{len(findings)+1:03d}",
                                title="IIS ASP.NET Custom Errors Disabled (mode='Off')",
                                severity=Severity.HIGH,
                                description="Disabling customErrors reveals detailed stack traces, system paths, and source lines to remote attackers.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                cwe="CWE-209",
                                owasp="OWASP A05:2021-Security Misconfiguration",
                                remediation="Set <customErrors mode='On'/> or mode='RemoteOnly' in web.config.",
                                status=FindingStatus.OPEN
                            ))
                        if re.search(r"compilation\s+debug\s*=\s*['\"]true['\"]", content, re.IGNORECASE):
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-IIS-DEBUG-{len(findings)+1:03d}",
                                title="IIS ASP.NET Production Compilation Debug Enabled",
                                severity=Severity.MEDIUM,
                                description="Running with debug='true' degrades performance and exposes internal execution metadata.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                cwe="CWE-489",
                                owasp="OWASP A05:2021-Security Misconfiguration",
                                remediation="Set <compilation debug='false'/> in production web.config.",
                                status=FindingStatus.OPEN
                            ))
                    except Exception:
                        pass

                # --- 4. Caddyfile Audit ---
                if f_lower == "caddyfile":
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            content = fl.read()
                        if re.search(r"admin\s+(?:0\.0\.0\.0(?::\d+)?|:\d+)", content, re.IGNORECASE):
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-CADDY-ADMIN-{len(findings)+1:03d}",
                                title="Caddy Admin API Exposed to Non-Loopback Network",
                                severity=Severity.HIGH,
                                description="Caddy administration endpoint configured on public IP address without loopback binding, allowing remote reconfiguration.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                cwe="CWE-306",
                                owasp="OWASP A05:2021-Security Misconfiguration",
                                remediation="Bind Caddy admin API exclusively to localhost (admin localhost:2019) or disable if unused.",
                                status=FindingStatus.OPEN
                            ))
                    except Exception:
                        pass

                # --- 5. HAProxy / Envoy / Supervisord Audit ---
                if f_lower == "haproxy.cfg":
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            content = fl.read()
                        if "stats enable" in content and "stats auth" not in content:
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-HAPROXY-STATS-{len(findings)+1:03d}",
                                title="HAProxy Statistics Dashboard Exposed Without Authentication",
                                severity=Severity.HIGH,
                                description="HAProxy 'stats enable' is active without 'stats auth <user>:<pass>', allowing unauthenticated telemetry reconnaissance.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                cwe="CWE-306",
                                owasp="OWASP A07:2021-Identification and Authentication Failures",
                                remediation="Add 'stats auth <username>:<password>' to haproxy.cfg stats block.",
                                status=FindingStatus.OPEN
                            ))
                    except Exception:
                        pass

                if f_lower == "supervisord.conf":
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            content = fl.read()
                        if "[inet_http_server]" in content and "username" not in content:
                            findings.append(self.parent.create_finding(
                                finding_id=f"CONF-SUPERVISORD-AUTH-{len(findings)+1:03d}",
                                title="Supervisord HTTP Server Configured Without Authentication",
                                severity=Severity.CRITICAL,
                                description="Supervisord inet_http_server allows unauthenticated process execution and arbitrary host restart.",
                                tool="DKSec Web Server Auditor",
                                file_path=rel_path,
                                line_number=1,
                                cwe="CWE-306",
                                owasp="OWASP A07:2021-Identification and Authentication Failures",
                                remediation="Require strong username and password under [inet_http_server] or use unix_http_server.",
                                status=FindingStatus.OPEN
                            ))
                    except Exception:
                        pass

        return findings

