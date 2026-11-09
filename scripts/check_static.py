from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, unquote
import re
import subprocess
import tempfile
import sys

ROOT = Path(".").resolve()
errors = []
inline_scripts = []

class AuditParser(HTMLParser):
    def __init__(self, html_path):
        super().__init__(convert_charrefs=True)
        self.html_path = html_path
        self.in_inline_script = False
        self.script_buffer = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for attr in ("src", "href", "poster"):
            value = attrs.get(attr, "")
            if not value or value.startswith(("#", "${")):
                continue
            parsed = urlsplit(value)
            if parsed.scheme or parsed.netloc:
                continue
            rel = unquote(parsed.path)
            if not rel:
                continue
            if rel.startswith("/"):
                errors.append(f"{self.html_path}: root-absolute URL may break on project Pages: {value}")
                continue
            target = (self.html_path.parent / rel).resolve()
            if not target.exists():
                errors.append(f"{self.html_path}: missing local reference: {rel}")
        if tag.lower() == "script" and not attrs.get("src"):
            self.in_inline_script = True
            self.script_buffer = []

    def handle_data(self, data):
        if self.in_inline_script:
            self.script_buffer.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self.in_inline_script:
            source = "".join(self.script_buffer).strip()
            if source:
                inline_scripts.append((str(self.html_path), source))
            self.in_inline_script = False
            self.script_buffer = []

def check_node(source, label):
    with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as tmp:
        tmp.write(source)
        temp_path = tmp.name
    result = subprocess.run(["node", "--check", temp_path], capture_output=True, text=True)
    Path(temp_path).unlink(missing_ok=True)
    if result.returncode:
        errors.append(f"{label}: JavaScript syntax check failed")

html_files = sorted(p for p in ROOT.rglob("*.html") if ".git" not in p.parts)
if not (ROOT / "index.html").is_file():
    errors.append("Root index.html is missing")

for path in html_files:
    parser = AuditParser(path)
    try:
        parser.feed(path.read_text(encoding="utf-8"))
        parser.close()
    except Exception:
        errors.append(f"{path}: HTML parsing failed")

for path in ROOT.rglob("*.css"):
    if ".git" in path.parts:
        continue
    css = path.read_text(encoding="utf-8", errors="replace")
    for raw in re.findall(r"url\((.*?)\)", css, flags=re.I):
        value = raw.strip().strip("\"'").split("?", 1)[0].split("#", 1)[0]
        if not value or value.startswith(("/", "data:")) or re.match(r"^[a-z]+:", value, re.I):
            continue
        if not (path.parent / unquote(value)).resolve().exists():
            errors.append(f"{path}: missing CSS asset: {value}")

for path in ROOT.rglob("*.js"):
    if ".git" in path.parts:
        continue
    check_node(path.read_text(encoding="utf-8"), str(path))

for label, source in inline_scripts:
    check_node(source, f"{label} inline script")

# Report only rule names and file paths; never print matched values.
secret_rules = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "cloud-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic-secret": re.compile(r"(?i)\b(?:client_secret|api_key|access_token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
}
for path in ROOT.rglob("*"):
    if not path.is_file() or ".git" in path.parts or path.suffix.lower() not in (".html", ".js", ".css", ".json", ".yml", ".yaml", ".md", ".txt"):
        continue
    content = path.read_text(encoding="utf-8", errors="replace")
    for rule, pattern in secret_rules.items():
        if pattern.search(content):
            errors.append(f"{path}: potential {rule} detected; value suppressed")

if errors:
    for error in errors:
        print(error)
    sys.exit(1)

print(f"Static audit passed: {len(html_files)} HTML files, local HTML/CSS references and JavaScript syntax checked.")
