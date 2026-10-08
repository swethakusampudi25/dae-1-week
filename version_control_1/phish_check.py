"""Rule-based phishing checker for URLs, emails (.eml) and files. No ML, stdlib only.

Usage:
    python phish_check.py url  "http://paypa1-secure-login.xyz/verify"
    python phish_check.py email suspicious.eml
    python phish_check.py file  invoice.pdf.exe
    python phish_check.py scan  "C:\\Users\\you\\Downloads"   # file or folder, shows a popup
    python phish_check.py scan  <path> --no-popup            # same, terminal only
"""
import email
import hashlib
import ipaddress
import os
import re
import sys
import zipfile
from email import policy
from html.parser import HTMLParser
from urllib.parse import urlparse

# ---------------- Config ----------------
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click",
                   "country", "work", "support", "rest", "fit", "cam"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
              "rebrand.ly", "shorturl.at"}
BRANDS = ["paypal", "apple", "microsoft", "office365", "outlook", "amazon", "netflix",
          "google", "bankofamerica", "chase", "wellsfargo", "dhl", "fedex", "usps", "irs"]
URL_KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm",
                "password", "banking", "wallet", "unlock"]
EMAIL_KEYWORDS = ["urgent", "immediately", "suspended", "locked", "verify your",
                  "confirm your", "unusual activity", "password", "click here",
                  "act now", "final notice", "invoice", "payment failed", "gift card",
                  "wire transfer", "within 24 hours"]
RISKY_EXT = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
             ".vbe", ".wsf", ".ps1", ".hta", ".lnk", ".iso", ".img", ".jar", ".msi"}
MACRO_EXT = {".docm", ".xlsm", ".pptm"}
URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)


class Report:
    def __init__(self, target):
        self.target, self.score, self.reasons = target, 0, []

    def add(self, points, reason):
        self.score += points
        self.reasons.append(f"+{points}  {reason}")

    def verdict(self):
        if self.score >= 5:
            return "🚨 PHISHING / MALICIOUS"
        if self.score >= 2:
            return "⚠️  SUSPICIOUS"
        return "✅ LIKELY SAFE"

    def show(self):
        print(f"\n[{self.target}]  score={self.score}  →  {self.verdict()}")
        for r in self.reasons:
            print("   ", r)


# ---------------- URL checks ----------------
def check_url(url):
    r = Report(url)
    if not re.match(r"^[a-z]+://", url, re.I):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    parts = host.split(".")
    tld = parts[-1] if parts else ""
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    full = url.lower()

    try:
        ipaddress.ip_address(host)
        r.add(3, "Uses raw IP address instead of domain")
    except ValueError:
        pass
    if "@" in p.netloc:
        r.add(3, "Contains '@' (real destination hidden after it)")
    if p.scheme != "https":
        r.add(1, "Not HTTPS")
    if len(url) > 75:
        r.add(1, f"Long URL ({len(url)} chars)")
    if len(parts) > 4:
        r.add(2, f"Many subdomains ({len(parts) - 2})")
    if tld in SUSPICIOUS_TLDS:
        r.add(2, f"Suspicious TLD .{tld}")
    if "xn--" in host:
        r.add(3, "Punycode domain (possible look-alike characters)")
    if host.count("-") >= 2:
        r.add(1, "Multiple hyphens in domain")
    if domain in SHORTENERS:
        r.add(2, "URL shortener hides real destination")
    if re.search(r"[a-z][0-9][a-z]|[0-9][a-z]{3,}", parts[-2] if len(parts) >= 2 else host):
        r.add(1, "Digits mixed into domain name (e.g. paypa1)")
    for b in BRANDS:
        lookalike = b.replace("o", "0").replace("l", "1").replace("i", "1")
        if b in full and not (domain.startswith(b + ".") or domain == b):
            r.add(3, f"Mentions brand '{b}' but domain is {domain}")
            break
        if lookalike != b and lookalike in host:
            r.add(3, f"Look-alike of brand '{b}'")
            break
    hits = [k for k in URL_KEYWORDS if k in full]
    if hits:
        r.add(min(len(hits), 2), f"Sensitive keywords: {', '.join(hits)}")
    if re.search(r"\.(exe|scr|js|vbs|zip|apk|hta)(\?|$)", p.path.lower()):
        r.add(2, "Links directly to executable/archive download")
    return r


# ---------------- File checks ----------------
def check_file(path, data=None, name=None):
    name = name or os.path.basename(path)
    r = Report(name)
    if data is None:
        with open(path, "rb") as f:
            data = f.read()
    lower = name.lower()
    ext = os.path.splitext(lower)[1]

    if ext in RISKY_EXT:
        r.add(4, f"Executable/script extension {ext}")
    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.[a-z0-9]{2,4}$", lower) and ext in RISKY_EXT:
        r.add(3, "Double extension disguise (e.g. invoice.pdf.exe)")
    if ext in MACRO_EXT:
        r.add(3, f"Macro-enabled Office file {ext}")

    head = data[:8]
    if head.startswith(b"MZ") and ext not in {".exe", ".dll", ".scr", ".msi"}:
        r.add(5, "Windows executable disguised with another extension")
    if head.startswith(b"\xd0\xcf\x11\xe0") and b"VBA" in data:
        r.add(3, "Legacy Office file with VBA macros")
    if head.startswith(b"PK"):
        try:
            with zipfile.ZipFile(__import__("io").BytesIO(data)) as z:
                names = [n.lower() for n in z.namelist()]
                if any("vbaproject.bin" in n for n in names):
                    r.add(3, "Office file contains VBA macros")
                inner = [n for n in names if os.path.splitext(n)[1] in RISKY_EXT]
                if inner:
                    r.add(4, f"Archive contains executables: {inner[:3]}")
        except zipfile.BadZipFile:
            pass
    if head.startswith(b"%PDF"):
        for tag, pts in [(b"/JavaScript", 3), (b"/JS", 2), (b"/OpenAction", 2),
                         (b"/Launch", 3), (b"/EmbeddedFile", 2)]:
            if tag in data:
                r.add(pts, f"PDF contains {tag.decode()}")
        for u in set(URL_RE.findall(data.decode("latin-1"))[:10]):
            if check_url(u).score >= 5:
                r.add(2, f"PDF links to suspicious URL {u}")
    r.reasons.append(f"     SHA256 {hashlib.sha256(data).hexdigest()}  (look up on VirusTotal)")
    return r


# ---------------- Email checks ----------------
class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, ""

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), ""

    def handle_data(self, d):
        if self._href is not None:
            self._text += d

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append((self._text.strip(), self._href))
            self._href = None


def addr_domain(header):
    m = re.search(r"@([\w.-]+)", header or "")
    return m.group(1).lower() if m else ""


def check_email(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    r = Report(os.path.basename(path))
    frm, reply = str(msg.get("From", "")), str(msg.get("Reply-To", ""))
    ret = str(msg.get("Return-Path", ""))
    fdom = addr_domain(frm)

    # Header checks
    if reply and addr_domain(reply) and addr_domain(reply) != fdom:
        r.add(3, f"Reply-To domain ({addr_domain(reply)}) differs from From ({fdom})")
    if ret and addr_domain(ret) and addr_domain(ret) != fdom:
        r.add(1, f"Return-Path domain ({addr_domain(ret)}) differs from From")
    display = frm.split("<")[0].lower()
    for b in BRANDS:
        if b in display and b not in fdom:
            r.add(3, f"Display name claims '{b}' but sender domain is {fdom}")
            break
    auth = str(msg.get("Authentication-Results", "")).lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"{mech}=(fail|softfail)", auth):
            r.add(2, f"{mech.upper()} failed")

    # Body
    html, text = "", ""
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_filename():
            fr = check_file(part.get_filename(), part.get_payload(decode=True) or b"",
                            part.get_filename())
            if fr.score:
                r.add(fr.score, f"Attachment {part.get_filename()}: "
                      + "; ".join(x.split("  ", 1)[1] for x in fr.reasons if x.startswith("+")))
        elif ctype == "text/html":
            html += part.get_content()
        elif ctype == "text/plain":
            text += part.get_content()
    body = (text + " " + re.sub(r"<[^>]+>", " ", html)).lower()
    subj = str(msg.get("Subject", "")).lower()

    hits = [k for k in EMAIL_KEYWORDS if k in body or k in subj]
    if hits:
        r.add(min(len(hits), 3), f"Urgency/credential language: {', '.join(hits[:5])}")

    # Link text vs real destination
    lp = LinkParser()
    lp.feed(html)
    for txt, href in lp.links:
        shown = re.search(r"(?:https?://)?([\w.-]+\.[a-z]{2,})", txt.lower())
        real = (urlparse(href).hostname or "").lower()
        if shown and real and shown.group(1) not in real:
            r.add(3, f"Link text shows '{shown.group(1)}' but goes to '{real}'")

    # Score every URL
    urls = set(URL_RE.findall(text)) | {h for _, h in lp.links if h.startswith("http")}
    for u in list(urls)[:20]:
        ur = check_url(u)
        if ur.score >= 3:
            r.add(min(ur.score, 4), f"Suspicious link {u} (url score {ur.score})")
    return r


# ---------------- Folder scan + popup ----------------
MAX_SCAN_BYTES = 50 * 1024 * 1024


def status_of(score):
    return "MALICIOUS" if score >= 5 else "SUSPICIOUS" if score >= 2 else "SAFE"


def popup(title, message, warning=True):
    """Show a native dialog; falls back to a no-op if no GUI is available."""
    try:
        import tkinter
        from tkinter import messagebox
        root = tkinter.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        (messagebox.showwarning if warning else messagebox.showinfo)(title, message, parent=root)
        root.destroy()
    except Exception:
        print("(popup unavailable - see the report above)")


def scan_path(target, show_popup=True):
    """Scan a file or every file under a folder; print status and warn on bad ones."""
    if os.path.isdir(target):
        files = [os.path.join(d, f) for d, _, fs in os.walk(target) for f in fs]
    elif os.path.isfile(target):
        files = [target]
    else:
        sys.exit(f"Not found: {target}")

    print(f"Scanning {len(files)} file(s) in {target}\n")
    print(f"{'#':>4}  {'STATUS':<11} {'SCORE':>5}  FILE")
    results, skipped = [], []
    for i, path in enumerate(files, 1):
        try:
            if os.path.getsize(path) > MAX_SCAN_BYTES:
                raise OSError("file larger than 50 MB")
            r = check_email(path) if path.lower().endswith(".eml") else check_file(path)
        except Exception as e:
            skipped.append((path, str(e)))
            print(f"{i:>4}  {'SKIPPED':<11} {'-':>5}  {path}  ({e})")
            continue
        r.path = path
        results.append(r)
        print(f"{i:>4}  {status_of(r.score):<11} {r.score:>5}  {path}")

    bad = sorted((r for r in results if r.score >= 5), key=lambda r: -r.score)
    sus = sorted((r for r in results if 2 <= r.score < 5), key=lambda r: -r.score)
    print("\n" + "=" * 70)
    print(f"Scanned {len(results)} file(s): {len(bad)} malicious, {len(sus)} suspicious, "
          f"{len(results) - len(bad) - len(sus)} safe, {len(skipped)} skipped")

    for title, group in (("MALICIOUS - do NOT open or access", bad),
                         ("SUSPICIOUS - review before opening", sus)):
        if group:
            print(f"\n{title}:")
            for r in group:
                print(f"\n  {r.path}  (score {r.score})")
                for reason in r.reasons:
                    if reason.startswith("+"):
                        print(f"     - {reason.split('  ', 1)[1]}")

    if show_popup:
        if bad or sus:
            lines = [f"Scanned {len(results)} file(s).", ""]
            if bad:
                lines.append(f"MALICIOUS ({len(bad)}) - do NOT open or access:")
                lines += [f"  - {os.path.basename(r.path)}" for r in bad[:10]]
            if sus:
                lines += ["", f"SUSPICIOUS ({len(sus)}) - review before opening:"]
                lines += [f"  - {os.path.basename(r.path)}" for r in sus[:10]]
            lines += ["", "See the terminal for the full threat details."]
            popup("Phishing scan - threats found", "\n".join(lines))
        else:
            popup("Phishing scan complete",
                  f"Scanned {len(results)} file(s). No malicious files found.\n"
                  "(Not a guarantee of safety.)", warning=False)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) in (3, 4) and sys.argv[1] == "scan":
        scan_path(sys.argv[2], show_popup="--no-popup" not in sys.argv[3:])
    elif len(sys.argv) != 3 or sys.argv[1] not in {"url", "email", "file"}:
        sys.exit(__doc__)
    else:
        kind, target = sys.argv[1], sys.argv[2]
        {"url": check_url, "email": check_email, "file": check_file}[kind](target).show()
