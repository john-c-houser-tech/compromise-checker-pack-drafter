"""A.6: checks on what the AI writes for people to read and act on.

The prose (title, remediation, mitigation text, detection titles, unknowns) reaches
server administrators, and the sources it was written from are fetched text that an
attacker could have shaped: an advisory could steer the model into telling admins to
run something. So, in the prose:

- **Commands, network addresses, file paths and URLs** are found and looked up in the
  sources. One that no source contains was made up: the answer is refused. One a
  source does contain is listed at the top of the draft with the source it came
  from, for the person signing: being in a source doesn't make it safe.
- **Dangerous instructions** are refused wherever they came from: a download piped
  into a shell, a download from a bare IP address or over plain HTTP, base64-decoded
  code, a /dev/tcp connection, and the like. A pack never needs one.

References were already held to the sources (A.5); here each is listed with the
sources that gave it, and one whose site isn't a known advisory publisher is marked.

Heuristics, on purpose: a phrase missed is caught by the person reviewing, who sees
every literal the checks found; a phrase wrongly flagged costs one more request.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

# Commands an administrator would type, whose names aren't also ordinary words or
# the software's own names (php, node, ruby are left out for that reason).
_COMMANDS = (
    "apt", "apt-get", "aptitude", "dnf", "yum", "rpm", "dpkg", "snap", "pip", "pip3",
    "npm", "gem", "curl", "wget", "systemctl", "journalctl", "chmod", "chown", "chattr",
    "iptables", "ip6tables", "nft", "firewall-cmd", "ufw", "setenforce", "setsebool",
    "update-ca-certificates", "update-crypto-policies", "openssl", "sudo", "sysctl",
    "modprobe", "insmod", "rmmod", "crontab", "useradd", "usermod", "userdel", "passwd",
    "docker", "podman", "kubectl", "sed", "awk", "base64", "nc", "ncat", "socat", "killall",
    "pkill", "tar", "unzip", "scp", "rsync", "ssh-keygen", "bash", "sh", "zsh", "powershell",
    "certutil", "keytool", "virsh", "qemu-img", "mokutil", "efibootmgr", "grubby",
)  # fmt: skip
_COMMAND = re.compile(
    r"(?<![\w./-])(?:sudo[ \t]+)?(?:" + "|".join(re.escape(c) for c in _COMMANDS) + r")"
    r"(?:[ \t]+(?!(?:and|or|to|then|on|in|the|a|an|for|if|until|so|with|after|before|from|as"
    r"|is|are|was|which|that|shell|shells|package|packages|command|commands)\b)"
    r"(?:-{1,2}[\w=.:/-]+|[\w./:@=+~*-]+))+",
    re.IGNORECASE,
)
# Clearly code, however it is worded.
_SHELLISH = re.compile(r"`[^`\n]{2,300}`|\$\([^)\n]{1,300}\)|(?:^|\s)\$[ \t]+\S[^\n]{0,300}")
# Each bounded, so a long or hostile answer can't make one slow (no unbounded run
# before a later part of the pattern), and each within one line. Negated advice
# ("never set SELINUX=disabled") is refused too: skipping it would let "don't
# hesitate to run …" through; the model rewords on its second try.
_DANGER = (
    (re.compile(r"\|[ \t]*(?:sudo[ \t]+(?:-\w+[ \t]+)*)?(?:ba|z|da|k)?sh\b", re.I),
     "a download piped into a shell"),
    (re.compile(r"\b(?:curl|wget)\b[^\n|]{0,300}\|(?![ \t]*(?:grep|head|tail|less|more|wc|jq)\b)",
                re.I), "a download piped into another program"),
    (re.compile(r"<\([ \t]*(?:curl|wget)\b|\b(?:curl|wget)\b[^\n]{0,300}(?:&&|;)[ \t]*"
                r"(?:sudo[ \t]+)?(?:ba|z|da|k)?sh[ \t]", re.I), "a download run by a shell"),
    (re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.I), "a download from a bare IP address"),
    (re.compile(r"\b(?:curl|wget)(?:[ \t]+-{1,2}[\w-]{1,30}(?:[ \t]+[^\s-][^\s]{0,80})?){0,6}"
                r"[ \t]+[\"']?http://", re.I), "a download over plain HTTP"),
    (re.compile(r"\bbase64[ \t]+(?:-d|--decode)\b", re.I), "base64-decoded code"),
    (re.compile(r"/dev/(?:tcp|udp)/", re.I), "a /dev/tcp connection"),
    (re.compile(r"\bn(?:c|cat|etcat)(?:[ \t]+(?!(?:and|or|then|with|grep)\b)[^\s;|&]{1,80}){0,8}?"
                r"[ \t]+(?:-[ce]\b|--(?:sh-)?exec\b)", re.I), "netcat running a program"),
    (re.compile(r"\brm(?:[ \t]+-{1,2}[\w-]{1,30}){1,6}[ \t]+(?:--no-preserve-root[ \t]+)?"
                r"[\"']?/\*?[\"']?(?![\w/*-]|\.\w)", re.I), "deleting from the root"),
    (re.compile(r"\bchmod(?:[ \t]+-{1,2}[\w-]{1,20}){0,3}[ \t]+(?:[ugoa]{0,4}\+[rw]{0,2}x\b"
                r"|0?[0-7]?777\b|0?[0-7]?[0-7][0-7]7\b)", re.I),
     "making a file executable or writable by anyone"),
    (re.compile(r"\beval[ \t]*(?:\$|\((?!\))|[\"'`])", re.I), "evaluating code"),
    (re.compile(r"\bsetenforce[ \t]+(?:0|permissive)\b|SELINUX[ \t]*=[ \t]*(?:disabled|permissive)",
                re.I), "turning SELinux off"),
    (re.compile(r"\bsystemctl[ \t]+(?:stop|disable|mask|kill)[ \t]+(?:--now[ \t]+)?(?:firewalld|ufw"
                r"|nftables|iptables|auditd|apparmor|fail2ban|rsyslog|systemd-journald|selinux\w*)",
                re.I), "stopping a firewall, audit or logging service"),
    (re.compile(r"\bufw[ \t]+disable\b|\bip6?tables[ \t]+(?:-F|--flush|-P[ \t]+\w+[ \t]+ACCEPT)\b"
                r"|\bnft[ \t]+flush\b", re.I), "dropping the firewall's rules"),
    (re.compile(r"\baa-(?:disable|complain|teardown)\b", re.I), "turning AppArmor off"),
)  # fmt: skip
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w/]|\.\d)")
_IPV6 = re.compile(r"(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:/\d{1,3})?(?![\w:])", re.I)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_TLDS = (
    "com|net|org|io|gov|edu|mil|info|biz|co|dev|app|cloud|xyz|site|online|top|ru|cn|us|uk"
    "|de|fr|nl|eu|jp|kr|in|br|au|ca|ch|se|no|fi|pl|cz|it|es|be|at|dk|ie|il|tw|hk|sg|me|tk"
    "|ws|cc|tv|sh|ly|to|su|ir|kp|onion|local|lan|internal|ai|gg|li|pw|pro|tech|link|click"
    "|live|shop|store|club|name|mobi|asia|cn|vn|th|id|my|ph|ua|by|kz|tr|gr|ro|hu|pt|mx|ar|cl"
    "|za|ng|ke|eg|sa|ae|pk|bd|lk|nz"
)
_HOST = re.compile(
    rf"(?<![\w.@/-])(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{_TLDS})(?![\w-]|\.[\w-])", re.I
)
_PATH = re.compile(r"(?<![\w.:/~-])(?:~/|/)(?:[\w.@+-]+/)*[\w.@+*-]+/?")
_URL = re.compile(r"https?://[^\s\"'<>`\u201c\u201d\u2018\u2019]+", re.I)
_URL_END = ".,;:)]?!"


def url_forms(url: str) -> set[str]:
    """A URL as written and without what a sentence puts after it."""
    url = plain(url)
    return {url, url.rstrip(_URL_END)}


# Sites whose advisories the sources point to as a matter of course.
KNOWN_SITES = (
    "nvd.nist.gov", "cve.org", "cisa.gov", "redhat.com", "ubuntu.com", "launchpad.net",
    "canonical.com", "debian.org", "almalinux.org", "rockylinux.org", "github.com",
    "microsoft.com", "oracle.com", "openjdk.org", "php.net", "nodejs.org", "ruby-lang.org",
    "gitlab.com", "about.gitlab.com", "apache.org", "kernel.org", "openssl.org",
    "mozilla.org", "google.com", "chromium.org", "cert.org", "mitre.org", "first.org",
)  # fmt: skip


@dataclass(frozen=True)
class Literal:
    kind: str  # command, address, path, URL
    text: str


def plain(text: str) -> str:
    """Text as matched: compatibility forms folded (full-width letters, ligatures and
    the like read as the letters they stand for)."""
    return unicodedata.normalize("NFKC", text)


def literals(prose: str) -> list[Literal]:
    """The commands, addresses, paths and URLs in some prose, each once."""
    prose = plain(prose)
    found: list[Literal] = []
    seen: set[Literal] = set()

    def add(kind: str, text: str) -> None:
        text = text.strip().rstrip(_URL_END if kind == "URL" else ".,;:)]")
        lit = Literal(kind, text)
        if text and lit not in seen:
            seen.add(lit)
            found.append(lit)

    for match in _URL.finditer(prose):
        add("URL", match.group(0))
    for match in _SHELLISH.finditer(prose):  # a command keeps its URL
        add("command", match.group(0).strip().strip("`").lstrip("$ "))
    for match in _COMMAND.finditer(prose):
        add("command", match.group(0))
    rest = _URL.sub(" ", prose)
    for match in _IPV4.finditer(rest):
        add("address", match.group(0))
    for match in _IPV6.finditer(rest):
        text = match.group(0)
        if "::" in text or text.count(":") >= 5:  # not a time of day (12:30:45)
            add("address", text)
    for match in _EMAIL.finditer(rest):
        add("address", match.group(0))
    for match in _HOST.finditer(_EMAIL.sub(" ", rest)):
        tld = match.group(0).rsplit(".", 1)[1]
        if not (tld.isupper() and len(tld) > 1):  # ASP.NET, VB.NET: names, not sites
            add("address", match.group(0))
    for match in _PATH.finditer(rest):
        if len(match.group(0)) > 2:  # not "/" or "~/" alone
            add("path", match.group(0))
    return found


def dangers(prose: str) -> list[str]:
    """What in some prose a pack must never tell anyone to do."""
    prose = plain(prose)
    return [
        f"{why}: {' '.join(m.group(0).split())[:80]}"
        for p, why in _DANGER
        for m in p.finditer(prose)
    ]


def _norm(text: str) -> str:
    return " ".join(plain(text).lower().split())


@dataclass(frozen=True)
class Finding:
    literal: Literal
    sources: tuple[str, ...]  # the sources that contain it: none, it was made up
    context: str = ""  # the words around it in the first of those, for the signer


# What may stand next to a literal in a source for it to count as the source's own,
# by kind: a command whole; an address also in a URL or with a port or path after it
# (github.com/org/x, 127.0.0.1:11211, //host); a path also as a directory of a longer
# one (/etc/modprobe.d of /etc/modprobe.d/x.conf) or with a line number (file.c:12).
_BOUNDS = {
    "command": (r"(?<![\w./@:~-])", r"(?![\w/@~-]|[.:][\w/])"),
    "address": (r"(?<![\w.@-])", r"(?![\w-]|\.\w)"),
    "path": (r"(?<![\w.~-])", r"(?![\w-]|\.\w)"),
    "URL": (r"(?<![\w./-])", r"(?![\w/-]|[.:][\w/])"),
}


def _wanted(lit: Literal) -> str:
    text = _norm(lit.text)
    if lit.kind == "command":  # a source's "# systemctl …" is the model's "sudo systemctl …"
        text = re.sub(r"^sudo\s+", "", text)
    return text


def look_up(found: list[Literal], sources: list[tuple[str, str]]) -> list[Finding]:
    """Each literal with the sources (name, text) that contain it whole (not as part of
    a longer word, path or address), whitespace and case aside, and the words around
    it in the first."""
    texts = [(name, _norm(text)) for name, text in sources]
    out = []
    for lit in found:
        bounds = _BOUNDS[lit.kind]
        pattern = re.compile(bounds[0] + re.escape(_wanted(lit)) + bounds[1])
        given, context = [], ""
        for name, text in texts:
            match = pattern.search(text)
            if match is None:
                continue
            given.append(name)
            if not context:
                start, end = max(0, match.start() - 60), min(len(text), match.end() + 60)
                context = (
                    ("…" if start else "") + text[start:end] + ("…" if end < len(text) else "")
                )
        out.append(Finding(lit, tuple(given), context))
    return out


def site(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def known_site(url: str) -> bool:
    host = site(url)
    return any(host == s or host.endswith("." + s) for s in KNOWN_SITES)
