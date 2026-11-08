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
_SHELLISH = re.compile(r"`[^`\n]{2,}`|\$\([^)\n]+\)|(?:^|\s)\$\s+\S[^\n]*")
_DANGER = (
    (re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b", re.I), "a download piped into a shell"),
    (re.compile(r"\b(?:curl|wget)\b[^\n|]*\|", re.I), "a download piped into another program"),
    (re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.I), "a download from a bare IP address"),
    (re.compile(r"\b(?:curl|wget)\b[^\n]*\bhttp://", re.I), "a download over plain HTTP"),
    (re.compile(r"\bbase64\s+(?:-d|--decode)\b", re.I), "base64-decoded code"),
    (re.compile(r"/dev/(?:tcp|udp)/", re.I), "a /dev/tcp connection"),
    (re.compile(r"\b(?:bash|sh)\s+-c\b", re.I), "a shell given a command string"),
    (re.compile(r"\bnc(?:at)?\s+(?:\S+\s+)*?-[ce]\b", re.I), "netcat running a program"),
    (re.compile(r"\brm\s+-\w*r\w*f?\s+/(?:\s|$)", re.I), "deleting from the root"),
    (re.compile(r"\bchmod\s+(?:\+x|[0-7]*7[0-7]{2})\b", re.I), "making a file executable"),
    (re.compile(r"\b(?:eval|exec)\s*[(\s]", re.I), "evaluating code"),
    (re.compile(r"\bsetenforce\s+0\b|\bsetenforce\s+permissive\b", re.I), "turning SELinux off"),
    (
        re.compile(
            r"\bsystemctl\s+(?:stop|disable|mask|kill)\s+(?:--now\s+)?(?:firewalld|ufw|nftables"
            r"|iptables|auditd|apparmor|fail2ban|rsyslog|systemd-journald|selinux\w*)",
            re.I,
        ),
        "stopping a firewall, audit or logging service",
    ),
    (
        re.compile(r"\bufw\s+disable\b|\b(?:ip6?tables|nft)\s+(?:-F|flush)\b", re.I),
        "dropping the firewall's rules",
    ),
    (re.compile(r"\baa-(?:disable|complain|teardown)\b", re.I), "turning AppArmor off"),
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:/\d{1,3})?(?![\w:])", re.I)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_TLDS = (
    "com|net|org|io|gov|edu|mil|info|biz|co|dev|app|cloud|xyz|site|online|top|ru|cn|us|uk"
    "|de|fr|nl|eu|jp|kr|in|br|au|ca|ch|se|no|fi|pl|cz|it|es|be|at|dk|ie|il|tw|hk|sg|me|tk"
    "|ws|cc|tv|sh|ly|to|su|ir|kp|onion|local|lan|internal"
)
_HOST = re.compile(
    rf"(?<![\w.@/-])(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{_TLDS})(?![\w-]|\.[\w-])", re.I
)
_PATH = re.compile(r"(?<![\w.:/~-])(?:~/|/)(?:[\w.@+-]+/)*[\w.@+*-]+/?")
_URL = re.compile(r"https?://[^\s\"'<>`]+", re.I)
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


def literals(prose: str) -> list[Literal]:
    """The commands, addresses, paths and URLs in some prose, each once."""
    found: list[Literal] = []

    def add(kind: str, text: str) -> None:
        text = text.strip().rstrip(".,;:)]")
        if text and Literal(kind, text) not in found:
            found.append(Literal(kind, text))

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
    return [f"{why}: {m.group(0).strip()[:80]}" for p, why in _DANGER for m in p.finditer(prose)]


def _norm(text: str) -> str:
    return " ".join(text.lower().split())


@dataclass(frozen=True)
class Finding:
    literal: Literal
    sources: tuple[str, ...]  # the sources that contain it: none, it was made up


def look_up(found: list[Literal], sources: list[tuple[str, str]]) -> list[Finding]:
    """Each literal with the sources (name, text) that contain it, whitespace and case
    aside."""
    texts = [(name, _norm(text)) for name, text in sources]
    return [
        Finding(lit, tuple(name for name, text in texts if _norm(lit.text) in text))
        for lit in found
    ]


def site(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def known_site(url: str) -> bool:
    host = site(url)
    return any(host == s or host.endswith("." + s) for s in KNOWN_SITES)
