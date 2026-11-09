"""What a pack's detections may name, as the checker has it at the commit
drafter.checkerformat pins: its built-in checks (with their titles and variants),
the event types and fields its own rules can match, and the snapshot sections they
can read (not those exposure is judged from). The drafting prompt offers only these,
and a draft naming anything else is refused.

Checks and sections: generated from checker.checks.load_checks() and
checker.snapshot.SECTIONS at that commit (scripts/vocabulary.py). Events: the types
and fields checker/events.py writes there, those a threat's detection can use.
"""

from __future__ import annotations

CHECKS: dict[str, tuple[str, tuple[str, ...]]] = {  # id: (title, variants)
    "account.changes": (
        "New and removed accounts; service accounts able to log in",
        ("new", "removed", "root_group", "service_login"),
    ),
    "account.log_changes": (
        "Account and group changes recorded in the logs",
        (
            "created",
            "deleted",
            "modified",
            "renamed",
            "locked",
            "unlocked",
            "group_created",
            "group_member_added",
            "group_member_removed",
            "group_members_set",
        ),
    ),
    "account.password": ("su use, password changes and refused sudo", ()),
    "account.uid0": ("Accounts with UID 0 besides root; duplicate names and UIDs", ()),
    "agent.stopped": ("Security agents that ran at the baseline and don't now", ("moved",)),
    "clock.jump": ("The system clock set by hand (not at boot)", ()),
    "container.host_namespace": (
        "A container sharing the host's process or network namespace since the baseline",
        (),
    ),
    "container.new": (
        "Containers new since the baseline, or running another image",
        ("new", "image_changed"),
    ),
    "container.privileged": (
        "A container that holds the host: privileged, mounting its root or a runtime's socket, or with a device or capability that reaches it",
        ("new", "standing"),
    ),
    "files.backdated": ("Programs and scripts whose modification time was set back", ()),
    "files.deceptive": ("Names chosen to hide or to pass for system ones", ()),
    "files.dev": ("Files under /dev that don't belong", ()),
    "files.privileged": (
        "Set-user-ID, set-group-ID and capability files; device nodes out of place",
        (),
    ),
    "files.scratch": ("Programs and scripts in /tmp, /var/tmp and /dev/shm", ()),
    "files.unowned": ("Executables in system directories that no package installed", ()),
    "files.web": (
        "Web shells: new or changed scripts in web roots, scripts in upload directories; new or changed scripts outside what the web servers serve",
        (),
    ),
    "group.privileged": ("New members of root-equivalent groups", ()),
    "history.disabled": (
        "Shell history switched off: linked to /dev/null, emptied, or disabled in start-up files",
        ("link", "emptied", "deleted", "startup"),
    ),
    "kernel.core_dump": ("Core dumps of network-facing services", ()),
    "kernel.errors": ("Kernel oopses, hung tasks and machine checks", ()),
    "kernel.oom_kill": ("Out-of-memory kills", ()),
    "kernel.segfault": ("Segfaults, repeated or in network-facing services", ()),
    "kernel.taint": (
        "Kernel taint: out-of-tree or unsigned modules, taint changes",
        ("unexplained", "unloaded"),
    ),
    "logs.cleared": (
        "Logs cleared, truncated, replaced or deleted since the previous collection",
        ("truncated", "deleted", "replaced", "journal_removed"),
    ),
    "logs.journald_config": ("journald set to keep nothing, or nothing on disk", ()),
    "logs.stopped": (
        "Logging or audit stopped, audit rules removed, audit switched off",
        ("unit", "audit_daemon", "audit_rules", "not_running", "moved"),
    ),
    "mac.disabled": (
        "SELinux enforcement or AppArmor profiles turned down",
        ("selinux", "selinux_audit", "apparmor"),
    ),
    "mail.domains": ("Many recipient domains never written to before, in one day", ()),
    "mail.relay": ("Mail relay changed, or relaying open to anyone", ("relay", "open_relay")),
    "mail.volume": ("A sudden jump in outgoing mail, or a growing queue", ("deliveries", "queue")),
    "mail.web_user": ("Mail submitted by a web-server account", ()),
    "net.config": (
        "Changes to hosts, resolver, TCP wrappers and the firewall",
        ("file", "firewall", "json_lost"),
    ),
    "net.directory": (
        "Directory services reached from a web-server account",
        ("smb_winrm", "ldap_kerberos"),
    ),
    "net.firewall_comment": ("Firewall rules a comment may be disguising", ()),
    "net.listener": ("New listening ports", ()),
    "net.managed_chain": (
        "Firewall chains or sets named like another program's, which isn't running",
        (),
    ),
    "net.metadata": ("The cloud metadata address reached by an unexpected program", ()),
    "net.peer": ("New outgoing destinations; Tor", ("new_destination", "tor")),
    "net.promiscuous": ("Interfaces in promiscuous mode (capturing all traffic)", ()),
    "net.transfer": (
        "Weak signs of data leaving: large archives in scratch places, transfer tools talking out",
        ("archive", "tool", "counters"),
    ),
    "net.tunnel": ("SSH tunnels: forwarding clients and sessions holding listeners", ()),
    "package.changed": ("System files that differ from their package", ()),
    "pam.changes": ("PAM: pam_exec lines, configuration changes, unknown modules", ()),
    "persistence.at_jobs": ("Queued at jobs", ()),
    "persistence.changes": ("New and changed cron, systemd, start-up and hook files", ()),
    "persistence.homes": ("User units, autostart entries and lingering users", ()),
    "persistence.ld_preload": ("/etc/ld.so.preload and loader variables in processes", ()),
    "process.executable": (
        "Processes running from deleted, memory-only or scratch files, or posing as kernel threads",
        (),
    ),
    "process.hidden": ("Processes hidden from /proc's listing", ()),
    "process.injected": (
        "Code mapped from deleted, memory-only or scratch files",
        ("scratch", "deleted", "libffi", "memory", "shared", "replaced"),
    ),
    "process.miner": ("Cryptocurrency miners", ()),
    "process.reverse_shell": ("Shells whose input or output is a network socket", ()),
    "software.global": ("Python and Node packages installed system-wide by hand", ()),
    "software.packages": (
        "Packages installed, removed or upgraded since the baseline",
        ("installed", "removed", "upgraded", "automatic"),
    ),
    "software.repository": (
        "New or changed package repositories and signing keys",
        ("repository", "key"),
    ),
    "software.tools": (
        "Attack and tunnelling tools, or compilers, installed since the baseline",
        ("attack_tool", "compiler"),
    ),
    "ssh.authorized_keys": (
        "New, changed or unattributed authorized SSH keys",
        ("unattributed", "new_key", "options"),
    ),
    "ssh.guessed": ("Failed logins followed by success from the same source", ()),
    "ssh.login": (
        "Direct root logins; logins from sources never seen before",
        ("root_login", "new_address"),
    ),
    "ssh.login_hours": ("Logins at hours unusual for the account", ()),
    "sshd.config": ("sshd configuration changes", ()),
    "sudo.rules": ("New sudo rights", ()),
    "system.reboot": (
        "Reboots: unclean, unexplained, by an operator or planned",
        ("unclean", "operator", "power_button", "planned", "unexplained"),
    ),
    "web.errors": ("A burst of server errors from one source", ()),
    "web.exploit": ("Attack strings in web requests, answered or refused", ("answered", "refused")),
    "web.new_script_hit": ("Requests answered by a script new since the baseline", ()),
    "web.noise": ("Background noise: requests for paths the site doesn't have", ()),
    "web.worker_child": (
        "A web worker started a shell, interpreter, download tool or recon command",
        ("live", "history"),
    ),
}

# Fields every event from a log message can carry (the line's pid, and what the
# journal itself records); and `program`, which a rule may match on any event
# (checker/packs/detect.py reads it from the event, not its fields).
MESSAGE_FIELDS = ("pid", "systemd_unit", "journal_comm", "journal_uid", "audit_session", "boot_id")
ANY_EVENT = ("program",)

# Each type's own fields, as checker/events.py writes them at the pinned commit (sudo's
# details become tty, pwd and runas; sshd's invalid becomes invalid_user).
OWN_FIELDS: dict[str, tuple[str, ...]] = {
    "web.request": (
        "client",
        "network",
        "method",
        "path",
        "status",
        "size",
        "referrer",
        "agent",
        "attacks",
        "agent_attacks",
    ),
    "web.error": ("level", "message", "client", "network", "request"),
    "process.exec": (
        "pid",
        "ppid",
        "uid",
        "euid",
        "auid",
        "session",
        "comm",
        "exe",
        "cwd",
        "argv",
        "success",
    ),
    "process.core_dump": ("comm", "pid", "uid"),
    "kernel.segfault": ("comm", "pid"),
    "kernel.oom_kill": ("comm", "pid"),
    "kernel.oops": (),
    "kernel.hung_task": (),
    "kernel.machine_check": (),
    "kernel.module_taint": ("module",),
    "unit.failed": ("unit",),
    "unit.starting": ("what",),
    "unit.started": ("what",),
    "unit.stopped": ("what",),
    "unit.finished": ("what",),
    "ssh.login.accepted": ("address", "fingerprint", "key_type", "method", "port", "user"),
    "ssh.login.failed": ("address", "invalid_user", "method", "port", "user"),
    "ssh.login.too_many_failures": ("address", "invalid_user", "port", "user"),
    "ssh.login.abandoned": ("address", "invalid_user", "port", "user"),
    "ssh.invalid_user": ("address", "port", "user"),
    "auth.failure": ("module", "rest", "service"),
    "sudo.command": ("command", "user", "tty", "pwd", "runas"),
    "sudo.failed": ("command", "reason", "user", "tty", "pwd", "runas"),
    "sudo.denied": ("command", "reason", "user", "tty", "pwd", "runas"),
    "su.switch": ("target", "tty", "user"),
    "su.failed": ("target", "user"),
    "session.opened": ("by", "service", "user"),
    "session.closed": ("by", "service", "user"),
    "account.created": ("origin", "shell", "uid", "user"),
    "account.deleted": ("user",),
    "account.modified": ("user",),
    "account.renamed": ("old_user", "user"),
    "account.password_changed": ("user",),
    "account.locked": ("user",),
    "account.unlocked": ("user",),
    "group.created": ("group",),
    "group.member_added": ("by", "group", "user"),
    "group.member_removed": ("by", "group", "user"),
    "mail.submitted": ("queue_id", "uid", "user", "sender"),
    "mail.sent": ("queue_id", "recipient", "relay", "domain", "local"),
    "mail.deferred": ("queue_id", "recipient", "relay", "domain", "local"),
    "mail.bounced": ("queue_id", "recipient", "relay", "domain", "local"),
}

EVENTS: dict[str, tuple[str, ...]] = {  # type: every field a rule may match
    etype: fields
    + ANY_EVENT
    + (() if etype in ("web.request", "web.error", "process.exec") else MESSAGE_FIELDS)
    for etype, fields in OWN_FIELDS.items()
}

SECTIONS: dict[str, str] = {  # name: what it holds
    "accounts": "accounts, with their password status",
    "groups": "groups and their members",
    "shell_history": "shell history files (size and times)",
    "sudo_rules": "sudoers lines, per file",
    "sudo_files": "sudoers files",
    "authorized_keys": "authorized SSH keys, by fingerprint",
    "sshd_config": "sshd configuration lines, per file and Match block",
    "ssh_files": "sshd configuration files, key files and .ssh directories",
    "pam": "PAM configuration and module files",
    "pam_rules": "PAM configuration lines, per file",
    "cron": "cron and at files",
    "systemd": "systemd units, drop-ins and generators",
    "startup": "start-up scripts and shell start-up files",
    "hooks": "package-manager hooks and udev rules",
    "crash_dumps": "crash dumps",
    "kernel_modules": "loaded kernel modules",
    "package_changes": "package files that differ from their package",
    "checksum_store": "the package managers' own checksum lists",
    "privileged_files": "set-user-ID, set-group-ID, capability and device files, in system directories and elsewhere",
    "unowned_executables": "executables in system directories that no package installed",
    "unusual_files": "unusual files in writable and web directories",
    "web_files": "executable or script files in web roots",
    "listeners": "listening and raw sockets, with their programs",
    "peers": "outbound connections open at collection, by program and remote network and port",
    "network_files": "resolver, hosts, TCP-wrapper and firewall configuration files",
    "interfaces": "network interfaces: flags, state, bridges",
    "firewall_rules": "the firewall's loaded rules, line by line",
    "log_config": "journald, rsyslog, audit and SELinux configuration files",
    "software_files": "package repositories (text) and signing keys (hashes)",
    "global_packages": "Python and Node packages installed system-wide by hand",
    "logging": "SELinux and AppArmor state, journald storage, logging services and security agents running",
    "mail_files": "Postfix and Exim configuration files",
    "web_served": "the folders nginx and Apache serve (root, alias, DocumentRoot, Alias), per file",
    "containers": "Docker and Podman containers: image, privilege, capabilities, namespaces, devices, mounts",
    "mail_config": "mail server settings: relay host, trusted networks, relay restrictions, services",
}


# C.1: each check's bands, its lowest and highest, as the checker's docs/checks.md
# gives them at the pinned commit (its Band column, and the bands its What column
# names: web.worker_child is high, an interpreter medium). Two checks have no row
# there and are written by hand from docs/scoring.md: a second UID 0 account is
# critical; a reboot is low, or info when an operator's.
RATIOS = {"info": 1.0, "low": 1.5, "medium": 4.0, "high": 20.0, "critical": 100.0}
ORDER = ("info", "low", "medium", "high", "critical")
BY_HAND = {"account.uid0": ("critical", "critical"), "system.reboot": ("info", "low")}


def read_bands(doc: str) -> dict[str, tuple[str, str]]:
    """(lowest, highest) band of each check in the checker's docs/checks.md."""
    import re

    rows: list[str] = []
    for line in doc.splitlines():
        if (
            rows
            and rows[-1].startswith("| `")
            and not rows[-1].rstrip().endswith("|")
            and (line.strip() and not line.startswith("|"))
        ):
            rows[-1] += " " + line  # a row written over several lines
        else:
            rows.append(line)
    words = re.compile(r"\b(info|low|medium|high|critical)\b")
    out: dict[str, tuple[str, str]] = {}
    heads: list[str] | None = None
    for line in rows:
        if line.startswith("| Check |"):
            heads = [h.strip().lower() for h in line.strip().strip("|").split("|")]
            continue
        m = re.match(r"\| `([a-z_]+\.[a-z_]+)` \|", line)
        if not (m and heads and "band" in heads):
            continue
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        band = cells[heads.index("band")] if len(cells) > heads.index("band") else ""
        found = words.findall(band.lower()) + words.findall(cells[1].lower())
        if found:
            out[m[1]] = (min(found, key=ORDER.index), max(found, key=ORDER.index))
    return out | BY_HAND


def ceiling(check: str) -> float:
    """The most a pack may raise this check's findings to: one band over its
    highest (docs/scoring.md), and never more than the critical band's 100."""
    top = BANDS[check][1]
    return RATIOS[ORDER[min(ORDER.index(top) + 1, len(ORDER) - 1)]]


def floor(check: str) -> float:
    """At or below this a pack's ratio raises none of the check's findings."""
    return RATIOS[BANDS[check][0]]


BANDS: dict[str, tuple[str, str]] = {  # id: (lowest band, highest); read_bands at the commit
    "account.changes": ("medium", "medium"),
    "account.log_changes": ("low", "high"),
    "account.password": ("info", "low"),
    "account.uid0": ("critical", "critical"),
    "agent.stopped": ("high", "high"),
    "clock.jump": ("low", "medium"),
    "container.host_namespace": ("medium", "medium"),
    "container.new": ("low", "low"),
    "container.privileged": ("medium", "high"),
    "files.backdated": ("low", "low"),
    "files.deceptive": ("medium", "high"),
    "files.dev": ("medium", "high"),
    "files.privileged": ("high", "high"),
    "files.scratch": ("medium", "high"),
    "files.unowned": ("info", "high"),
    "files.web": ("high", "high"),
    "group.privileged": ("high", "high"),
    "history.disabled": ("medium", "high"),
    "kernel.core_dump": ("info", "medium"),
    "kernel.errors": ("low", "low"),
    "kernel.oom_kill": ("low", "medium"),
    "kernel.segfault": ("low", "medium"),
    "kernel.taint": ("medium", "critical"),
    "logs.cleared": ("medium", "high"),
    "logs.journald_config": ("high", "high"),
    "logs.stopped": ("high", "high"),
    "mac.disabled": ("medium", "high"),
    "mail.domains": ("medium", "medium"),
    "mail.relay": ("medium", "medium"),
    "mail.volume": ("medium", "medium"),
    "mail.web_user": ("medium", "medium"),
    "net.config": ("medium", "medium"),
    "net.directory": ("medium", "high"),
    "net.firewall_comment": ("medium", "medium"),
    "net.listener": ("low", "low"),
    "net.managed_chain": ("medium", "medium"),
    "net.metadata": ("low", "medium"),
    "net.peer": ("low", "low"),
    "net.promiscuous": ("low", "medium"),
    "net.transfer": ("low", "low"),
    "net.tunnel": ("medium", "medium"),
    "package.changed": ("critical", "critical"),
    "pam.changes": ("medium", "medium"),
    "persistence.at_jobs": ("medium", "medium"),
    "persistence.changes": ("low", "high"),
    "persistence.homes": ("info", "low"),
    "persistence.ld_preload": ("high", "critical"),
    "process.executable": ("high", "high"),
    "process.hidden": ("critical", "critical"),
    "process.injected": ("low", "high"),
    "process.miner": ("high", "high"),
    "process.reverse_shell": ("high", "high"),
    "software.global": ("low", "low"),
    "software.packages": ("low", "low"),
    "software.repository": ("low", "medium"),
    "software.tools": ("low", "medium"),
    "ssh.authorized_keys": ("high", "high"),
    "ssh.guessed": ("high", "high"),
    "ssh.login": ("medium", "medium"),
    "ssh.login_hours": ("low", "low"),
    "sshd.config": ("medium", "high"),
    "sudo.rules": ("high", "high"),
    "system.reboot": ("info", "low"),
    "web.errors": ("low", "low"),
    "web.exploit": ("info", "medium"),
    "web.new_script_hit": ("high", "high"),
    "web.noise": ("info", "info"),
    "web.worker_child": ("medium", "high"),
}
