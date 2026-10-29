"""Pure decision logic for SentinelOne path exclusions: validation, breadth guard, duplicates.

Kept in sync with the ``Create Path Exclusion`` Sumo Logic SOAR action so both delivery
paths refuse and warn about the same paths.
"""

import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from typing import Final, Literal

from purple_mcp.libs.agents.client import ApiObject

# Legacy exclusion modes (POST /web/api/v2.1/exclusions, data.mode) and their console names.
MODES: Final[dict[str, str]] = {
    "suppress": "Suppress Alerts",
    "disable_in_process_monitor": "Interoperability",
    "disable_in_process_monitor_deep": "Interoperability - Extended",
    "disable_all_monitors": "Performance Focus",
    "disable_all_monitors_deep": "Performance Focus - Extended",
}
WINDOWS_ONLY_MODES: Final[frozenset[str]] = frozenset(
    {"disable_in_process_monitor", "disable_in_process_monitor_deep"}
)
EXTENDED_MODES: Final[frozenset[str]] = frozenset({"disable_all_monitors_deep"})
OS_TYPES: Final[tuple[str, ...]] = ("windows", "macos", "linux")
PATH_TYPES: Final[tuple[str, ...]] = ("file", "folder", "subfolders")
SCOPE_LEVELS: Final[tuple[str, ...]] = ("group", "site")
MAX_DESCRIPTION: Final = 500
MAX_PATH_LENGTH: Final = 1000

# Only system variables are expanded by the agent (4.6+); user variables like %USERPROFILE% are not.
WINDOWS_ENV_VARS: Final[frozenset[str]] = frozenset(
    {
        "programfiles",
        "programfiles(x86)",
        "programw6432",
        "systemdrive",
        "windir",
        "systemroot",
        "programdata",
        "allusersprofile",
        "public",
        "commonprogramfiles",
        "comspec",
        "homedrive",
    }
)

# Breadth guard. "?" in a pattern = any single path segment; a trailing "*" is a prefix match.
_Pattern = tuple[str, ...]
WINDOWS_BLOCKED: Final[tuple[_Pattern, ...]] = (
    (),
    ("users",),
    ("users", "?"),
    ("users", "?", "appdata"),
    ("users", "?", "appdata", "local"),
    ("users", "?", "appdata", "roaming"),
    ("users", "?", "appdata", "locallow"),
    ("users", "?", "documents"),
    ("users", "?", "onedrive*"),
    ("program files",),
    ("program files (x86)",),
    ("programdata",),
    ("%programfiles%",),
    ("%programfiles(x86)%",),
    ("%programdata%",),
    ("%systemdrive%",),
    ("perflogs",),
    ("$recycle.bin",),
)
WINDOWS_BLOCKED_PREFIXES: Final[tuple[_Pattern, ...]] = (
    ("windows",),
    ("%windir%",),
    ("%systemroot%",),
)
POSIX_BLOCKED: Final[tuple[_Pattern, ...]] = (
    (),
    ("users",),
    ("users", "?"),
    ("users", "?", "library"),
    ("users", "?", "documents"),
    ("library",),
    ("applications",),
    ("private",),
    ("private", "var"),
    ("var",),
    ("usr",),
    ("usr", "bin"),
    ("usr", "sbin"),
    ("usr", "local"),
    ("usr", "local", "bin"),
    ("usr", "lib"),
    ("bin",),
    ("sbin",),
    ("lib",),
    ("opt",),
    ("opt", "homebrew"),
    ("opt", "homebrew", "bin"),
    ("volumes",),
    ("home",),
    ("home", "?"),
    ("etc",),
    ("root",),
    ("dev",),
    ("proc",),
    ("snap",),
)
POSIX_BLOCKED_PREFIXES: Final[tuple[_Pattern, ...]] = (
    ("system",),
    ("private", "etc"),
    ("boot",),
)
# Malware staging locations: never excluded, wherever they appear.
STAGING_SEGMENTS: Final[frozenset[str]] = frozenset(
    {"temp", "tmp", "downloads", "desktop", "inetcache", "$recycle.bin"}
)
# Script hosts / LOLBins: excluding them blinds the agent to most attacks.
BLOCKED_FILES: Final[frozenset[str]] = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "msiexec.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "schtasks.exe",
        "explorer.exe",
        "svchost.exe",
        "lsass.exe",
        "conhost.exe",
        "osascript",
        "bash",
        "sh",
        "zsh",
        "dash",
        "curl",
        "wget",
        "launchctl",
        "sudo",
    }
)
INTERPRETERS: Final[frozenset[str]] = frozenset(
    {
        "python.exe",
        "pythonw.exe",
        "node.exe",
        "java.exe",
        "javaw.exe",
        "python",
        "python3",
        "node",
        "java",
        "perl",
        "ruby",
        "php",
    }
)

ExclusionStatus = Literal["ready", "rejected", "already_exists", "already_covered"]


def segments(path: str, os_type: str) -> list[str]:
    """Lower-cased path segments without drive/volume prefix and trailing separator or ``*``."""
    value = path.strip().lower()
    if os_type == "windows":
        value = re.sub(r"^\\device\\harddiskvolume\d+", "", value)
        value = re.sub(r"^[a-z\*\?]:", "", value)
        parts = value.split("\\")
    else:
        parts = value.split("/")
    parts = [part for part in parts if part]
    while parts and parts[-1] == "*":
        parts.pop()
    return parts


def segments_match(pattern: Sequence[str], segs: Sequence[str]) -> bool:
    """Return whether ``segs`` matches ``pattern`` segment by segment (same length)."""
    if len(pattern) != len(segs):
        return False
    for pat, seg in zip(pattern, segs, strict=True):
        if pat == "?":
            continue
        if pat.endswith("*") and seg.startswith(pat[:-1]):
            continue
        if pat != seg:
            return False
    return True


def default_path_type(path: str) -> str:
    """Infer the S1 ``pathExclusionType``: a trailing separator or ``*`` means sub-folders."""
    return "subfolders" if path.rstrip().endswith(("\\", "/", "\\*", "/*")) else "file"


def _mode_problems(mode: str, os_type: str, allow_extended: bool) -> list[str]:
    if mode not in MODES:
        return [f'Unsupported mode "{mode}". Allowed: {", ".join(MODES)}.']
    problems = []
    if mode in WINDOWS_ONLY_MODES and os_type != "windows":
        problems.append(f"{MODES[mode]} ({mode}) is only available on Windows.")
    if mode in EXTENDED_MODES and not allow_extended:
        problems.append(
            f"{MODES[mode]} also stops monitoring of child processes; "
            "set allow_extended=true to use it."
        )
    return problems


def _syntax_problems(path: str, os_type: str) -> list[str]:
    problems = []
    if len(path) > MAX_PATH_LENGTH:
        problems.append(f"Path is longer than {MAX_PATH_LENGTH} characters.")
    if any(char in path for char in '\r\n\t"<>|'):
        problems.append('Path contains a newline, tab or one of " < > |.')
    if "**" in path:
        problems.append('"**" is not a valid S1 wildcard.')
    if os_type == "windows":
        return problems + _windows_syntax_problems(path)
    if not path.startswith("/"):
        problems.append(f"{os_type} paths must be absolute (start with /).")
    if "\\" in path:
        problems.append(f"{os_type} paths use forward slashes.")
    return problems


def _windows_syntax_problems(path: str) -> list[str]:
    problems = []
    if "/" in path:
        problems.append("Windows paths use backslashes.")
    for var in re.findall(r"%([^%]+)%", path):
        if var.lower() not in WINDOWS_ENV_VARS:
            problems.append(f"%{var}% is not supported; only system environment variables are.")
    if re.match(r"^[\*\?]:", path):
        problems.append(
            "The drive letter cannot be a wildcard; drop the drive to match every drive."
        )
    return problems


def _breadth_problems(path: str, segs: list[str], os_type: str) -> list[str]:
    problems = []
    blocked, prefixes = (
        (WINDOWS_BLOCKED, WINDOWS_BLOCKED_PREFIXES)
        if os_type == "windows"
        else (POSIX_BLOCKED, POSIX_BLOCKED_PREFIXES)
    )
    if segs and "*" in segs[0]:
        problems.append("Wildcard in the first folder level would match whole drives/volumes.")
    if any(segments_match(pattern, segs) for pattern in blocked):
        problems.append(
            f'"{path}" is a system-wide or per-user root folder; excluding it removes visibility '
            "for too much. Exclude the specific application folder instead."
        )
    if any(segments_match(pattern, segs[: len(pattern)]) for pattern in prefixes):
        problems.append("Operating system folders cannot be excluded through this tool.")
    staging = next((seg for seg in segs if seg in STAGING_SEGMENTS), None)
    if staging:
        problems.append(f'Path goes through "{staging}", a common malware staging location.')
    if segs and segs[-1] in BLOCKED_FILES:
        problems.append(
            f'"{segs[-1]}" is a script host / LOLBin; excluding it blinds the agent to most attacks.'
        )
    return problems


def _warnings(path: str, segs: list[str], os_type: str, mode: str, path_type: str) -> list[str]:
    warnings = []
    name = segs[-1] if segs else ""
    if os_type == "windows" and re.search(r"%[^%]+%", path):
        warnings.append("Environment variables need agent 4.6 or later.")
    if name in INTERPRETERS:
        warnings.append(
            f'"{name}" is an interpreter: everything it runs loses monitoring. '
            "Prefer excluding the script folder."
        )
    if path_type != "file" and len([seg for seg in segs if "*" not in seg]) <= 2:
        warnings.append(f"Broad folder ({len(segs)} level(s) deep) with sub-folders included.")
    if "*" in path.rstrip("*\\/") or "?" in path:
        warnings.append("Wildcards widen the match beyond a single folder.")
    if path_type == "file" and not re.search(r"\.[a-z0-9]{1,6}$", name):
        warnings.append(
            "No trailing separator and no file extension: this is treated as a single FILE. "
            "End the path with \\ or / to exclude a folder."
        )
    if mode.startswith("disable_all_monitors"):
        warnings.append(
            "Performance Focus turns off most behavioral monitoring for this path, and it "
            "applies after the process or endpoint restarts."
        )
    elif mode.startswith("disable_in_process_monitor"):
        warnings.append(
            "Interoperability stops in-process monitoring (DLL injection) for this path; "
            "applies after the process restarts."
        )
    return warnings


def validate_exclusion(
    path: str, os_type: str, mode: str, path_type: str, allow_extended: bool = False
) -> tuple[list[str], list[str]]:
    """Check a proposed path exclusion.

    Returns:
        ``(problems, warnings)``. Any problem means the exclusion must be refused.
    """
    segs = segments(path, os_type)
    problems = [
        *_mode_problems(mode, os_type, allow_extended),
        *_syntax_problems(path, os_type),
        *_breadth_problems(path, segs, os_type),
    ]
    return problems, _warnings(path, segs, os_type, mode, path_type)


def find_existing(
    exclusions: Sequence[ApiObject], path: str, os_type: str
) -> tuple[list[ApiObject], list[ApiObject]]:
    """Split existing exclusions into exact matches and sub-folder exclusions covering ``path``."""
    target = segments(path, os_type)
    exact: list[ApiObject] = []
    covering: list[ApiObject] = []
    for item in exclusions:
        other = segments(str(item.get("value") or ""), os_type)
        if other == target:
            exact.append(item)
        elif (
            item.get("pathExclusionType") == "subfolders"
            and other
            and segments_match(other, target[: len(other)])
        ):
            covering.append(item)
    return exact, covering


def build_description(
    approved_by: str, reason: str, computer_name: str | None, reference: str | None
) -> str:
    """Audit string stored on the exclusion: who approved it, for which endpoint, and why."""
    text = (
        f"[MCP] Approved by: {approved_by} | Ref: {reference or '-'} | "
        f"Endpoint: {computer_name or '-'} | Reason: {reason}"
    )
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > MAX_DESCRIPTION:
        text = text[: MAX_DESCRIPTION - 3] + "..."
    return text


def exclusion_summary(item: ApiObject) -> dict[str, object]:
    """Compact view of an exclusion record for tool output."""
    return {
        "id": item.get("id"),
        "value": item.get("value"),
        "os_type": item.get("osType"),
        "mode": item.get("mode"),
        "path_exclusion_type": item.get("pathExclusionType"),
        "scope": item.get("scopeName"),
        "scope_path": item.get("scopePath"),
        "description": item.get("description"),
        "created_by": item.get("userName"),
        "created_at": item.get("createdAt"),
    }


@dataclass(frozen=True)
class ExclusionPlan:
    """What creating one path exclusion would do, before anything is sent."""

    status: ExclusionStatus
    agent_id: str
    computer_name: str | None
    path: str
    os_type: str
    path_type: str
    mode: str
    mode_name: str | None
    scope_level: str
    scope_id: str | None
    scope_name: str | None
    description: str
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    existing: list[dict[str, object]] = field(default_factory=list)
    covering: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable view of the plan."""
        return asdict(self)

    def request_body(self) -> dict[str, object]:
        """Body for ``POST /web/api/v2.1/exclusions``."""
        scope_key = "groupIds" if self.scope_level == "group" else "siteIds"
        return {
            "filter": {scope_key: [self.scope_id]},
            "data": {
                "type": "path",
                "value": self.path,
                "osType": self.os_type,
                "pathExclusionType": self.path_type,
                "mode": self.mode,
                "description": self.description,
            },
        }
