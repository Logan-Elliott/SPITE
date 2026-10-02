#!/usr/bin/env python3
"""Resolve profile placeholders in plan paths to directories on this machine.

A placeholder expands to a full directory and must start the path, for example
"<chrome-profile>/Login Data". Synthetic runs map every placeholder to an
isolated directory under the user's home so they never touch a real profile.
Real runs discover the directory the product created on this machine, or leave
the entry unresolved when the product is not installed.
"""
import re
from pathlib import Path

TOKEN = re.compile(r"<([a-z0-9-]+)>")

SYNTHETIC_ROOT = ".asrt-exercise"
SYNTHETIC_NAMES = {
    "chrome-profile": "chrome",
    "brave-profile": "brave",
    "edge-profile": "edge",
    "firefox-profile": "firefox",
    "trae-storage": "trae",
    "openclaw-config": "openclaw-config",
    "openclaw-home": "openclaw-home",
}

# macOS relative root first, then Linux relative root(s).
CHROMIUM_ROOTS = {
    "chrome-profile": ("Google/Chrome", "google-chrome", "chromium"),
    "brave-profile": ("BraveSoftware/Brave-Browser",),
    "edge-profile": ("Microsoft Edge", "microsoft-edge"),
}


def default_home():
    return Path.home()


def _chromium_profile(root):
    if not root.is_dir() or root.is_symlink():
        return None
    candidates = []
    default = root / "Default"
    if default.is_dir() and not default.is_symlink():
        candidates.append(default)
    candidates.extend(sorted(p for p in root.iterdir()
                             if p.is_dir() and not p.is_symlink() and p not in candidates))
    for profile in candidates:
        if (profile / "Login Data").exists() or (profile / "Network/Cookies").exists():
            return profile
    return candidates[0] if candidates else None


def _read_ini(path):
    sections = {}
    current = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections[current] = {}
        elif "=" in line and current:
            key, _, value = line.partition("=")
            sections[current][key.strip()] = value.strip()
    return sections


def _firefox_profile(root):
    if not root.is_dir() or root.is_symlink():
        return None
    ini = root / "profiles.ini"
    if ini.is_file():
        sections = _read_ini(ini)
        profiles = [v for k, v in sections.items() if k.lower().startswith("profile") and v.get("Path")]
        ordered = [v for v in profiles if v.get("Default") == "1"]
        ordered += [v for v in profiles if v not in ordered]
        installs = [v for k, v in sections.items() if k.lower().startswith("install") and v.get("Default")]
        for values in ordered + installs:
            relative = values.get("Path") or values.get("Default")
            if not relative or relative == "1":
                continue
            candidate = root / relative
            if candidate.is_dir() and not candidate.is_symlink():
                return candidate
    profiles_dir = root / "Profiles"
    for base in (profiles_dir, root):
        if base.is_dir() and not base.is_symlink():
            candidates = sorted(p for p in base.iterdir() if p.is_dir() and not p.is_symlink())
            preferred = [p for p in candidates if ".default" in p.name]
            if preferred:
                return preferred[0]
            if candidates:
                return candidates[0]
    return None


def _chromium_roots(name, home):
    macos, *linux = CHROMIUM_ROOTS[name]
    yield home / "Library/Application Support" / macos
    for relative in linux:
        yield home / ".config" / relative


def _firefox_roots(home):
    return (
        home / "Library/Application Support/Firefox",
        home / ".mozilla/firefox",
        home / "snap/firefox/common/.mozilla/firefox",
        home / ".var/app/org.mozilla.firefox/.mozilla/firefox",
    )


def discover(name, home):
    if name in CHROMIUM_ROOTS:
        for root in _chromium_roots(name, home):
            profile = _chromium_profile(root)
            if profile is not None:
                return profile
        return None
    if name == "firefox-profile":
        for root in _firefox_roots(home):
            profile = _firefox_profile(root)
            if profile is not None:
                return profile
        return None
    if name == "trae-storage":
        for root in (home / "Library/Application Support/Trae/User/globalStorage",
                     home / ".config/Trae/User/globalStorage"):
            if root.is_dir() and not root.is_symlink():
                return root
        return None
    if name in ("openclaw-config", "openclaw-home"):
        root = home / (".config/openclaw" if name == "openclaw-config" else ".openclaw")
        return root if root.is_dir() and not root.is_symlink() else None
    return None


def resolve(raw, workspace, source, home=None):
    """Return the concrete absolute Path for one plan entry, or None when unpublished."""
    home = home or default_home()
    unresolved = []

    def replace(match):
        if match.start() != 0:
            raise ValueError("A path placeholder must start the path: " + raw)
        name = match.group(1)
        if name == "workspace":
            return str(workspace)
        if name not in SYNTHETIC_NAMES:
            raise ValueError("Unknown path placeholder: <{}>".format(name))
        if source == "synthetic":
            return str(home / SYNTHETIC_ROOT / SYNTHETIC_NAMES[name])
        found = discover(name, home)
        if found is None:
            unresolved.append(name)
            return name
        return str(found)

    text = TOKEN.sub(replace, raw)
    if unresolved:
        return None
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise ValueError("A path placeholder must start the path: " + raw)
    return path
