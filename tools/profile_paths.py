#!/usr/bin/env python3
"""Resolve profile placeholders in plan paths to directories on this machine.

A placeholder expands to a full directory and must start the path, for example
"<chrome-profile>/Login Data". Runs use the directory the product created on
this machine. Synthetic runs use the usual product directory when none exists;
real runs leave that entry unresolved.

Discovery checks the native macOS and Linux locations, honors XDG_CONFIG_HOME
for Electron and Chromium-family applications, and also checks snap and flatpak
roots for Chrome, Chromium, Brave, Edge, and Firefox.
"""
import os
import re
import stat
import sys
from pathlib import Path

TOKEN = re.compile(r"<([a-z0-9-]+)>")

PROFILE_NAMES = ("chrome-profile", "brave-profile", "edge-profile", "firefox-profile",
                 "trae-storage", "openclaw-config", "openclaw-home")

# macOS relative root, native Linux config-relative roots, snap names, flatpak app ids.
CHROMIUM = {
    "chrome-profile": {
        "macos": "Google/Chrome",
        "linux": ("google-chrome", "chromium"),
        "snap": ("chromium",),
        "flatpak": ("com.google.Chrome", "org.chromium.Chromium"),
    },
    "brave-profile": {
        "macos": "BraveSoftware/Brave-Browser",
        "linux": ("BraveSoftware/Brave-Browser",),
        "snap": ("brave",),
        "flatpak": ("com.brave.Browser",),
    },
    "edge-profile": {
        "macos": "Microsoft Edge",
        "linux": ("microsoft-edge",),
        "snap": ("microsoft-edge",),
        "flatpak": ("com.microsoft.Edge",),
    },
}


def default_home():
    return Path.home()


def _config_home(home):
    configured = os.environ.get("XDG_CONFIG_HOME")
    if configured and configured.startswith("/"):
        return Path(configured)
    return home / ".config"


def usual_profile(name, home, platform=None):
    """Return the usual profile directory for a product on macOS or Linux."""
    home = Path(home)
    platform = platform or sys.platform
    if name in CHROMIUM:
        spec = CHROMIUM[name]
        if platform == "darwin":
            return home / "Library/Application Support" / spec["macos"] / "Default"
        if platform.startswith("linux"):
            return _config_home(home) / spec["linux"][0] / "Default"
    elif name == "firefox-profile":
        if platform == "darwin":
            return home / "Library/Application Support/Firefox/Profiles/spite.default-release"
        if platform.startswith("linux"):
            return home / ".mozilla/firefox/spite.default-release"
    elif name == "trae-storage":
        if platform == "darwin":
            return home / "Library/Application Support/Trae/User/globalStorage"
        if platform.startswith("linux"):
            return _config_home(home) / "Trae/User/globalStorage"
    elif name == "openclaw-config":
        if platform == "darwin" or platform.startswith("linux"):
            return _config_home(home) / "openclaw"
    elif name == "openclaw-home":
        if platform == "darwin" or platform.startswith("linux"):
            return home / ".openclaw"
    if name not in PROFILE_NAMES:
        raise ValueError("Unknown profile placeholder: <{}>".format(name))
    raise ValueError("Synthetic profile paths are supported only on macOS and Linux")


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
    return next((profile for profile in candidates
                 if profile.name == "Default" or re.fullmatch(r"Profile [0-9]+", profile.name)), None)


def _read_ini(path):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise OSError("Cannot safely read profiles.ini on this platform")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return {}
        with os.fdopen(descriptor, encoding="utf-8", errors="replace") as handle:
            descriptor = None
            lines = handle.read().splitlines()
    finally:
        if descriptor is not None:
            os.close(descriptor)

    sections = {}
    current = None
    for line in lines:
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
    try:
        sections = _read_ini(ini)
    except OSError:
        sections = {}
    if sections:
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
            populated = [p for p in candidates if (p / "logins.json").exists()]
            if populated:
                return populated[0]
    return None


def _chromium_roots(name, home):
    spec = CHROMIUM[name]
    yield home / "Library/Application Support" / spec["macos"]
    config = _config_home(home)
    for relative in spec["linux"]:
        yield config / relative
    for snap in spec["snap"]:
        base = home / "snap" / snap
        for relative in spec["linux"]:
            yield base / "current/.config" / relative
            yield base / "common/.config" / relative
            yield base / "common" / relative
    for app in spec["flatpak"]:
        base = home / ".var/app" / app / "config"
        for relative in spec["linux"]:
            yield base / relative


def _firefox_roots(home):
    return (
        home / "Library/Application Support/Firefox",
        home / ".mozilla/firefox",
        home / "snap/firefox/common/.mozilla/firefox",
        home / ".var/app/org.mozilla.firefox/.mozilla/firefox",
    )


def discover(name, home):
    if name in CHROMIUM:
        for root in _chromium_roots(name, home):
            try:
                profile = _chromium_profile(root)
            except OSError:
                continue
            if profile is not None:
                return profile
        return None
    if name == "firefox-profile":
        for root in _firefox_roots(home):
            try:
                profile = _firefox_profile(root)
            except OSError:
                continue
            if profile is not None:
                return profile
        return None
    if name == "trae-storage":
        for root in (home / "Library/Application Support/Trae/User/globalStorage",
                     _config_home(home) / "Trae/User/globalStorage"):
            if root.is_dir() and not root.is_symlink():
                return root
        return None
    if name == "openclaw-config":
        for root in (_config_home(home) / "openclaw", home / ".config/openclaw"):
            if root.is_dir() and not root.is_symlink():
                return root
        return None
    if name == "openclaw-home":
        root = home / ".openclaw"
        return root if root.is_dir() and not root.is_symlink() else None
    return None


def resolve(raw, workspace, source, home=None, platform=None):
    """Return the concrete absolute Path for one plan entry, or None when unresolved."""
    home = home or default_home()
    unresolved = []

    def replace(match):
        if match.start() != 0:
            raise ValueError("A path placeholder must start the path: " + raw)
        name = match.group(1)
        if name == "workspace":
            return str(workspace)
        if name not in PROFILE_NAMES:
            raise ValueError("Unknown path placeholder: <{}>".format(name))
        try:
            found = discover(name, home)
        except OSError:
            found = None
        if found is None and source == "synthetic":
            found = usual_profile(name, home, platform=platform)
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
