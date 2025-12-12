#!/usr/bin/env python3
"""
WireGuard Namespace Manager (Python port)

Description: Manage multiple isolated WireGuard tunnels and Xray proxy
instances using Linux network namespaces. Each tunnel runs in its own
namespace with automatic Xray setup.

This is a mostly feature-equivalent translation of the original
`setup-wg.sh` Bash script.
"""

import hashlib
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import time
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# Colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"


def run_cmd(
    cmd: str,
    check: bool = False,
    capture_output: bool = True,
    ns: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a shell command, optionally inside a network namespace."""
    if ns:
        # For commands with pipes or complex shell operations, use shell=True
        # but wrap in ip netns exec for security
        if "|" in cmd or ">" in cmd or "<" in cmd or "&&" in cmd or ";" in cmd:
            # Complex command with pipes - use shell but with proper quoting
            full_cmd = f"ip netns exec {shlex.quote(ns)} sh -c {shlex.quote(cmd)}"
            return subprocess.run(
                full_cmd,
                shell=True,
                check=check,
                capture_output=capture_output,
                text=True,
            )
        else:
            # Simple command - use list format for better security
            cmd_parts = shlex.split(cmd)
            full_cmd_list = ["ip", "netns", "exec", ns] + cmd_parts
            return subprocess.run(
                full_cmd_list,
                check=check,
                capture_output=capture_output,
                text=True,
            )
    else:
        # For commands without namespace, use shell for compatibility
        return subprocess.run(
            cmd,
            shell=True,
            check=check,
            capture_output=capture_output,
            text=True,
        )


def require_root() -> None:
    """Check if script is running as root, exit if not."""
    if os.geteuid() != 0:
        print(f"{RED}This script must be run as root{NC}")
        sys.exit(1)


def command_exists(cmd: str) -> bool:
    """Check if a command exists in the system PATH."""
    return subprocess.run(
        ["bash", "-lc", f"command -v {shlex.quote(cmd)} >/dev/null 2>&1"],
        capture_output=True,
    ).returncode == 0


def check_and_install_dependencies() -> None:
    print(f"{BLUE}Checking dependencies...{NC}")
    missing = []

    if not command_exists("wg"):
        missing.append("wireguard-tools")
    if not command_exists("ip"):
        missing.append("iproute2")
    if not command_exists("iptables"):
        missing.append("iptables")
    if not command_exists("curl"):
        missing.append("curl")
    if not command_exists("ss"):
        missing.append("iproute2")

    # WireGuard kernel module
    lsmod = run_cmd("lsmod | grep -q wireguard", capture_output=False)
    if lsmod.returncode != 0:
        modprobe = run_cmd("modprobe wireguard", capture_output=False)
        if modprobe.returncode != 0:
            missing.append("wireguard-dkms")

    if not missing:
        print(f"{GREEN}All dependencies are installed.{NC}")
        return

    print(f"{YELLOW}Missing dependencies: {' '.join(missing)}{NC}")
    ans = input(f"{YELLOW}Do you want to install them automatically? (y/n){NC}\n> ")
    if ans.lower() != "y":
        print(f"{RED}Please install the following packages manually:{NC}")
        print(" ", " ".join(missing))
        sys.exit(1)

    # Detect package manager
    pkg_manager = None
    update_cmd = ""
    install_cmd = ""
    if command_exists("apt-get"):
        pkg_manager = "apt-get"
        update_cmd = "apt-get update"
        install_cmd = "apt-get install -y"
    elif command_exists("yum"):
        pkg_manager = "yum"
        update_cmd = "yum check-update || true"
        install_cmd = "yum install -y"
    elif command_exists("dnf"):
        pkg_manager = "dnf"
        update_cmd = "dnf check-update || true"
        install_cmd = "dnf install -y"
    else:
        print(f"{RED}Could not detect package manager. Please install manually.{NC}")
        sys.exit(1)

    print(f"{BLUE}Updating package list...{NC}")
    run_cmd(update_cmd, capture_output=False)

    pkgs_to_install = []
    for dep in missing:
        if dep == "wireguard-tools":
            pkgs_to_install.append("wireguard-tools")
        elif dep == "wireguard-dkms":
            if pkg_manager == "apt-get":
                pkgs_to_install.append("wireguard-dkms")
            else:
                pkgs_to_install.append("wireguard")
        elif dep == "iproute2":
            pkgs_to_install.append("iproute2")
        elif dep == "iptables":
            pkgs_to_install.append("iptables")
        elif dep == "curl":
            pkgs_to_install.append("curl")

    pkgs_to_install = sorted(set(pkgs_to_install))

    if pkgs_to_install:
        print(f"{BLUE}Installing: {' '.join(pkgs_to_install)}{NC}")
        res = run_cmd(
            f"{install_cmd} {' '.join(pkgs_to_install)}", capture_output=False
        )
        if res.returncode != 0:
            print(f"{RED}Installation failed. Please install manually.{NC}")
            sys.exit(1)

    # Try to load wireguard again
    modprobe = run_cmd("modprobe wireguard", capture_output=False)
    if modprobe.returncode != 0:
        print(
            f"{YELLOW}Warning: Could not load wireguard module. You may need to reboot.{NC}"
        )

    print(f"{GREEN}Dependencies installed successfully!{NC}\n")


def _shorten_path(path: str, max_len: int = 40) -> str:
    """Shorten long paths from the left, keeping the filename visible."""
    if len(path) <= max_len:
        return path
    # Keep last `max_len - 3` chars and prefix with "..."
    return "..." + path[-(max_len - 3) :]


def _get_current_uuid_count() -> Optional[int]:
    """Return how many UUIDs/users are currently in the panel DB, if possible.

    For Marzban we count rows in `users` (live from DB) so the number displayed
    on the first page exactly matches the number of users in the panel.
    Otherwise we fall back to the last loaded UUID count.
    """
    global PANEL_DB_PATH, PANEL_PANEL_NAME, LAST_UUID_COUNT

    db_path = PANEL_DB_PATH
    if not db_path or not os.path.isfile(db_path):
        return LAST_UUID_COUNT

    # For Marzban, use live COUNT(*) from users table
    if PANEL_PANEL_NAME == "marzban":
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) FROM "users"')
            (cnt,) = cur.fetchone()
            conn.close()
            return int(cnt)
        except Exception as e:  # pragma: no cover - defensive
            debug_log(f"header_uuid_count: marzban count(*) failed: {e!r}")
            return LAST_UUID_COUNT

    return LAST_UUID_COUNT


def show_header() -> None:
    global UUID_WATCHER_STARTED
    os.system("clear")
    print(f"{BLUE}╔════════════════════════════════════════════════════╗{NC}")
    print(f"{BLUE}║        WireGuard Namespace Manager                 ║{NC}")
    print(f"{BLUE}╚════════════════════════════════════════════════════╝{NC}")
    print("Repo: https://github.com/alihm-us/WireGuard-Namespace-Manager\n")

    # Panel / UUID status line
    panel = PANEL_PANEL_NAME or "Not set"
    db_path = PANEL_DB_PATH or "N/A"
    uuid_count = _get_current_uuid_count()

    print(f"{YELLOW}Panel:{NC} {panel}")
    print(f"{YELLOW}DB:{NC}    {_shorten_path(db_path)}")
    if uuid_count is None:
        print(f"{YELLOW}UUIDs:{NC} N/A (select panel DB in Xray management)")
    else:
        print(f"{YELLOW}UUIDs:{NC} {GREEN}{uuid_count}{NC} loaded from panel DB")
    
    # Display Auto-Refresh Watcher status
    if UUID_WATCHER_STARTED:
        config = load_config()
        interval = config.get("uuid_refresh_interval", 5)
        watcher_status = f"{GREEN}Active{NC} (refreshing every {interval} seconds)"
    else:
        watcher_status = f"{YELLOW}Not started{NC}"
    print(f"{YELLOW}Auto-Refresh:{NC} {watcher_status}")
    print()


GEO_CACHE: Dict[str, str] = {}

# Simple log file for UUID refresh/debug info
DEBUG_LOG_FILE = "/tmp/setup-wg-watch.log"

# Small state file so we remember chosen panel DB across runs
PANEL_STATE_FILE = "/tmp/setup-wg-panel.state"

# Setup state file to restore tunnels after reboot
SETUP_STATE_FILE = "/etc/setup-wg-tunnels.state"
SETUP_STATE_DIR = "/etc/setup-wg"

# Main configuration file
CONFIG_FILE = "/etc/setup-wg/config.json"


def debug_log(message: str) -> None:
    """Append a timestamped debug line to the watcher log."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    try:
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception:
        # Logging must never break the script
        pass


# Global panel DB info (set the first time user chooses a panel)
PANEL_DB_PATH: Optional[str] = None
PANEL_PANEL_NAME: Optional[str] = None

# Background watcher state
UUID_WATCHER_STARTED = False
MARZBAN_LOG_WATCHER_STARTED = False
UUID_WATCHER_LOCK = threading.Lock()  # Thread safety for watcher

# Last known UUID stats (updated whenever we successfully read from panel DB)
LAST_UUID_COUNT: Optional[int] = None
LAST_UUID_UPDATE_TS: Optional[float] = None
LAST_UUID_HASH: Optional[str] = None  # Hash of UUID list to detect changes

# UUID file path (one file per namespace/port)
UUID_FILE_DIR = "/tmp/setup-wg-uuids"
UUID_HASH_FILE = os.path.join(UUID_FILE_DIR, "last_hash.txt")
UUID_DB_MTIME_FILE = os.path.join(UUID_FILE_DIR, "last_db_mtime.txt")

# Ensure UUID file directory exists
os.makedirs(UUID_FILE_DIR, exist_ok=True)


def load_last_uuid_hash() -> Optional[str]:
    """Load last UUID hash from file to persist across process restarts."""
    if not os.path.isfile(UUID_HASH_FILE):
        return None
    try:
        with open(UUID_HASH_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return None


def save_last_uuid_hash(hash_value: str) -> None:
    """Save UUID hash to file to persist across process restarts."""
    try:
        with open(UUID_HASH_FILE, "w", encoding="utf-8") as f:
            f.write(hash_value)
    except Exception as e:
        debug_log(f"save_last_uuid_hash: failed to save: {e!r}")


def get_db_mtime(db_path: str) -> Optional[float]:
    """Get database file modification time."""
    try:
        return os.path.getmtime(db_path)
    except Exception:
        return None


def load_last_db_mtime() -> Optional[float]:
    """Load last DB mtime from file."""
    if not os.path.isfile(UUID_DB_MTIME_FILE):
        return None
    try:
        with open(UUID_DB_MTIME_FILE, "r", encoding="utf-8") as f:
            return float(f.read().strip())
    except Exception:
        return None


def save_last_db_mtime(mtime: float) -> None:
    """Save DB mtime to file."""
    try:
        with open(UUID_DB_MTIME_FILE, "w", encoding="utf-8") as f:
            f.write(str(mtime))
    except Exception as e:
        debug_log(f"save_last_db_mtime: failed to save: {e!r}")


def save_uuids_to_file(port: int, uuids: List[str]) -> None:
    """Save UUIDs to a text file for this port."""
    uuid_file = os.path.join(UUID_FILE_DIR, f"uuids-{port}.txt")
    try:
        with open(uuid_file, "w", encoding="utf-8") as f:
            for uuid in sorted(uuids):  # Sort for consistency
                f.write(f"{uuid}\n")
        debug_log(f"save_uuids: saved {len(uuids)} UUID(s) to {uuid_file}")
    except Exception as e:
        debug_log(f"save_uuids: failed to save to {uuid_file}: {e!r}")


def get_uuids_hash(uuids: List[str]) -> str:
    """Calculate hash of UUID list to detect changes."""
    sorted_uuids = sorted(uuids)
    uuid_string = "\n".join(sorted_uuids)
    return hashlib.md5(uuid_string.encode("utf-8")).hexdigest()


def load_uuids_from_file(port: int) -> Optional[List[str]]:
    """Load UUIDs from text file for this port."""
    uuid_file = os.path.join(UUID_FILE_DIR, f"uuids-{port}.txt")
    if not os.path.isfile(uuid_file):
        return None
    try:
        with open(uuid_file, "r", encoding="utf-8") as f:
            uuids = [line.strip() for line in f if line.strip()]
        return uuids
    except Exception as e:
        debug_log(f"load_uuids: failed to load from {uuid_file}: {e!r}")
        return None


def load_config() -> Dict:
    """Load main configuration from file.
    
    Returns:
        Dictionary with configuration values. Returns default config if file doesn't exist.
    """
    default_config = {
        "panel_type": None,  # "x-ui" or "marzban"
        "panel_db_path": None,
        "uuid_refresh_interval": 5,  # seconds
        "auto_restore_enabled": True,
        "setup_completed": False
    }
    
    if not os.path.isfile(CONFIG_FILE):
        return default_config
    
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
        # Merge with defaults to ensure all keys exist
        for key, value in default_config.items():
            if key not in config:
                config[key] = value
        debug_log(f"load_config: loaded from {CONFIG_FILE}")
        return config
    except Exception as e:
        debug_log(f"load_config: failed to load: {e!r}, using defaults")
        return default_config


def save_config(config: Dict) -> None:
    """Save main configuration to file."""
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        debug_log(f"save_config: saved to {CONFIG_FILE}")
    except Exception as e:
        debug_log(f"save_config: failed to save: {e!r}")


def setup_wizard() -> None:
    """First-time setup wizard to configure the script."""
    print(f"\n{BLUE}{'='*60}{NC}")
    print(f"{BLUE}  WireGuard Namespace Manager - First Time Setup{NC}")
    print(f"{BLUE}{'='*60}{NC}\n")
    
    print(f"{YELLOW}This wizard will help you configure the script.{NC}\n")
    
    config = load_config()
    
    # Panel selection
    print(f"{BLUE}1. Panel Selection:{NC}")
    print("   Which panel are you using?")
    print("   1) x-ui")
    print("   2) Marzban")
    print("   3) None (skip)")
    
    while True:
        choice = input(f"{YELLOW}Select (1-3): {NC}").strip()
        if choice == "1":
            config["panel_type"] = "x-ui"
            default_db = "/etc/x-ui/x-ui.db"
            break
        elif choice == "2":
            config["panel_type"] = "marzban"
            default_db = "/var/lib/marzban/db.sqlite3"
            break
        elif choice == "3":
            config["panel_type"] = None
            config["panel_db_path"] = None
            break
        else:
            print(f"{RED}Invalid choice. Please enter 1, 2, or 3.{NC}")
    
    # Database path
    if config["panel_type"]:
        print(f"\n{BLUE}2. Database Path:{NC}")
        print(f"   Default for {config['panel_type']}: {default_db}")
        db_path = input(f"{YELLOW}Enter database path (or press Enter for default): {NC}").strip()
        if db_path:
            config["panel_db_path"] = db_path
        else:
            config["panel_db_path"] = default_db
        
        # Verify database exists
        if not os.path.isfile(config["panel_db_path"]):
            print(f"{YELLOW}⚠ Warning: Database file not found at {config['panel_db_path']}{NC}")
            print(f"{YELLOW}   You can change this later from the menu.{NC}")
    
    # UUID refresh interval
    print(f"\n{BLUE}3. UUID Refresh Interval:{NC}")
    print("   How often should the script check for new UUIDs? (in seconds)")
    while True:
        try:
            interval = input(f"{YELLOW}Enter interval (default: 5): {NC}").strip()
            if not interval:
                interval = 5
            else:
                interval = int(interval)
            if interval < 1:
                print(f"{RED}Interval must be at least 1 second.{NC}")
                continue
            config["uuid_refresh_interval"] = interval
            break
        except ValueError:
            print(f"{RED}Invalid input. Please enter a number.{NC}")
    
    # Auto-restore
    print(f"\n{BLUE}4. Auto-Restore After Reboot:{NC}")
    print("   Should tunnels be automatically restored after server reboot?")
    while True:
        choice = input(f"{YELLOW}Enable auto-restore? (y/n, default: y): {NC}").strip().lower()
        if not choice or choice == "y":
            config["auto_restore_enabled"] = True
            break
        elif choice == "n":
            config["auto_restore_enabled"] = False
            break
        else:
            print(f"{RED}Invalid choice. Please enter y or n.{NC}")
    
    # Setup systemd service if auto-restore is enabled
    if config["auto_restore_enabled"]:
        service_file = "/etc/systemd/system/setup-wg-restore.service"
        if not os.path.isfile(service_file):
            print(f"\n{BLUE}5. Setting up systemd service...{NC}")
            script_path = os.path.abspath(__file__)
            service_content = f"""[Unit]
Description=WireGuard Namespace Manager - Restore Tunnels After Reboot
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {script_path} --restore
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
            try:
                with open(service_file, "w", encoding="utf-8") as f:
                    f.write(service_content)
                run_cmd("systemctl daemon-reload", capture_output=False)
                run_cmd("systemctl enable setup-wg-restore.service", capture_output=False)
                print(f"{GREEN}✓ Systemd service configured and enabled{NC}")
            except Exception as e:
                print(f"{RED}✗ Failed to setup systemd service: {e}{NC}")
                print(f"{YELLOW}You can set it up later from the menu (option 8).{NC}")
    
    # Mark setup as completed
    config["setup_completed"] = True
    
    # Save config
    save_config(config)
    
    # Update global variables
    global PANEL_DB_PATH, PANEL_PANEL_NAME
    if config["panel_type"]:
        PANEL_PANEL_NAME = config["panel_type"]
        PANEL_DB_PATH = config["panel_db_path"]
        save_panel_state()
    
    # Start UUID watcher in background if panel is configured
    if config["panel_type"] and config["panel_db_path"]:
        print(f"\n{BLUE}Starting UUID auto-refresh watcher...{NC}")
        if start_background_uuid_watcher():
            interval = config.get("uuid_refresh_interval", 5)
            print(f"{GREEN}✓ UUID Auto-Refresh Watcher started (every {interval} seconds){NC}")
            print(f"{BLUE}  UUIDs will be automatically updated from panel every {interval} seconds{NC}")
            print(f"{BLUE}  New users will be able to connect automatically{NC}")
        else:
            print(f"{YELLOW}⚠ Could not start UUID watcher automatically{NC}")
            print(f"{YELLOW}  You can start it manually from the menu{NC}")
    
    print(f"\n{GREEN}{'='*60}{NC}")
    print(f"{GREEN}  Setup completed successfully!{NC}")
    print(f"{GREEN}{'='*60}{NC}\n")
    
    input("Press Enter to continue...")


def load_panel_state() -> None:
    """Load previously chosen panel DB path (if any) from disk."""
    global PANEL_DB_PATH, PANEL_PANEL_NAME
    
    # First try to load from main config
    config = load_config()
    if config.get("panel_type") and config.get("panel_db_path"):
        PANEL_PANEL_NAME = config["panel_type"]
        PANEL_DB_PATH = config["panel_db_path"]
        debug_log(f"panel_state: loaded from config: panel={PANEL_PANEL_NAME}, db={PANEL_DB_PATH}")
        return
    
    # Fallback to old state file
    if not os.path.isfile(PANEL_STATE_FILE):
        return
    try:
        with open(PANEL_STATE_FILE, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f.readlines() if ln.strip()]
        if len(lines) >= 2:
            PANEL_PANEL_NAME = lines[0]
            PANEL_DB_PATH = lines[1]
            debug_log(
                f"panel_state: loaded from {PANEL_STATE_FILE}: "
                f"panel={PANEL_PANEL_NAME}, db={PANEL_DB_PATH}"
            )
    except Exception as e:
        debug_log(f"panel_state: failed to load: {e}")


def save_panel_state() -> None:
    """Persist currently selected panel DB info so auto-refreshers can reuse it."""
    global PANEL_DB_PATH, PANEL_PANEL_NAME
    if not PANEL_DB_PATH or not PANEL_PANEL_NAME:
        return
    try:
        with open(PANEL_STATE_FILE, "w", encoding="utf-8") as f:
            f.write(f"{PANEL_PANEL_NAME}\n{PANEL_DB_PATH}\n")
        debug_log(
            f"panel_state: saved to {PANEL_STATE_FILE}: "
            f"panel={PANEL_PANEL_NAME}, db={PANEL_DB_PATH}"
        )
    except Exception as e:
        debug_log(f"panel_state: failed to save: {e}")


def save_setup_state(port: int, wg_config_path: str) -> None:
    """Save tunnel setup state to file for auto-restore after reboot."""
    try:
        os.makedirs(SETUP_STATE_DIR, exist_ok=True)
        state_file = os.path.join(SETUP_STATE_DIR, f"tunnel-{port}.state")
        with open(state_file, "w", encoding="utf-8") as f:
            f.write(f"{port}\n{wg_config_path}\n")
        debug_log(f"save_setup_state: saved tunnel {port} with config {wg_config_path}")
    except Exception as e:
        debug_log(f"save_setup_state: failed to save tunnel {port}: {e!r}")


def delete_setup_state(port: int) -> None:
    """Delete tunnel setup state file."""
    try:
        state_file = os.path.join(SETUP_STATE_DIR, f"tunnel-{port}.state")
        if os.path.isfile(state_file):
            os.remove(state_file)
            debug_log(f"delete_setup_state: removed state for tunnel {port}")
    except Exception as e:
        debug_log(f"delete_setup_state: failed to delete tunnel {port}: {e!r}")


def load_all_setup_states() -> List[Tuple[int, str]]:
    """Load all saved tunnel states.
    
    Returns:
        List of (port, wg_config_path) tuples.
    """
    tunnels = []
    if not os.path.isdir(SETUP_STATE_DIR):
        return tunnels
    
    try:
        for filename in os.listdir(SETUP_STATE_DIR):
            if not filename.startswith("tunnel-") or not filename.endswith(".state"):
                continue
            state_file = os.path.join(SETUP_STATE_DIR, filename)
            try:
                with open(state_file, "r", encoding="utf-8") as f:
                    lines = [ln.strip() for ln in f.readlines() if ln.strip()]
                if len(lines) >= 2:
                    port = int(lines[0])
                    wg_config_path = lines[1]
                    if os.path.isfile(wg_config_path):
                        tunnels.append((port, wg_config_path))
                    else:
                        debug_log(f"load_all_setup_states: config file not found: {wg_config_path}, removing state")
                        os.remove(state_file)
            except (ValueError, IndexError, OSError) as e:
                debug_log(f"load_all_setup_states: error reading {state_file}: {e!r}")
    except OSError as e:
        debug_log(f"load_all_setup_states: error listing {SETUP_STATE_DIR}: {e!r}")
    
    return tunnels


def restore_setup(port: int, wg_config_path: str) -> bool:
    """Restore a single tunnel setup from saved state.
    
    Returns:
        True if restore was successful, False otherwise.
    """
    ns_name = f"ns-{port}"
    
    # Check if namespace already exists
    ns_list = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'").stdout.split()
    if ns_name in ns_list:
        debug_log(f"restore_setup: namespace {ns_name} already exists, skipping")
        return True
    
    print(f"{BLUE}Restoring tunnel on port {port}...{NC}")
    debug_log(f"restore_setup: restoring port {port} with config {wg_config_path}")
    
    # Recreate setup using existing create_setup logic
    # We'll extract the relevant parts
    subnet_octet = (port % 250) + 2
    veth_host = f"veth-{port}"
    veth_ns = f"vpeer-{port}"
    host_ip = f"10.100.{subnet_octet}.1"
    ns_ip = f"10.100.{subnet_octet}.2"
    subnet = f"10.100.{subnet_octet}.0/24"
    
    # Resolve endpoint
    endpoint_host, endpoint_ip = resolve_endpoint_ip(wg_config_path)
    if not endpoint_ip:
        print(f"{RED}Could not resolve endpoint: {endpoint_host}{NC}")
        debug_log(f"restore_setup: failed to resolve endpoint for {wg_config_path}")
        return False
    
    # Create namespace and veth
    if run_cmd(f"ip netns add {shlex.quote(ns_name)}", capture_output=False).returncode != 0:
        debug_log(f"restore_setup: failed to create namespace {ns_name}")
        return False
    
    run_cmd(f"ip link delete {shlex.quote(veth_host)} 2>/dev/null || true", capture_output=False)
    time.sleep(1)
    if run_cmd(
        f"ip link add {shlex.quote(veth_host)} type veth peer name {shlex.quote(veth_ns)}",
        capture_output=False,
    ).returncode != 0:
        debug_log(f"restore_setup: failed to create veth pair")
        run_cmd(f"ip netns delete {shlex.quote(ns_name)} 2>/dev/null || true", capture_output=False)
        return False
    
    run_cmd(f"ip link set {shlex.quote(veth_host)} up", capture_output=False)
    run_cmd(f"ip addr flush dev {shlex.quote(veth_host)} 2>/dev/null || true", capture_output=False)
    run_cmd(f"ip addr add {host_ip}/24 dev {shlex.quote(veth_host)}", capture_output=False)
    
    run_cmd(f"ip link set {shlex.quote(veth_ns)} netns {shlex.quote(ns_name)}", capture_output=False)
    run_cmd("ip link set lo up", ns=ns_name, capture_output=False)
    run_cmd(f"ip link set {shlex.quote(veth_ns)} up", ns=ns_name, capture_output=False)
    run_cmd(f"ip addr flush dev {shlex.quote(veth_ns)} 2>/dev/null || true", ns=ns_name, capture_output=False)
    run_cmd(f"ip addr add {ns_ip}/24 dev {shlex.quote(veth_ns)}", ns=ns_name, capture_output=False)
    
    # WireGuard setup
    wg_name = ""
    if command_exists("md5sum"):
        res = run_cmd(f"echo {port} | md5sum | cut -c1-8")
        wg_name = f"wg-{res.stdout.strip()}"
    elif command_exists("md5"):
        res = run_cmd(f"echo {port} | md5 | cut -c1-8")
        wg_name = f"wg-{res.stdout.strip()}"
    else:
        wg_name = f"wg-{(port * 31):08x}"[:11]
    
    wg_address = "10.0.0.2/32"
    with open(wg_config_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip().lower().startswith("address"):
                wg_address = line.split("=", 1)[1].strip()
                break
    
    run_cmd(f"ip netns exec {shlex.quote(ns_name)} ip link delete {shlex.quote(wg_name)} 2>/dev/null || true", capture_output=False)
    run_cmd(f"ip link delete {shlex.quote(wg_name)} 2>/dev/null || true", capture_output=False)
    time.sleep(1)
    
    if run_cmd(f"ip link add {shlex.quote(wg_name)} type wireguard", capture_output=False).returncode != 0:
        debug_log(f"restore_setup: failed to create WireGuard interface")
        run_cmd(f"ip link delete {shlex.quote(veth_host)} 2>/dev/null || true", capture_output=False)
        run_cmd(f"ip netns delete {shlex.quote(ns_name)} 2>/dev/null || true", capture_output=False)
        return False
    
    filter_cmd = (
        r"grep -vE '^(Address|DNS|Table|MTU|PreUp|PostUp|PreDown|PostDown)' "
        f"{shlex.quote(wg_config_path)} | wg setconf {shlex.quote(wg_name)} /dev/stdin"
    )
    if run_cmd(filter_cmd, capture_output=False).returncode != 0:
        debug_log(f"restore_setup: failed to configure WireGuard")
        run_cmd(f"ip link delete {shlex.quote(wg_name)} 2>/dev/null || true", capture_output=False)
        run_cmd(f"ip link delete {shlex.quote(veth_host)} 2>/dev/null || true", capture_output=False)
        run_cmd(f"ip netns delete {shlex.quote(ns_name)} 2>/dev/null || true", capture_output=False)
        return False
    
    run_cmd(f"ip link set {shlex.quote(wg_name)} netns {shlex.quote(ns_name)}", capture_output=False)
    run_cmd(f"ip addr add {wg_address} dev {shlex.quote(wg_name)}", ns=ns_name, capture_output=False)
    run_cmd(f"ip link set {shlex.quote(wg_name)} up", ns=ns_name, capture_output=False)
    
    # Routing
    run_cmd("ip route flush table main 2>/dev/null || true", ns=ns_name, capture_output=False)
    run_cmd("ip route flush table 100 2>/dev/null || true", ns=ns_name, capture_output=False)
    run_cmd(
        f"ip route add 10.100.{subnet_octet}.0/24 dev {shlex.quote(veth_ns)} proto kernel scope link src {ns_ip}",
        ns=ns_name,
        capture_output=False,
    )
    run_cmd(f"ip route add {endpoint_ip}/32 via {host_ip}", ns=ns_name, capture_output=False)
    run_cmd(f"ip route add default dev {shlex.quote(wg_name)}", ns=ns_name, capture_output=False)
    run_cmd(f"ip route add default via {host_ip} dev {shlex.quote(veth_ns)} table 100", ns=ns_name, capture_output=False)
    run_cmd(f"ip rule add fwmark 1 lookup 100", ns=ns_name, capture_output=False)
    run_cmd(f"iptables -t mangle -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -s {ns_ip} -j MARK --set-mark 1", ns=ns_name, capture_output=False)
    
    # NAT & firewall
    run_cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null", capture_output=False)
    run_cmd(f"iptables -t nat -A POSTROUTING -o {shlex.quote(wg_name)} -j MASQUERADE", ns=ns_name, capture_output=False)
    run_cmd(f"iptables -t nat -D POSTROUTING -s {subnet} ! -o {veth_host} -j MASQUERADE 2>/dev/null || true", capture_output=False)
    run_cmd(f"iptables -t nat -A POSTROUTING -s {subnet} ! -o {veth_host} -j MASQUERADE", capture_output=False)
    
    # DNAT + FORWARD
    for proto in ("tcp", "udp"):
        run_cmd(f"iptables -t nat -D PREROUTING -p {proto} --dport {port} -j DNAT --to-destination {ns_ip}:{port} 2>/dev/null || true", capture_output=False)
        run_cmd(f"iptables -t nat -A PREROUTING -p {proto} --dport {port} -j DNAT --to-destination {ns_ip}:{port}", capture_output=False)
        run_cmd(f"iptables -D FORWARD -p {proto} -d {ns_ip}/32 --dport {port} -j ACCEPT 2>/dev/null || true", capture_output=False)
        run_cmd(f"iptables -I FORWARD 1 -p {proto} -d {ns_ip}/32 --dport {port} -j ACCEPT", capture_output=False)
        run_cmd(f"iptables -D FORWARD -p {proto} -s {ns_ip}/32 -j ACCEPT 2>/dev/null || true", capture_output=False)
        run_cmd(f"iptables -I FORWARD 1 -p {proto} -s {ns_ip}/32 -j ACCEPT", capture_output=False)
    
    # DNS
    etc_ns = f"/etc/netns/{ns_name}"
    os.makedirs(etc_ns, exist_ok=True)
    with open(os.path.join(etc_ns, "resolv.conf"), "w", encoding="utf-8") as f:
        f.write("nameserver 1.1.1.1\n")
    
    # Start Xray - force restart to ensure it starts after restore
    if ensure_xray_binary():
        refresh_uuids_for_all_namespaces(interactive=False, force_restart=True)
    
    print(f"{GREEN}✓ Tunnel on port {port} restored{NC}")
    debug_log(f"restore_setup: successfully restored tunnel {port}")
    return True


def find_wg_config_for_port(port: int) -> Optional[str]:
    """Try to find WireGuard config file for a given port.
    
    Searches common locations and patterns.
    """
    possible_configs = [
        f"/root/wg-{port}.conf",
        f"/root/wg{port}.conf",
        f"/root/ns-{port}.conf",
        f"/etc/wireguard/wg-{port}.conf",
        f"/etc/wireguard/wg{port}.conf",
        f"/root/.config/wireguard/wg-{port}.conf",
    ]
    
    # Check common locations
    for config_path in possible_configs:
        if os.path.isfile(config_path):
            return config_path
    
    # Search in /root for any .conf file with port in name
    if os.path.isdir("/root"):
        try:
            for filename in os.listdir("/root"):
                if filename.endswith(".conf") and str(port) in filename:
                    config_path = os.path.join("/root", filename)
                    if os.path.isfile(config_path):
                        return config_path
        except OSError:
            pass
    
    # Search in /etc/wireguard
    if os.path.isdir("/etc/wireguard"):
        try:
            for filename in os.listdir("/etc/wireguard"):
                if filename.endswith(".conf") and str(port) in filename:
                    config_path = os.path.join("/etc/wireguard", filename)
                    if os.path.isfile(config_path):
                        return config_path
        except OSError:
            pass
    
    return None


def scan_wg_config_files() -> List[Tuple[int, str]]:
    """Scan for WireGuard config files and try to extract port from filename.
    
    Returns:
        List of (port, config_path) tuples.
    """
    tunnels = []
    search_dirs = ["/root", "/etc/wireguard"]
    
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        
        try:
            for filename in os.listdir(search_dir):
                if not filename.endswith(".conf"):
                    continue
                
                config_path = os.path.join(search_dir, filename)
                if not os.path.isfile(config_path):
                    continue
                
                # Try to extract port from filename
                # Patterns: wg-{port}.conf, wg{port}.conf, ns-{port}.conf, etc.
                import re
                port_match = re.search(r'(\d+)', filename)
                if port_match:
                    try:
                        port = int(port_match.group(1))
                        # Verify it's a valid WireGuard config
                        try:
                            with open(config_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                if '[Interface]' in content or 'PrivateKey' in content:
                                    tunnels.append((port, config_path))
                                    debug_log(f"scan_wg_config_files: found config {config_path} for port {port}")
                        except (OSError, UnicodeDecodeError):
                            continue
                    except ValueError:
                        continue
        except OSError:
            continue
    
    return tunnels


def detect_existing_tunnels() -> List[Tuple[int, str]]:
    """Detect existing tunnels from namespaces, iptables, or config files.
    
    Returns:
        List of (port, wg_config_path) tuples. Config path may be empty if not found.
    """
    tunnels = []
    
    # First, try to find from existing namespaces
    res = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'", capture_output=True)
    namespaces = [n for n in res.stdout.splitlines() if n.startswith("ns-")]
    
    if namespaces:
        debug_log(f"detect_existing_tunnels: found {len(namespaces)} namespace(s)")
        
        for ns_name in namespaces:
            # Extract port from namespace name (ns-{port})
            try:
                port = int(ns_name.split("-")[1])
            except (ValueError, IndexError):
                continue
            
            # Get namespace IP to verify it's a valid tunnel
            res_ip = run_cmd(
                "ip -4 addr show 2>/dev/null "
                "| grep -E 'inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' "
                "| awk '{print $2}' | cut -d'/' -f1 | grep '^10\\.100' | head -1",
                ns=ns_name,
            )
            ns_ip = res_ip.stdout.strip()
            
            if not ns_ip:
                continue
            
            # Try to find WireGuard config file
            wg_config_path = find_wg_config_for_port(port)
            
            tunnels.append((port, wg_config_path or ""))
            debug_log(f"detect_existing_tunnels: found tunnel port {port} in {ns_name}, config: {wg_config_path or 'not found'}")
    
    # If no namespaces found, scan for config files
    if not tunnels:
        debug_log("detect_existing_tunnels: no namespaces found, scanning for config files")
        scanned = scan_wg_config_files()
        tunnels.extend(scanned)
        debug_log(f"detect_existing_tunnels: scanned and found {len(scanned)} config file(s)")
    
    return tunnels


def restore_all_setups() -> None:
    """Restore all saved tunnel setups after reboot."""
    tunnels = load_all_setup_states()
    
    # If no saved states, try to detect existing tunnels
    if not tunnels:
        debug_log("restore_all_setups: no saved tunnels found, trying to detect existing tunnels")
        detected = detect_existing_tunnels()
        if detected:
            print(f"{YELLOW}No saved state found, but detected {len(detected)} existing tunnel(s).{NC}")
            print(f"{YELLOW}These tunnels are already running. Saving state for future restores...{NC}\n")
            
            # Save states for detected tunnels
            for port, wg_config_path in detected:
                if wg_config_path and os.path.isfile(wg_config_path):
                    save_setup_state(port, wg_config_path)
                    print(f"{GREEN}✓ Saved state for tunnel on port {port}{NC}")
                else:
                    print(f"{YELLOW}⚠ Tunnel on port {port} found but config file not found. Please recreate.{NC}")
            
            tunnels = load_all_setup_states()
    
    if not tunnels:
        print(f"{YELLOW}No tunnels to restore.{NC}")
        print(f"{YELLOW}If you had tunnels before reboot, they may not have been saved.{NC}")
        print(f"{YELLOW}Please recreate them using option 1 from the menu.{NC}\n")
        debug_log("restore_all_setups: no tunnels to restore")
        return
    
    print(f"{BLUE}=== Restoring {len(tunnels)} tunnel(s) after reboot ==={NC}\n")
    debug_log(f"restore_all_setups: found {len(tunnels)} tunnel(s) to restore")
    
    restored_count = 0
    for port, wg_config_path in tunnels:
        try:
            # Check if namespace already exists
            ns_name = f"ns-{port}"
            ns_list = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'").stdout.split()
            if ns_name in ns_list:
                print(f"{YELLOW}⚠ Tunnel on port {port} already exists, skipping{NC}")
                debug_log(f"restore_all_setups: tunnel {port} already exists")
                continue
            
            if not wg_config_path or not os.path.isfile(wg_config_path):
                print(f"{RED}✗ Config file not found for port {port}: {wg_config_path}{NC}")
                debug_log(f"restore_all_setups: config not found for port {port}")
                continue
            
            if restore_setup(port, wg_config_path):
                restored_count += 1
        except Exception as e:
            debug_log(f"restore_all_setups: failed to restore tunnel {port}: {e!r}")
            print(f"{RED}✗ Failed to restore tunnel on port {port}: {e}{NC}")
    
    # After restoring all tunnels, ensure Xray is started for all of them
    # This is important because restore_setup() may have been called before panel state was loaded
    global PANEL_DB_PATH
    if restored_count > 0 or tunnels:
        debug_log("restore_all_setups: ensuring Xray is started for all restored tunnels")
        # Load panel state if not already loaded
        load_panel_state()
        # Force refresh to start Xray for all namespaces
        if PANEL_DB_PATH and os.path.isfile(PANEL_DB_PATH):
            refresh_uuids_for_all_namespaces(interactive=False, force_restart=True)
    
    if restored_count > 0:
        print(f"\n{GREEN}✓ Successfully restored {restored_count} tunnel(s)!{NC}\n")
    else:
        print(f"\n{YELLOW}No tunnels were restored (they may already be running).{NC}\n")


def refresh_uuids_for_all_namespaces_noninteractive() -> None:
    """
    Non-interactive wrapper: only refresh if PANEL_DB_PATH is already set
    and points to an existing DB; otherwise just log and skip.
    
    This function is called every 5 seconds to fetch UUIDs from the panel
    and restart Xray with the new list.
    """
    global PANEL_DB_PATH

    # If panel/DB is not set in this process, try to load from disk state
    if not PANEL_DB_PATH:
        load_panel_state()

    db_path = PANEL_DB_PATH
    if not db_path or not os.path.isfile(db_path):
        # If DB is not set, just log but don't stop the watcher
        # This keeps the watcher always active and waiting for DB to be set
        return

    # If DB exists, refresh UUIDs
    try:
        refresh_uuids_for_all_namespaces()
    except Exception as e:
        # Never stop the watcher, just log
        debug_log(f"refresh_uuids_for_all_namespaces_noninteractive error: {e!r}")


def start_uuid_watcher(interval_seconds: int = 5) -> None:
    """
    Start a background thread that refreshes UUIDs for all namespaces
    every `interval_seconds` seconds.
    
    This watcher is always active and reads UUIDs from the panel every interval_seconds
    and restarts Xray with the new list so new users can also connect.
    """
    global UUID_WATCHER_STARTED, UUID_WATCHER_LOCK
    
    with UUID_WATCHER_LOCK:
        if UUID_WATCHER_STARTED:
            debug_log("UUID watcher already started, skipping")
            return
        UUID_WATCHER_STARTED = True

    def _loop() -> None:
        debug_log(f"UUID watcher started with interval={interval_seconds}s")
        debug_log(f"Watcher will refresh UUIDs every {interval_seconds} seconds to keep user list updated")
        
        consecutive_errors = 0
        max_consecutive_errors = 10
        
        while True:
            try:
                # Every interval_seconds, fetch UUIDs from panel and restart Xray
                refresh_uuids_for_all_namespaces_noninteractive()
                consecutive_errors = 0  # Reset error counter on success
            except KeyboardInterrupt:
                # Allow graceful shutdown
                debug_log("UUID watcher interrupted by user")
                break
            except Exception as e:
                consecutive_errors += 1
                debug_log(f"UUID watcher error (attempt {consecutive_errors}/{max_consecutive_errors}): {e!r}")
                
                # If consecutive errors are too many, wait a bit longer
                if consecutive_errors >= max_consecutive_errors:
                    debug_log(f"Too many consecutive errors, waiting {interval_seconds * 2}s before retry")
                    time.sleep(interval_seconds * 2)
                    consecutive_errors = 0
                else:
                    time.sleep(interval_seconds)
                continue
            
            # Sleep after successful refresh
            time.sleep(interval_seconds)

    t = threading.Thread(target=_loop, daemon=True, name="UUID-Watcher")
    t.start()
    debug_log("UUID watcher thread started successfully")


def ensure_uuid_watcher_service() -> bool:
    """
    Ensure UUID watcher systemd service is set up and running.
    This creates a systemd service that runs the watcher independently
    of the main script process.
    
    Returns True if service is running or was successfully started, False otherwise.
    """
    service_file = "/etc/systemd/system/setup-wg-uuid-watcher.service"
    script_path = os.path.abspath(__file__)
    
    # Check if service file exists
    if not os.path.isfile(service_file):
        # Create service file
        config = load_config()
        interval = config.get("uuid_refresh_interval", 5)
        
        service_content = f"""[Unit]
Description=WireGuard Namespace Manager - UUID Auto-Refresh Watcher
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script_path} --auto-refresh
Restart=always
RestartSec=10
StandardOutput=append:/tmp/setup-wg-watch.log
StandardError=append:/tmp/setup-wg-watch.log
User=root

[Install]
WantedBy=multi-user.target
"""
        try:
            with open(service_file, "w", encoding="utf-8") as f:
                f.write(service_content)
            debug_log(f"ensure_uuid_watcher_service: created service file at {service_file}")
            
            # Reload systemd
            run_cmd("systemctl daemon-reload", capture_output=False)
            debug_log("ensure_uuid_watcher_service: systemd daemon reloaded")
            
            # Enable service
            run_cmd("systemctl enable setup-wg-uuid-watcher.service", capture_output=False)
            debug_log("ensure_uuid_watcher_service: service enabled")
        except Exception as e:
            debug_log(f"ensure_uuid_watcher_service: failed to create service: {e!r}")
            return False
    
    # Check if service is running
    status_cmd = run_cmd("systemctl is-active setup-wg-uuid-watcher.service", capture_output=True)
    if status_cmd.returncode == 0 and "active" in status_cmd.stdout.lower():
        debug_log("ensure_uuid_watcher_service: service is already running")
        return True
    
    # Try to start the service
    try:
        start_cmd = run_cmd("systemctl start setup-wg-uuid-watcher.service", capture_output=True)
        if start_cmd.returncode == 0:
            debug_log("ensure_uuid_watcher_service: service started successfully")
            return True
        else:
            debug_log(f"ensure_uuid_watcher_service: failed to start service: {start_cmd.stderr}")
            return False
    except Exception as e:
        debug_log(f"ensure_uuid_watcher_service: error starting service: {e!r}")
        return False


def start_background_uuid_watcher() -> bool:
    """
    Start UUID watcher in background. First tries to use systemd service,
    if that fails, starts as a daemon thread in current process.
    
    Returns True if watcher was started successfully, False otherwise.
    """
    # First, try to ensure systemd service is running (preferred method)
    if ensure_uuid_watcher_service():
        debug_log("start_background_uuid_watcher: using systemd service")
        return True
    
    # Fallback: start as thread in current process
    debug_log("start_background_uuid_watcher: systemd service not available, using thread")
    config = load_config()
    interval = config.get("uuid_refresh_interval", 5)
    start_uuid_watcher(interval_seconds=interval)
    return True


def start_marzban_log_watcher() -> None:
    """
    Watch Marzban logs (via docker logs -f) and refresh UUIDs whenever a new
    user is added, e.g. when a line like the following appears:

        marzban-1  | INFO:     New user "cQ0gJY" added
    """
    global MARZBAN_LOG_WATCHER_STARTED

    if MARZBAN_LOG_WATCHER_STARTED:
        return

    # Only meaningful when panel type is marzban
    if PANEL_PANEL_NAME != "marzban":
        return

    if not command_exists("marzban"):
        debug_log("marzban log watcher: 'marzban' CLI not found, disabling watcher")
        return

    MARZBAN_LOG_WATCHER_STARTED = True

    def _loop() -> None:
        debug_log("marzban log watcher started using 'marzban logs'")
        while True:
            try:
                # Follow logs; restart the loop if the command exits for any reason
                # Use list format for better security
                proc = subprocess.Popen(
                    ["marzban", "logs"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                if not proc.stdout:
                    # Should not normally happen, but be defensive
                    debug_log(
                        "marzban log watcher: no stdout from docker logs; retrying soon"
                    )
                    proc.kill()
                    time.sleep(5)
                    continue

                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    # Example: marzban-1  | INFO:     New user "cQ0gJY" added
                    if "New user" in line and "added" in line:
                        debug_log(
                            f"marzban log watcher: detected new user in logs: {line}"
                        )
                        refresh_uuids_for_all_namespaces_noninteractive()
            except Exception as e:  # pragma: no cover - defensive
                debug_log(f"marzban log watcher error: {e}")
            # In case of any failure, wait a bit and then re-attach to logs
            time.sleep(5)

def refresh_uuids_for_all_namespaces(interactive: bool = False, force_restart: bool = False) -> None:
    """Reload UUIDs from the configured panel DB and update files/restart Xray only if changed.

    This is the central place where we sync DB -> Xray in one shot.
    This function reads UUIDs from the panel and only restarts Xray if they changed
    to prevent excessive resource usage and disconnections.
    
    Args:
        interactive: If True and PANEL_DB_PATH is not set, prompts the user.
                    If False (default), only loads from state file.
        force_restart: If True, restarts Xray even if UUIDs haven't changed.
                      Useful for restore after reboot.
    """
    global PANEL_DB_PATH, LAST_UUID_COUNT, LAST_UUID_UPDATE_TS, LAST_UUID_HASH

    db_path = PANEL_DB_PATH
    if not db_path or not os.path.isfile(db_path):
        # If in interactive mode and DB is not set, ask the user
        if interactive:
            debug_log("refresh: PANEL_DB_PATH missing, calling choose_uuids_from_panel (interactive)")
            _ = choose_uuids_from_panel()
            db_path = PANEL_DB_PATH
        else:
            # In non-interactive mode, just load state
            debug_log("refresh: PANEL_DB_PATH missing, trying to load from state file")
            load_panel_state()
            db_path = PANEL_DB_PATH
        
        if not db_path or not os.path.isfile(db_path):
            debug_log("refresh: PANEL_DB_PATH still not set or file missing")
            return

    # Check if DB file has been modified (more reliable than hash for detecting changes)
    current_db_mtime = get_db_mtime(db_path)
    last_db_mtime = load_last_db_mtime()
    db_file_changed = (last_db_mtime is None or current_db_mtime != last_db_mtime)
    
    if db_file_changed:
        debug_log(f"refresh: DB file modified (mtime changed from {last_db_mtime} to {current_db_mtime})")
        # Reset hash when DB file changes to force refresh
        save_last_uuid_hash("")  # Clear old hash
    
    uuids = extract_uuids_from_sqlite(db_path)
    if not uuids:
        debug_log("refresh: no UUIDs returned from DB")
        return

    # Calculate hash of current UUIDs to detect changes
    current_uuid_hash = get_uuids_hash(uuids)
    
    # Load last hash from file (persists across process restarts)
    old_hash_from_file = load_last_uuid_hash()
    if old_hash_from_file == "":  # Was cleared due to DB change
        old_hash_from_file = None
    
    # Remember stats so header can display up-to-date count
    old_count = LAST_UUID_COUNT
    old_hash = LAST_UUID_HASH if LAST_UUID_HASH is not None else old_hash_from_file
    LAST_UUID_COUNT = len(uuids)
    LAST_UUID_UPDATE_TS = time.time()
    LAST_UUID_HASH = current_uuid_hash
    
    # Save hash and mtime to file for persistence
    save_last_uuid_hash(current_uuid_hash)
    if current_db_mtime:
        save_last_db_mtime(current_db_mtime)
    
    # Debug: log hash comparison
    debug_log(f"refresh: hash comparison - old={old_hash[:8] if old_hash else 'None'}, new={current_uuid_hash[:8]}, count={len(uuids)}, db_changed={db_file_changed}")
    
    # Check if UUIDs actually changed (either hash changed or DB file changed)
    # If force_restart is True, always restart (useful after restore)
    uuids_changed = (old_hash is None or old_hash != current_uuid_hash or db_file_changed or force_restart)
    
    if uuids_changed:
        if old_count is not None and old_count != len(uuids):
            debug_log(f"refresh: UUID count changed from {old_count} to {len(uuids)}")
        else:
            debug_log(f"refresh: UUID list changed (same count: {len(uuids)})")
    else:
        debug_log(f"refresh: UUIDs unchanged ({len(uuids)} UUIDs), skipping restart")
        # Still update the file even if no restart needed
        # Discover namespaces to update files
        res = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'")
        namespaces = [n for n in res.stdout.splitlines() if n.startswith("ns-")]
        for ns in namespaces:
            res_ip = run_cmd(
                "ip -4 addr show 2>/dev/null "
                "| grep -E 'inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' "
                "| awk '{print $2}' | cut -d'/' -f1 | grep '^10\\.100' | head -1",
                ns=ns,
            )
            ns_ip = res_ip.stdout.strip()
            if not ns_ip:
                continue
            res_port = run_cmd(
                f"iptables -t nat -S PREROUTING 2>/dev/null | grep 'to-destination {ns_ip}' "
                "| head -1 | awk -F':' '{print $NF}' | awk '{print $1}'"
            )
            port_str = res_port.stdout.strip()
            if port_str.isdigit():
                port = int(port_str)
                save_uuids_to_file(port, uuids)
        return  # No restart needed

    # Discover namespaces created by this tool (ns-<port>)
    res = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'")
    namespaces = [n for n in res.stdout.splitlines() if n.startswith("ns-")]
    if not namespaces:
        debug_log("refresh: no namespaces found")
        return

    debug_log(f"refresh: UUIDs changed, updating {len(namespaces)} namespace(s) with {len(uuids)} UUID(s)")

    for ns in namespaces:
        # Derive NS IP (10.100.X.2) from interface address
        res_ip = run_cmd(
            "ip -4 addr show 2>/dev/null "
            "| grep -E 'inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' "
            "| awk '{print $2}' | cut -d'/' -f1 | grep '^10\\.100' | head -1",
            ns=ns,
        )
        ns_ip = res_ip.stdout.strip()
        if not ns_ip:
            debug_log(f"refresh: {ns} has no 10.100.x.x IP")
            continue

        res_port = run_cmd(
            f"iptables -t nat -S PREROUTING 2>/dev/null | grep 'to-destination {ns_ip}' "
            "| head -1 | awk -F':' '{print $NF}' | awk '{print $1}'"
        )
        port_str = res_port.stdout.strip()
        if not port_str.isdigit():
            debug_log(f"refresh: could not infer port for {ns} (ns_ip={ns_ip})")
            continue

        port = int(port_str)
        
        # Save UUIDs to file (always update file)
        save_uuids_to_file(port, uuids)
        
        debug_log(f"refresh: syncing {ns} on port {port} with {len(uuids)} UUID(s)")

        if not ensure_xray_binary():
            debug_log(f"refresh: ensure_xray_binary failed for {ns}")
            continue

        xray_config = f"/tmp/xray-{port}.json"
        create_xray_config(
            xray_config,
            port,
            uuids,
            use_http_header=True,
            http_host="iran.ir",
            http_path="/",
        )

        # Kill existing Xray processes on this port
        res_pids = run_cmd(
            f"ss -ltnp 2>/dev/null | grep ':{port} ' | sed -n 's/.*pid=\\([0-9]*\\).*/\\1/p'",
            ns=ns,
        )
        pids = res_pids.stdout.split()
        if pids:
            debug_log(f"refresh: killing old xray PIDs in {ns}: {' '.join(pids)}")
            run_cmd(
                f"kill {' '.join(pids)} 2>/dev/null || true",
                ns=ns,
                capture_output=False,
            )
            # Wait a bit for process to terminate
            time.sleep(0.5)

        # Start new Xray with updated config
        run_cmd(
            f"nohup /usr/local/bin/xray-ns -c {shlex.quote(xray_config)} "
            f"> /tmp/xray-{port}.log 2>&1 &",
            ns=ns,
            capture_output=False,
        )
        debug_log(f"refresh: restarted xray-ns in {ns} on port {port} with {len(uuids)} UUID(s)")
        
    debug_log(f"refresh: completed updating all {len(namespaces)} namespace(s)")


def geo_lookup(ip: str) -> str:
    if not ip or ip == "N/A":
        return ""
    if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", ip):
        return ""
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    try:
        resp = run_cmd(
            f'curl -s --max-time 0.8 "http://ip-api.com/csv/{ip}?fields=status,country,city"'
        )
        line = resp.stdout.strip()
    except Exception:
        line = ""

    geo = ""
    if line:
        parts = line.split(",")
        if len(parts) >= 3 and parts[0] == "success":
            country = parts[1]
            city = parts[2]
            if country or city:
                geo = f"{city}, {country}"

    GEO_CACHE[ip] = geo
    return geo


@dataclass
class VlessConfig:
    uuid: str = ""
    network: str = "tcp"
    security: str = "none"
    header_type: str = ""
    host_header: str = ""
    path: str = "/"


UUID_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def parse_vless_uri(uri: str) -> Optional[VlessConfig]:
    """
    Parse a VLESS URI and return VlessConfig, or None on error.
    """
    if not uri:
        return None

    config = VlessConfig()
    # strip scheme
    uri = uri.replace("vless://", "", 1)
    # remove fragment
    uri = uri.split("#", 1)[0]

    if "?" in uri:
        base, query = uri.split("?", 1)
    else:
        base, query = uri, ""

    # base is uuid@host:port or just uuid
    if "@" in base:
        config.uuid = base.split("@", 1)[0]
    else:
        config.uuid = base

    if query:
        for p in query.split("&"):
            if "=" not in p:
                continue
            key, val = p.split("=", 1)
            if key == "type":
                config.network = val
            elif key == "security":
                config.security = val
            elif key == "headerType":
                config.header_type = val
            elif key == "host":
                config.host_header = val
            elif key == "path":
                config.path = val

    if config.network != "tcp":
        print(f"{RED}Only TCP VLESS URIs are supported by this script.{NC}")
        return None

    uuid_re = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    if not uuid_re.match(config.uuid):
        print(f"{RED}Invalid UUID in VLESS URI.{NC}")
        return None

    return config


def _extract_uuids_raw_file(db_path: str) -> List[str]:
    """Fallback: scan the raw SQLite file bytes and extract all UUID-looking substrings.
    
    This function reads the database file as binary and extracts UUIDs from both
    formats (text and binary) so that new UUIDs that might be in binary format
    are also found.
    """
    try:
        size = os.path.getsize(db_path)
        mtime = os.path.getmtime(db_path)
        debug_log(
            f"raw_uuid_scan: reading {db_path} (size={size} bytes, "
            f"mtime={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))})"
        )
        with open(db_path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"{RED}Failed to read database file {db_path}: {e}{NC}")
        debug_log(f"raw_uuid_scan: failed to read {db_path}: {e!r}")
        return []

    # Try UTF-8 decode first (most common case)
    text = data.decode("utf-8", errors="ignore")
    matches = set()
    if text:
        matches = set(UUID_REGEX.findall(text))
    
    # Also scan raw bytes by sliding window to catch UUIDs that might be
    # stored in binary format or with different encoding
    # UUID format: 8-4-4-4-12 hex digits with dashes (36 bytes total)
    for i in range(len(data) - 35):  # UUID is 36 chars, but we check 35 to be safe
        try:
            # Try to decode a 36-byte chunk as UTF-8
            chunk = data[i:i+36]
            chunk_str = chunk.decode("utf-8", errors="ignore")
            # Check if this chunk matches UUID pattern
            if len(chunk_str) == 36 and UUID_REGEX.match(chunk_str):
                matches.add(chunk_str)
        except (UnicodeDecodeError, IndexError):
            # Skip invalid UTF-8 sequences
            continue
    
    all_matches = sorted(matches)
    debug_log(f"raw_uuid_scan: found {len(all_matches)} unique UUID(s) in file bytes")
    return all_matches


def extract_uuids_from_sqlite(db_path: str) -> List[str]:
    """Prefer structured extraction for known schemas, then fall back to raw scan.

    Important note: This function for Marzban returns the users.uuid column values
    without removing duplicates so that if you have 97 users in the panel, 97 entries
    will be created in the Xray config.
    """
    if not os.path.isfile(db_path):
        print(f"{RED}Database file not found: {db_path}{NC}")
        return []

    uuids: List[str] = []

    # Try structured extraction first (helpful for Marzban's users.uuid, etc.)
    try:
        debug_log(f"sqlite_uuid_scan: opening DB {db_path}")
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()

        tables = [
            r[0]
            for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]

        # 1) Marzban-style: UUIDs in proxies.settings JSON field
        proxies_found = False
        if "proxies" in tables:
            cols = [
                r[1]
                for r in cur.execute('PRAGMA table_info("proxies")').fetchall()
            ]
            debug_log(f"sqlite_uuid_scan: proxies table columns: {cols}")
            if "settings" in cols and "user_id" in cols:
                proxy_count = 0
                for (settings_json, user_id) in cur.execute('SELECT settings, user_id FROM "proxies" WHERE type="VLESS"'):
                    proxy_count += 1
                    if settings_json and user_id:
                        try:
                            settings = json.loads(settings_json) if isinstance(settings_json, str) else settings_json
                            if isinstance(settings, dict) and "id" in settings:
                                uuid_val = settings["id"]
                                if isinstance(uuid_val, str) and uuid_val.strip():
                                    uuids.append(uuid_val.strip())
                                    proxies_found = True
                        except (json.JSONDecodeError, TypeError, AttributeError) as e:
                            debug_log(f"sqlite_uuid_scan: error parsing proxy settings: {e!r}")
                            continue
                debug_log(f"sqlite_uuid_scan: processed {proxy_count} VLESS proxy(ies), found {len([u for u in uuids if u])} UUID(s) from proxies")
        
        # 2) Fallback: users.uuid column (for Marzban or x-ui)
        # Always check users table - it's the primary source for Marzban
        # This ensures we get all UUIDs even if proxies table is incomplete
        if "users" in tables:
            cols = [
                r[1]
                for r in cur.execute('PRAGMA table_info("users")').fetchall()
            ]
            if "uuid" in cols:
                users_count = 0
                users_before = len(uuids)
                for (val,) in cur.execute('SELECT uuid FROM "users"'):
                    users_count += 1
                    if isinstance(val, str):
                        v = val.strip()
                        if v and v not in uuids:  # Avoid duplicates
                            uuids.append(v)
                users_added = len(uuids) - users_before
                debug_log(f"sqlite_uuid_scan: processed {users_count} user(s) from users table, added {users_added} new UUID(s)")
                debug_log(f"sqlite_uuid_scan: processed {users_count} user(s) from users table")

        debug_log(f"sqlite_uuid_scan: extracted {len(uuids)} UUID value(s) via SQL")

        # 2) If nothing from known structured sources, fall back to raw scan
    except sqlite3.Error as e:
        # Log and fall back to raw
        debug_log(f"sqlite_uuid_scan: sqlite error for {db_path}: {e!r}")
    finally:
        try:
            conn.close()  # type: ignore[name-defined]
        except Exception:
            pass

    if not uuids:
        return _extract_uuids_raw_file(db_path)

    return uuids


def choose_uuids_from_panel() -> List[str]:
    """
    Ask user if panel is x-ui or marzban, then read DB file and return all UUIDs found.
    Returns empty list on cancel/failure.
    """
    print(
        f"{YELLOW}Load UUIDs directly from your panel database?{NC}\n"
        "1) x-ui\n"
        "2) marzban\n"
        "3) Skip (use default UUID)"
    )
    choice = input("> ").strip()
    if choice not in {"1", "2"}:
        return []

    global PANEL_DB_PATH, PANEL_PANEL_NAME

    if choice == "1":
        default_db = "/etc/x-ui/x-ui.db"
        panel_name = "x-ui"
    else:
        default_db = "/var/lib/marzban/db.sqlite3"
        panel_name = "marzban"

    print(
        f"{YELLOW}Enter {panel_name} database path "
        f"(press Enter for default: {default_db}):{NC}"
    )
    db_path = input("> ").strip() or default_db
    if not os.path.isfile(db_path):
        print(f"{RED}Database file not found: {db_path}{NC}")
        return []

    # Remember chosen DB globally so background watchers can reuse it
    PANEL_DB_PATH = db_path
    PANEL_PANEL_NAME = panel_name
    debug_log(f"Panel DB set: panel={panel_name}, path={db_path}")

    # Persist selection so background/next-run processes can reuse it
    save_panel_state()

    # If this is a Marzban panel, also start the Marzban log watcher so that
    # adding new users triggers an immediate UUID refresh.
    if panel_name == "marzban":
        start_marzban_log_watcher()

    # Make sure UUID watcher is active (if not started yet)
    # Use config interval instead of hard-coded 5
    config = load_config()
    interval = config.get("uuid_refresh_interval", 5)
    start_background_uuid_watcher()

    print(f"{BLUE}Reading UUIDs from database...{NC}")
    uuids = extract_uuids_from_sqlite(db_path)
    if not uuids:
        print(f"{YELLOW}No valid UUIDs were found in the database.{NC}")
        return []

    print(f"{GREEN}Found {len(uuids)} UUIDs in {panel_name} database.{NC}")
    # Show a small preview for info
    preview = 10
    for u in uuids[:preview]:
        print(f" - {u}")
    if len(uuids) > preview:
        print(f"... and {len(uuids) - preview} more UUIDs")

    print(f"{GREEN}✓ UUID Auto-Refresh Watcher is active{NC}")
    print(f"{BLUE}  UUIDs will be automatically updated every 5 seconds{NC}")
    print(f"{BLUE}  New users will be able to connect automatically{NC}")

    # After we have a valid DB and UUID list, background watcher (started
    # from main) will keep Xray configs in sync with the panel every few
    # seconds whenever PANEL_DB_PATH is set.
    return uuids


def list_setups() -> None:
    print(f"{YELLOW}Active Setups:{NC}")
    print("------------------------------------------------------------------------")
    print(
        f"{'Namespace':<12} {'Port':<8} {'Tunnel':<10} {'Xray':<10} {'VPN IP':<15} {'Location':<25}"
    )
    print("------------------------------------------------------------------------")

    res = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'", capture_output=True)
    namespaces = [
        n for n in res.stdout.splitlines() if n.startswith("ns-") or n == "nsxray"
    ]
    if not namespaces:
        print("No active setups found.\n")
        print("To create a new setup, select option 1 from the menu.\n")
        return

    found_any = False
    for ns in namespaces:
        # verify still exists - ip netns list returns "ns-xxx (id: N)" format
        # So we check if any line starts with the namespace name
        ns_check = run_cmd("ip netns list 2>/dev/null", capture_output=True)
        if ns_check.returncode != 0:
            continue
        # Check if namespace exists (handle "ns-xxx (id: N)" format)
        ns_exists = any(line.strip().startswith(ns) for line in ns_check.stdout.splitlines())
        if not ns_exists:
            debug_log(f"list_setups: namespace {ns} not found in netns list")
            continue

        if ns == "nsxray":
            ns_ip = "10.200.200.2"
            port = "9349"
        else:
            # Extract port from namespace name (ns-{port})
            try:
                port = ns.split("-")[1]
            except (ValueError, IndexError):
                port = "Unknown"
            
            res_ip = run_cmd(
                "ip -4 addr show 2>/dev/null "
                "| grep -E 'inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' "
                "| awk '{print $2}' | cut -d'/' -f1 | grep '^10\\.100' | head -1",
                ns=ns,
            )
            ns_ip = res_ip.stdout.strip()
            
            # If port extraction failed, try from iptables
            if port == "Unknown" and ns_ip:
                res_port = run_cmd(
                    f"iptables -t nat -S PREROUTING 2>/dev/null | grep 'to-destination {ns_ip}' "
                    "| head -1 | awk -F':' '{{print $NF}}' | awk '{{print $1}}'",
                    capture_output=True,
                )
                port = res_port.stdout.strip() or "Unknown"

        if not ns_ip:
            # Debug: log why namespace was skipped
            debug_log(f"list_setups: skipping {ns} - no IP found")
            continue

        found_any = True

        # Check WireGuard tunnel status
        wg_output = run_cmd("wg show 2>/dev/null", ns=ns)
        t_status = f"{RED}Down{NC}"
        wg_iface = None
        
        if wg_output.stdout.strip():
            # Parse wg show output to find interface name and handshake status
            lines = wg_output.stdout.splitlines()
            has_handshake = False
            
            for i, line in enumerate(lines):
                line_stripped = line.strip()
                # Interface name is usually the first non-empty line or after "interface:"
                if "interface:" in line_stripped.lower():
                    # Next line or same line might have interface name
                    if ":" in line_stripped:
                        wg_iface = line_stripped.split(":")[-1].strip()
                elif line_stripped and not line_stripped.startswith("interface:") and not wg_iface:
                    # First meaningful line is usually interface name
                    if ":" in line_stripped:
                        wg_iface = line_stripped.split(":")[0].strip()
                
                # Check for handshake
                if "latest handshake" in line_stripped.lower() or "handshake" in line_stripped.lower():
                    # Extract handshake time if present
                    has_handshake = True
            
            # If no interface found, try to get from ip link
            if not wg_iface:
                wg_list = run_cmd("ip link show type wireguard 2>/dev/null | grep -o '^[0-9]*: [^:]*' | cut -d' ' -f2", ns=ns)
                if wg_list.stdout.strip():
                    wg_iface = wg_list.stdout.strip().split()[0] if wg_list.stdout.strip() else None
            
            # Determine status based on handshake and interface state
            if has_handshake:
                # Has handshake = active connection
                if wg_iface:
                    link_state_res = run_cmd(
                        f"ip link show {shlex.quote(wg_iface)} 2>/dev/null | grep -o 'state [A-Z]*'",
                        ns=ns,
                    )
                    link_state = link_state_res.stdout.strip()
                    if "UP" in link_state or "UNKNOWN" in link_state:
                        t_status = f"{GREEN}Active{NC}"
                    else:
                        t_status = f"{YELLOW}Connecting{NC}"
                else:
                    t_status = f"{GREEN}Active{NC}"
            elif wg_iface:
                # No handshake but interface exists - check if it's up
                link_state_res = run_cmd(
                    f"ip link show {shlex.quote(wg_iface)} 2>/dev/null | grep -o 'state [A-Z]*'",
                    ns=ns,
                )
                link_state = link_state_res.stdout.strip()
                if "UP" in link_state:
                    t_status = f"{YELLOW}Connecting{NC}"
                else:
                    t_status = f"{RED}Down{NC}"
            else:
                # Interface exists but no clear status
                t_status = f"{YELLOW}Connecting{NC}"

        # Check Xray status
        if port != "Unknown":
            try:
                port_int = int(port)
                xray_check = run_cmd(
                    f"ss -ltnp 2>/dev/null | grep -q ':{port_int} '", 
                    ns=ns, 
                    capture_output=False
                )
                if xray_check.returncode == 0:
                    x_status = f"{GREEN}Running{NC}"
                else:
                    x_status = f"{RED}Stopped{NC}"
            except ValueError:
                x_status = f"{YELLOW}?{NC}"
        else:
            x_status = f"{YELLOW}?{NC}"

        # Get VPN IP (with timeout to avoid hanging)
        vpn_ip_res = run_cmd(
            "timeout 2 curl -s --max-time 1 http://icanhazip.com 2>/dev/null || echo 'N/A'",
            ns=ns,
        )
        vpn_ip = vpn_ip_res.stdout.strip() or "N/A"
        if not vpn_ip or vpn_ip == "":
            vpn_ip = "N/A"
        geo = geo_lookup(vpn_ip)

        # Format output - remove color codes from status for proper alignment
        t_status_clean = t_status.replace(GREEN, "").replace(RED, "").replace(YELLOW, "").replace(NC, "")
        x_status_clean = x_status.replace(GREEN, "").replace(RED, "").replace(YELLOW, "").replace(NC, "")
        
        print(
            f"{ns:<12} {port:<8} {t_status:<10} {x_status:<10} {vpn_ip:<15} {geo:<25}"
        )

    if not found_any:
        print("No active setups found.\n")
        print("To create a new setup, select option 1 from the menu.")
    print()


def read_nonempty_path(prompt: str) -> str:
    while True:
        path = input(prompt).strip()
        if path.startswith("~"):
            path = os.path.expanduser(path)
        if os.path.isfile(path):
            return path
        print(f"{RED}File not found.{NC}")


def read_port(prompt: str) -> int:
    while True:
        p_str = input(prompt).strip()
        if not p_str.isdigit():
            print(f"{RED}Invalid port.{NC}")
            continue
        port = int(p_str)
        if not (1 <= port <= 65535):
            print(f"{RED}Invalid port.{NC}")
            continue
        # check in use
        res = run_cmd(f"ss -ltn | grep -q ':{port} '", capture_output=False)
        if res.returncode == 0:
            ans = input(
                f"{YELLOW}Port {port} is in use. Continue? (y/n){NC}\n> "
            ).strip()
            if ans.lower() != "y":
                continue
        return port


def resolve_endpoint_ip(wg_config: str) -> Tuple[str, str]:
    """
    Resolve WireGuard endpoint hostname to IP address.
    
    Args:
        wg_config: Path to WireGuard configuration file
        
    Returns:
        Tuple of (hostname, ip_address). IP may be empty if resolution fails.
    """
    with open(wg_config, "r", encoding="utf-8") as f:
        lines = f.readlines()
    endpoint_line = ""
    for line in lines:
        if line.strip().lower().startswith("endpoint"):
            endpoint_line = line
            break
    endpoint = endpoint_line.split("=", 1)[1].strip() if "=" in endpoint_line else ""
    host = endpoint.split(":", 1)[0] if endpoint else ""
    endpoint_ip = ""
    if host:
        for cmd in (
            f"getent ahosts {shlex.quote(host)} 2>/dev/null | awk '{{print $1}}' | head -1",
            f"host {shlex.quote(host)} 2>/dev/null | grep 'has address' | head -1 | awk '{{print $4}}'",
            f"dig +short {shlex.quote(host)} 2>/dev/null | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | head -1",
        ):
            res = run_cmd(cmd)
            ip = res.stdout.strip()
            if ip:
                endpoint_ip = ip
                break
    return host, endpoint_ip


def ensure_xray_binary() -> bool:
    """
    Ensure Xray binary exists at /usr/local/bin/xray-ns.
    
    Searches for existing xray binary or downloads from GitHub if not found.
    Returns True if binary is available, False otherwise.
    """
    if os.path.isfile("/usr/local/bin/xray-ns") and os.access(
        "/usr/local/bin/xray-ns", os.X_OK
    ):
        return True

    # search for existing xray
    res = run_cmd(
        "find /usr/local/x-ui/bin /usr/bin /usr/local/bin "
        "-name 'xray-linux-amd64' -o -name 'xray' 2>/dev/null | head -1"
    )
    xray_bin = res.stdout.strip()
    if xray_bin and os.path.isfile(xray_bin) and os.access(xray_bin, os.X_OK):
        try:
            subprocess.run(
                ["cp", xray_bin, "/usr/local/bin/xray-ns"], check=False
            )
            os.chmod("/usr/local/bin/xray-ns", 0o755)
            return True
        except Exception:
            pass

    print(f"{YELLOW}Xray binary not found. Downloading...{NC}")
    os.chdir("/tmp")
    download_ok = False
    if command_exists("wget"):
        r = run_cmd(
            "wget -q https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -O xray.zip",
            capture_output=False,
        )
        download_ok = r.returncode == 0
    elif command_exists("curl"):
        r = run_cmd(
            "curl -L -s https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o xray.zip",
            capture_output=False,
        )
        download_ok = r.returncode == 0
    else:
        print(f"{RED}Neither wget nor curl found. Cannot download Xray.{NC}")
        return False

    if not download_ok or not os.path.isfile("xray.zip"):
        print(f"{RED}Failed to download Xray{NC}")
        return False

    if not command_exists("unzip"):
        print(f"{YELLOW}unzip not found. Trying to install...{NC}")
        if command_exists("apt-get"):
            run_cmd("apt-get update >/dev/null 2>&1 && apt-get install -y unzip >/dev/null 2>&1",
                    capture_output=False)
        elif command_exists("yum"):
            run_cmd("yum install -y unzip >/dev/null 2>&1", capture_output=False)
        elif command_exists("dnf"):
            run_cmd("dnf install -y unzip >/dev/null 2>&1", capture_output=False)

    if not command_exists("unzip"):
        print(f"{RED}unzip is required but not available. Please install unzip manually.{NC}")
        return False

    unzip_res = run_cmd("unzip -q -o xray.zip xray 2>/dev/null", capture_output=False)
    if unzip_res.returncode != 0 or not os.path.isfile("xray"):
        print(f"{RED}Failed to extract Xray{NC}")
        return False

    os.chmod("xray", 0o755)
    os.makedirs("/usr/local/bin", exist_ok=True)
    os.replace("xray", "/usr/local/bin/xray-ns")
    os.remove("xray.zip")
    print(f"{GREEN}Xray downloaded and installed to /usr/local/bin/xray-ns{NC}")
    return True


def create_xray_config(
    path: str,
    port: int,
    uuids: List[str],
    use_http_header: bool,
    http_host: str,
    http_path: str,
) -> None:
    """
    Create Xray configuration file for VLESS inbound.
    
    If uuids list is empty, tries to load from file first.
    """
    # If no UUIDs provided, try to load from file
    if not uuids:
        file_uuids = load_uuids_from_file(port)
        if file_uuids:
            uuids = file_uuids
            debug_log(f"create_xray_config: loaded {len(uuids)} UUID(s) from file for port {port}")
        else:
            debug_log(f"create_xray_config: no UUIDs provided and file not found for port {port}")
    
    # Build clients JSON array from list of UUIDs
    clients_entries = ",\n                    ".join(
        f'{{\n                        "id": "{u}",\n                        "flow": ""\n                    }}'
        for u in uuids
    )

    if use_http_header:
        config = f"""
{{
    "log": {{
        "loglevel": "warning"
    }},
    "inbounds": [
        {{
            "listen": "0.0.0.0",
            "port": {port},
            "protocol": "vless",
            "settings": {{
                "clients": [
                    {clients_entries}
                ],
                "decryption": "none"
            }},
            "streamSettings": {{
                "network": "tcp",
                "security": "none",
                "tcpSettings": {{
                    "header": {{
                        "type": "http",
                        "request": {{
                            "version": "1.1",
                            "method": "GET",
                            "path": ["{http_path}"],
                            "headers": {{
                                "Host": ["{http_host}"]
                            }}
                        }}
                    }}
                }}
            }}
        }}
    ],
    "outbounds": [
        {{
            "protocol": "freedom",
            "tag": "direct"
        }}
    ]
}}
"""
    else:
        config = f"""
{{
    "log": {{
        "loglevel": "warning"
    }},
    "inbounds": [
        {{
            "listen": "0.0.0.0",
            "port": {port},
            "protocol": "vless",
            "settings": {{
                "clients": [
                    {clients_entries}
                ],
                "decryption": "none"
            }},
            "streamSettings": {{
                "network": "tcp",
                "security": "none"
            }}
        }}
    ],
    "outbounds": [
        {{
            "protocol": "freedom",
            "tag": "direct"
        }}
    ]
}}
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(config.strip() + "\n")


def create_setup() -> None:
    print(f"{GREEN}=== Create New Setup ==={NC}")
    wg_config = read_nonempty_path(f"{YELLOW}Enter WireGuard config file path:{NC}\n> ")
    port = read_port(f"{YELLOW}Enter port number:{NC}\n> ")

    # Calculate subnet octet: use port % 250 + 2 to avoid conflicts
    # (port 250 and 500 would both map to 1, so we use +2)
    subnet_octet = (port % 250) + 2
    ns_name = f"ns-{port}"
    veth_host = f"veth-{port}"
    veth_ns = f"vpeer-{port}"
    host_ip = f"10.100.{subnet_octet}.1"
    ns_ip = f"10.100.{subnet_octet}.2"
    subnet = f"10.100.{subnet_octet}.0/24"

    print(f"{BLUE}Setting up {ns_name} on port {port}...{NC}")

    # cleanup existing
    print(f"{YELLOW}Cleaning up any existing setup...{NC}")
    run_cmd(f"ip netns delete {shlex.quote(ns_name)} 2>/dev/null || true", capture_output=False)
    run_cmd(f"ip link delete {shlex.quote(veth_host)} 2>/dev/null || true", capture_output=False)

    # iptables cleanup
    run_cmd(
        f"iptables -t nat -D PREROUTING -p tcp --dport {port} -j DNAT --to-destination {ns_ip}:{port} 2>/dev/null || true",
        capture_output=False,
    )
    run_cmd(
        f"iptables -t nat -D PREROUTING -p udp --dport {port} -j DNAT --to-destination {ns_ip}:{port} 2>/dev/null || true",
        capture_output=False,
    )
    run_cmd(
        f"iptables -t nat -D POSTROUTING -s {subnet} ! -o {veth_host} -j MASQUERADE 2>/dev/null || true",
        capture_output=False,
    )
    for proto in ("tcp", "udp"):
        run_cmd(
            f"iptables -D FORWARD -p {proto} -d {ns_ip}/32 --dport {port} -j ACCEPT 2>/dev/null || true",
            capture_output=False,
        )
        run_cmd(
            f"iptables -D FORWARD -p {proto} -s {ns_ip}/32 -j ACCEPT 2>/dev/null || true",
            capture_output=False,
        )

    # resolve endpoint
    endpoint_host, endpoint_ip = resolve_endpoint_ip(wg_config)
    if not endpoint_ip:
        print(f"{RED}Could not resolve endpoint: {endpoint_host}{NC}")
        return

    print(f"{BLUE}Creating namespace and veth pair...{NC}")
    # namespace and veth
    if run_cmd(f"ip netns add {shlex.quote(ns_name)}", capture_output=False).returncode != 0:
        run_cmd(f"ip netns delete {shlex.quote(ns_name)} 2>/dev/null || true",
                capture_output=False)
        time.sleep(2)
        if run_cmd(f"ip netns add {shlex.quote(ns_name)}", capture_output=False).returncode != 0:
            print(
                f"{RED}Failed to create namespace after cleanup. Please check manually.{NC}"
            )
            return

    run_cmd(f"ip link delete {shlex.quote(veth_host)} 2>/dev/null || true", capture_output=False)
    time.sleep(1)
    if run_cmd(
        f"ip link add {shlex.quote(veth_host)} type veth peer name {shlex.quote(veth_ns)}",
        capture_output=False,
    ).returncode != 0:
        print(f"{RED}Failed to create veth pair. Cleaning up...{NC}")
        run_cmd(f"ip netns delete {shlex.quote(ns_name)} 2>/dev/null || true",
                capture_output=False)
        return

    run_cmd(f"ip link set {shlex.quote(veth_host)} up", capture_output=False)
    run_cmd(f"ip addr flush dev {shlex.quote(veth_host)} 2>/dev/null || true", capture_output=False)
    run_cmd(f"ip addr add {host_ip}/24 dev {shlex.quote(veth_host)}", capture_output=False)

    run_cmd(
        f"ip link set {shlex.quote(veth_ns)} netns {shlex.quote(ns_name)}",
        capture_output=False,
    )
    run_cmd("ip link set lo up", ns=ns_name, capture_output=False)
    run_cmd(f"ip link set {shlex.quote(veth_ns)} up", ns=ns_name, capture_output=False)
    run_cmd(
        f"ip addr flush dev {shlex.quote(veth_ns)} 2>/dev/null || true",
        ns=ns_name,
        capture_output=False,
    )
    run_cmd(
        f"ip addr add {ns_ip}/24 dev {shlex.quote(veth_ns)}",
        ns=ns_name,
        capture_output=False,
    )

    print(f"{BLUE}Setting up WireGuard...{NC}")
    # WG name
    wg_name = ""
    if command_exists("md5sum"):
        res = run_cmd(f"echo {port} | md5sum | cut -c1-8")
        wg_name = f"wg-{res.stdout.strip()}"
    elif command_exists("md5"):
        res = run_cmd(f"echo {port} | md5 | cut -c1-8")
        wg_name = f"wg-{res.stdout.strip()}"
    else:
        wg_name = f"wg-{(port * 31):08x}"[:11]

    wg_address = "10.0.0.2/32"
    with open(wg_config, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip().lower().startswith("address"):
                wg_address = line.split("=", 1)[1].strip()
                break

    # cleanup existing WG
    run_cmd(
        f"ip netns exec {shlex.quote(ns_name)} ip link delete {shlex.quote(wg_name)} 2>/dev/null || true",
        capture_output=False,
    )
    run_cmd(f"ip link delete {shlex.quote(wg_name)} 2>/dev/null || true", capture_output=False)
    time.sleep(1)

    if run_cmd(f"ip link add {shlex.quote(wg_name)} type wireguard", capture_output=False).returncode != 0:
        print(f"{RED}Failed to create WireGuard interface. Cleaning up...{NC}")
        run_cmd(f"ip link delete {shlex.quote(veth_host)} 2>/dev/null || true",
                capture_output=False)
        run_cmd(f"ip netns delete {shlex.quote(ns_name)} 2>/dev/null || true",
                capture_output=False)
        return

    # configure wg
    filter_cmd = (
        r"grep -vE '^(Address|DNS|Table|MTU|PreUp|PostUp|PreDown|PostDown)' "
        f"{shlex.quote(wg_config)} | wg setconf {shlex.quote(wg_name)} /dev/stdin"
    )
    if run_cmd(filter_cmd, capture_output=False).returncode != 0:
        print(f"{RED}Failed to configure WireGuard interface. Please check your config file.{NC}")
        run_cmd(f"ip link delete {shlex.quote(wg_name)} 2>/dev/null || true",
                capture_output=False)
        run_cmd(f"ip link delete {shlex.quote(veth_host)} 2>/dev/null || true",
                capture_output=False)
        run_cmd(f"ip netns delete {shlex.quote(ns_name)} 2>/dev/null || true",
                capture_output=False)
        return

    run_cmd(
        f"ip link set {shlex.quote(wg_name)} netns {shlex.quote(ns_name)}",
        capture_output=False,
    )
    run_cmd(
        f"ip addr add {wg_address} dev {shlex.quote(wg_name)}",
        ns=ns_name,
        capture_output=False,
    )
    run_cmd(f"ip link set {shlex.quote(wg_name)} up", ns=ns_name, capture_output=False)

    # routing
    run_cmd("ip route flush table main 2>/dev/null || true", ns=ns_name, capture_output=False)
    run_cmd("ip route flush table 100 2>/dev/null || true", ns=ns_name, capture_output=False)
    run_cmd(
        f"ip route add 10.100.{subnet_octet}.0/24 dev {shlex.quote(veth_ns)} proto kernel scope link src {ns_ip}",
        ns=ns_name,
        capture_output=False,
    )
    run_cmd(
        f"ip route add {endpoint_ip}/32 via {host_ip}",
        ns=ns_name,
        capture_output=False,
    )
    run_cmd(f"ip route add default dev {shlex.quote(wg_name)}", ns=ns_name, capture_output=False)
    run_cmd(
        f"ip route add default via {host_ip} dev {shlex.quote(veth_ns)} table 100",
        ns=ns_name,
        capture_output=False,
    )
    run_cmd(
        f"ip rule add fwmark 1 lookup 100",
        ns=ns_name,
        capture_output=False,
    )
    run_cmd(
        f"iptables -t mangle -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -s {ns_ip} -j MARK --set-mark 1",
        ns=ns_name,
        capture_output=False,
    )

    # NAT & firewall
    run_cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null", capture_output=False)
    run_cmd(
        f"iptables -t nat -A POSTROUTING -o {shlex.quote(wg_name)} -j MASQUERADE",
        ns=ns_name,
        capture_output=False,
    )
    run_cmd(
        f"iptables -t nat -D POSTROUTING -s {subnet} ! -o {veth_host} -j MASQUERADE 2>/dev/null || true",
        capture_output=False,
    )
    run_cmd(
        f"iptables -t nat -A POSTROUTING -s {subnet} ! -o {veth_host} -j MASQUERADE",
        capture_output=False,
    )

    # DNAT + FORWARD
    for proto in ("tcp", "udp"):
        run_cmd(
            f"iptables -t nat -D PREROUTING -p {proto} --dport {port} -j DNAT --to-destination {ns_ip}:{port} 2>/dev/null || true",
            capture_output=False,
        )
        run_cmd(
            f"iptables -t nat -A PREROUTING -p {proto} --dport {port} -j DNAT --to-destination {ns_ip}:{port}",
            capture_output=False,
        )
        run_cmd(
            f"iptables -D FORWARD -p {proto} -d {ns_ip}/32 --dport {port} -j ACCEPT 2>/dev/null || true",
            capture_output=False,
        )
        run_cmd(
            f"iptables -I FORWARD 1 -p {proto} -d {ns_ip}/32 --dport {port} -j ACCEPT",
            capture_output=False,
        )
        run_cmd(
            f"iptables -D FORWARD -p {proto} -s {ns_ip}/32 -j ACCEPT 2>/dev/null || true",
            capture_output=False,
        )
        run_cmd(
            f"iptables -I FORWARD 1 -p {proto} -s {ns_ip}/32 -j ACCEPT",
            capture_output=False,
        )

    # DNS for namespace
    etc_ns = f"/etc/netns/{ns_name}"
    os.makedirs(etc_ns, exist_ok=True)
    with open(os.path.join(etc_ns, "resolv.conf"), "w", encoding="utf-8") as f:
        f.write("nameserver 1.1.1.1\n")

    print(f"{GREEN}Setup complete!{NC}")
    
    # Save setup state for auto-restore after reboot
    save_setup_state(port, wg_config)
    print(f"{GREEN}✓ Tunnel state saved for auto-restore after reboot{NC}")

    # Auto-start Xray
    print(f"{BLUE}Automatically starting Xray inbound...{NC}")
    if not ensure_xray_binary():
        print(f"{RED}Failed to ensure Xray binary. Skipping Xray auto-start.{NC}")
        input("Press Enter to continue...")
        return

    # kill existing Xray on port
    res_pids = run_cmd(
        f"ss -ltnp 2>/dev/null | grep ':{port} ' | sed -n 's/.*pid=\\([0-9]*\\).*/\\1/p'",
        ns=ns_name,
    )
    pids = res_pids.stdout.split()
    if pids:
        run_cmd(f"kill {' '.join(pids)} 2>/dev/null || true", ns=ns_name, capture_output=False)
        time.sleep(1)

    # --- configure Xray using current DB and start it for this one namespace ---
    refresh_uuids_for_all_namespaces(interactive=True)
    
    # Ensure UUID watcher is running in background after setup
    config = load_config()
    if config.get("panel_type") and config.get("panel_db_path"):
        print(f"\n{BLUE}Ensuring UUID auto-refresh watcher is running...{NC}")
        if start_background_uuid_watcher():
            interval = config.get("uuid_refresh_interval", 5)
            print(f"{GREEN}✓ UUID Auto-Refresh Watcher is active (every {interval} seconds){NC}")
        else:
            print(f"{YELLOW}⚠ UUID watcher not started, but setup is complete{NC}")

    input("Press Enter to continue...")


def manage_xray(target_port: Optional[int] = None, action: Optional[str] = None) -> None:
    if target_port is None:
        print(f"{YELLOW}Enter port number (or type 'all' to apply to all namespaces):{NC}")
        raw = input("> ").strip()
        if raw.lower() == "all":
            manage_xray_all()
            return
        try:
            target_port = int(raw)
        except ValueError:
            print(f"{RED}Invalid input.{NC}")
            return

    ns_name = f"ns-{target_port}"
    # fallback to nsxray for 9349 like bash version
    ns_list = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'").stdout.split()
    if ns_name not in ns_list:
        if target_port == 9349 and "nsxray" in ns_list:
            ns_name = "nsxray"
        else:
            print(f"{RED}Namespace for port {target_port} not found.{NC}")
            return

    if action is None:
        print(f"{BLUE}Xray Management for Port {target_port} ({ns_name}){NC}")
        print("1. Start/Restart Xray")
        print("2. Stop Xray")
        print("3. Check Logs")
        sel = input("> ").strip()
        if sel == "1":
            action = "start"
        elif sel == "2":
            action = "stop"
        elif sel == "3":
            action = "logs"
        else:
            return

    if action == "start":
        print(f"{BLUE}Starting Xray...{NC}")
        if not ensure_xray_binary():
            print(f"{RED}Failed to ensure Xray binary. Exiting.{NC}")
            return

        # kill existing on port
        res_pids = run_cmd(
            f"ss -ltnp 2>/dev/null | grep ':{target_port} ' | sed -n 's/.*pid=\\([0-9]*\\).*/\\1/p'",
            ns=ns_name,
        )
        pids = res_pids.stdout.split()
        if pids:
            print(f"{YELLOW}Stopping existing Xray processes...{NC}")
            run_cmd(f"kill {' '.join(pids)} 2>/dev/null || true", ns=ns_name,
                    capture_output=False)
            time.sleep(1)

        # Re-sync all namespaces from the DB (single source of truth)
        refresh_uuids_for_all_namespaces(interactive=True)

    elif action == "stop":
        print(f"{BLUE}Stopping Xray...{NC}")
        res_pids = run_cmd(
            f"ss -ltnp 2>/dev/null | grep ':{target_port} ' | sed -n 's/.*pid=\\([0-9]*\\).*/\\1/p'",
            ns=ns_name,
        )
        pids = res_pids.stdout.split()
        if pids:
            run_cmd(f"kill {' '.join(pids)}", ns=ns_name, capture_output=False)
            print(f"{GREEN}Stopped.{NC}")
        else:
            print(f"{YELLOW}Not running.{NC}")

    elif action == "logs":
        print(
            f"{BLUE}Last 20 lines of log (/tmp/xray-{target_port}.log):{NC}"
        )
        try:
            with open(f"/tmp/xray-{target_port}.log", "r", encoding="utf-8") as f:
                lines = f.readlines()[-20:]
            for line in lines:
                print(line.rstrip())
        except FileNotFoundError:
            print(f"{YELLOW}Log file not found.{NC}")

    if target_port is None:
        input("Press Enter to continue...")
    else:
        input("Press Enter to continue...")


def manage_xray_all() -> None:
    """Start/Restart Xray for all managed namespaces in one go, using current DB."""
    print(f"{BLUE}Starting/Restarting Xray for all namespaces...{NC}")
    refresh_uuids_for_all_namespaces(interactive=True)


def restart_wireguard() -> None:
    print(f"{BLUE}=== Restart WireGuard ==={NC}")
    print(f"{YELLOW}Enter Port number to restart WireGuard:{NC}")
    try:
        port = int(input("> ").strip())
    except ValueError:
        return

    ns_name = f"ns-{port}"
    ns_list = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'").stdout.split()
    if ns_name not in ns_list:
        if port == 9349 and "nsxray" in ns_list:
            ns_name = "nsxray"
        else:
            print(f"{RED}Namespace for port {port} not found.{NC}")
            input("Press Enter to continue...")
            return

    print(f"{BLUE}Restarting WireGuard in {ns_name}...{NC}")
    wg_show = run_cmd("wg show 2>/dev/null", ns=ns_name)
    first_line = wg_show.stdout.splitlines()[0] if wg_show.stdout.splitlines() else ""
    wg_iface = first_line.split()[1].rstrip(":") if len(first_line.split()) > 1 else ""
    if not wg_iface:
        print(f"{RED}WireGuard interface not found in namespace.{NC}")
        input("Press Enter to continue...")
        return

    # Calculate subnet octet: use port % 250 + 2 to avoid conflicts
    # (port 250 and 500 would both map to 1, so we use +2)
    subnet_octet = (port % 250) + 2
    ns_ip = f"10.100.{subnet_octet}.2"
    host_ip = f"10.100.{subnet_octet}.1"

    wg_conf_tmp = f"/tmp/wg-restart-{port}.conf"
    run_cmd(f"wg showconf {shlex.quote(wg_iface)} > {shlex.quote(wg_conf_tmp)} 2>/dev/null",
            ns=ns_name, capture_output=False)

    endpoint_host = ""
    endpoint_ip = ""
    if os.path.isfile(wg_conf_tmp):
        with open(wg_conf_tmp, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().lower().startswith("endpoint"):
                    endpoint_field = line.split("=", 1)[1].strip()
                    endpoint_host = endpoint_field.split(":", 1)[0]
                    break
    if endpoint_host:
        for cmd in (
            f"getent ahosts {shlex.quote(endpoint_host)} 2>/dev/null | awk '{{print $1}}' | head -1",
            f"host {shlex.quote(endpoint_host)} 2>/dev/null | grep 'has address' | head -1 | awk '{{print $4}}'",
            f"dig +short {shlex.quote(endpoint_host)} 2>/dev/null | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | head -1",
        ):
            res = run_cmd(cmd)
            ip = res.stdout.strip()
            if ip:
                endpoint_ip = ip
                break

    print(f"{YELLOW}Bringing WireGuard interface DOWN...{NC}")
    run_cmd(f"ip link set {shlex.quote(wg_iface)} down 2>/dev/null", ns=ns_name,
            capture_output=False)
    time.sleep(2)

    print(f"{YELLOW}Bringing WireGuard interface UP...{NC}")
    run_cmd(f"ip link set {shlex.quote(wg_iface)} up 2>/dev/null", ns=ns_name,
            capture_output=False)
    time.sleep(2)

    print(f"{YELLOW}Refreshing routes...{NC}")
    vpeer = f"vpeer-{port}"
    run_cmd(
        f"ip route replace 10.100.{subnet_octet}.0/24 dev {shlex.quote(vpeer)} "
        f"proto kernel scope link src {ns_ip}",
        ns=ns_name,
        capture_output=False,
    )
    if endpoint_ip:
        run_cmd(
            f"ip route replace {endpoint_ip}/32 via {host_ip} dev {shlex.quote(vpeer)}",
            ns=ns_name,
            capture_output=False,
        )
    run_cmd(
        f"ip route replace default dev {shlex.quote(wg_iface)}",
        ns=ns_name,
        capture_output=False,
    )

    print(f"{YELLOW}Waiting for WireGuard handshake...{NC}")
    handshake_detected = False
    for _ in range(10):
        time.sleep(2)
        wg_status = run_cmd(f"wg show {shlex.quote(wg_iface)} 2>/dev/null", ns=ns_name)
        if "latest handshake" in wg_status.stdout:
            handshake_detected = True
            break
        print(".", end="", flush=True)
    print()

    if handshake_detected:
        print(f"{GREEN}WireGuard restarted successfully!{NC}")
        wg_status = run_cmd(f"wg show {shlex.quote(wg_iface)} 2>/dev/null", ns=ns_name)
        for line in wg_status.stdout.splitlines():
            if "latest handshake" in line:
                print(f"{BLUE}{line.strip()}{NC}")
                break
        print(f"{YELLOW}Current routing table in namespace:{NC}")
        routes = run_cmd("ip route show", ns=ns_name)
        print(routes.stdout)
    else:
        print(
            f"{YELLOW}WireGuard restarted but no handshake detected yet. It may take a few moments.{NC}"
        )

    if os.path.isfile(wg_conf_tmp):
        os.remove(wg_conf_tmp)
    input("Press Enter to continue...")


def delete_setup(port: Optional[int] = None, skip_confirm: bool = False) -> None:
    """Delete a tunnel setup.
    
    Args:
        port: Port number. If None, will prompt user.
        skip_confirm: If True, skip confirmation prompt.
    """
    if port is None:
        print(f"{RED}=== Delete Setup ==={NC}")
        print(f"{YELLOW}Enter Port number to delete:{NC}")
        try:
            port = int(input("> ").strip())
        except ValueError:
            return
    elif not skip_confirm:
        print(f"{RED}=== Delete Setup ==={NC}")
        print(f"{YELLOW}Deleting tunnel on port {port}...{NC}")

    ns_name = f"ns-{port}"
    ns_list = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'").stdout.split()
    namespace_exists = False
    if ns_name in ns_list:
        namespace_exists = True
    elif port == 9349 and "nsxray" in ns_list:
        ns_name = "nsxray"
        namespace_exists = True
    else:
        print(
            f"{YELLOW}Namespace not found, but cleaning up orphaned iptables rules...{NC}"
        )

    print(f"{RED}Deleting setup for Port {port} ({ns_name})...{NC}")

    if ns_name == "nsxray":
        veth_host = "veth-host"
        ns_ip = "10.200.200.2"
        subnet = "10.200.200.0/24"
    else:
        # Calculate subnet octet: use port % 250 + 2 to avoid conflicts
        # (port 250 and 500 would both map to 1, so we use +2)
        subnet_octet = (port % 250) + 2
        veth_host = f"veth-{port}"
        ns_ip = f"10.100.{subnet_octet}.2"
        subnet = f"10.100.{subnet_octet}.0/24"

    if namespace_exists:
        run_cmd(f"ip netns delete {shlex.quote(ns_name)} 2>/dev/null || true",
                capture_output=False)
    run_cmd(f"ip link delete {shlex.quote(veth_host)} 2>/dev/null || true",
            capture_output=False)

    # iptables cleanup
    for proto in ("tcp", "udp"):
        run_cmd(
            f"iptables -t nat -D PREROUTING -p {proto} --dport {port} -j DNAT --to-destination {ns_ip}:{port} 2>/dev/null || true",
            capture_output=False,
        )
    run_cmd(
        f"iptables -t nat -D POSTROUTING -s {subnet} ! -o {veth_host} -j MASQUERADE 2>/dev/null || true",
        capture_output=False,
    )
    for proto in ("tcp", "udp"):
        run_cmd(
            f"iptables -D FORWARD -p {proto} -d {ns_ip}/32 --dport {port} -j ACCEPT 2>/dev/null || true",
            capture_output=False,
        )
        run_cmd(
            f"iptables -D FORWARD -p {proto} -s {ns_ip}/32 -j ACCEPT 2>/dev/null || true",
            capture_output=False,
        )

    # LOG rules cleanup
    for proto in ("tcp", "udp"):
        run_cmd(
            f"iptables -t nat -D PREROUTING -p {proto} --dport {port} -j LOG --log-prefix '[DNAT-{port}] ' --log-level 4 2>/dev/null || true",
            capture_output=False,
        )
    for proto in ("tcp", "udp"):
        run_cmd(
            f"iptables -D FORWARD -p {proto} -d {ns_ip}/32 --dport {port} -j LOG --log-prefix '[FWD-{port}] ' --log-level 4 2>/dev/null || true",
            capture_output=False,
        )
        run_cmd(
            f"iptables -D FORWARD -p {proto} -s {ns_ip}/32 -j LOG --log-prefix '[RET-{port}] ' --log-level 4 2>/dev/null || true",
            capture_output=False,
        )

    # Remove saved state
    delete_setup_state(port)
    
    print(f"{GREEN}Deleted successfully.{NC}")
    if not skip_confirm:
        input("Press Enter to continue...")


def debug_setup() -> None:
    print(f"{BLUE}=== Debug Setup ==={NC}")
    print(f"{YELLOW}Enter Port number to debug:{NC}")
    try:
        port = int(input("> ").strip())
    except ValueError:
        return

    ns_name = f"ns-{port}"
    ns_list = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'").stdout.split()
    namespace_exists = False
    if ns_name in ns_list:
        namespace_exists = True
    elif port == 9349 and "nsxray" in ns_list:
        ns_name = "nsxray"
        namespace_exists = True
    else:
        print(
            f"{YELLOW}Namespace not found, but cleaning up orphaned iptables rules...{NC}"
        )

    log_file = f"/tmp/debug-{port}.log"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"=== Debug Log for Port {port} ({ns_name}) ===\n")
        f.write(f"Timestamp: {time.ctime()}\n\n")

    print(f"{BLUE}Collecting debug information...{NC}")

    def append_cmd(title: str, cmd: str, ns: Optional[str] = None) -> None:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"=== {title} ===\n")
        out = run_cmd(cmd, ns=ns)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(out.stdout)
            f.write("\n")

    # 1. Namespace info
    append_cmd("Namespace Info", f"ip netns list | grep '{ns_name}' 2>&1")

    # 2. IP addresses
    if namespace_exists:
        append_cmd("IP Addresses", "ip addr show", ns=ns_name)
        # 3. Routing
        append_cmd("Routing Table", "ip route show", ns=ns_name)
        append_cmd("IP Rules", "ip rule show", ns=ns_name)
        # 4. WireGuard status
        append_cmd("WireGuard Status", "wg show 2>&1", ns=ns_name)
        # 5. Listening ports
        append_cmd("Listening Ports", "ss -tulnp 2>&1", ns=ns_name)

        # 6. Namespace iptables
        append_cmd("Namespace iptables", "iptables -t nat -L -n -v 2>&1", ns=ns_name)

        # 7. Connectivity test
        append_cmd("Route to 8.8.8.8", "ip route get 8.8.8.8 2>&1", ns=ns_name)
        append_cmd(
            "Curl Test",
            "curl -s --max-time 5 http://icanhazip.com 2>&1",
            ns=ns_name,
        )

    # 6/8. Host iptables
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("=== Host iptables NAT PREROUTING ===\n")
    out = run_cmd(
        f"iptables -t nat -L PREROUTING -n -v | grep -E '({port}|10.100)' 2>&1"
    )
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(out.stdout + "\n")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write("=== Host iptables FORWARD ===\n")
    out = run_cmd(
        f"iptables -L FORWARD -n -v | grep -E '({port}|10.100)' 2>&1"
    )
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(out.stdout + "\n")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write("=== Host iptables NAT POSTROUTING ===\n")
    out = run_cmd(
        f"iptables -t nat -L POSTROUTING -n -v | grep -E '({port}|10.100)' 2>&1"
    )
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(out.stdout + "\n")

    # 8. Connection tracking
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("=== Connection Tracking ===\n")
    out = run_cmd(
        f"conntrack -L -n 2>&1 | grep -E '({port}|10.100)' | head -10"
    )
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(out.stdout + "\n")

    # 9. Veth interface
    # Calculate subnet octet: use port % 250 + 2 to avoid conflicts
    # (port 250 and 500 would both map to 1, so we use +2)
    subnet_octet = (port % 250) + 2
    veth_host = f"veth-{port}"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("=== Veth Interface ===\n")
    out = run_cmd(f"ip addr show {shlex.quote(veth_host)} 2>&1")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(out.stdout + "\n")

    print(f"{GREEN}Debug information saved to: {log_file}{NC}\n")
    print(f"{YELLOW}Last 50 lines of log:{NC}")
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()[-50:]
        for line in lines:
            print(line.rstrip())
    except FileNotFoundError:
        pass

    print(f"{YELLOW}Do you want to enable real-time packet logging? (y/n){NC}")
    ans = input("> ").strip()
    if ans.lower() == "y":
        enable_realtime_logging(port, ns_name)

    input("Press Enter to continue...")


def enable_realtime_logging(port: int, ns_name: str) -> None:
    # Calculate subnet octet: use port % 250 + 2 to avoid conflicts
    # (port 250 and 500 would both map to 1, so we use +2)
    subnet_octet = (port % 250) + 2
    ns_ip = f"10.100.{subnet_octet}.2"

    print(
        f"{BLUE}Enabling real-time packet logging for port {port}...{NC}\n"
        f"{YELLOW}Press Ctrl+C to stop logging{NC}"
    )

    # Add LOG rules
    for proto in ("tcp", "udp"):
        run_cmd(
            f"iptables -t nat -I PREROUTING 1 -p {proto} --dport {port} "
            f"-j LOG --log-prefix '[DNAT-{port}] ' --log-level 4",
            capture_output=False,
        )
        run_cmd(
            f"iptables -I FORWARD 1 -p {proto} -d {ns_ip}/32 --dport {port} "
            f"-j LOG --log-prefix '[FWD-{port}] ' --log-level 4",
            capture_output=False,
        )
        run_cmd(
            f"iptables -I FORWARD 1 -p {proto} -s {ns_ip}/32 "
            f"-j LOG --log-prefix '[RET-{port}] ' --log-level 4",
            capture_output=False,
        )

    # monitor kernel log
    # try /var/log/kern.log, else fall back to dmesg -w
    print()
    try:
        cmd = (
            f"tail -f /var/log/kern.log 2>/dev/null | grep -E '\\[(DNAT|FWD|RET)-{port}\\]'"
        )
        proc = subprocess.Popen(
            cmd, shell=True, text=True
        )
        proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        # cleanup logging rules
        for proto in ("tcp", "udp"):
            run_cmd(
                f"iptables -t nat -D PREROUTING -p {proto} --dport {port} "
                f"-j LOG --log-prefix '[DNAT-{port}] ' --log-level 4 2>/dev/null || true",
                capture_output=False,
            )
            run_cmd(
                f"iptables -D FORWARD -p {proto} -d {ns_ip}/32 --dport {port} "
                f"-j LOG --log-prefix '[FWD-{port}] ' --log-level 4 2>/dev/null || true",
                capture_output=False,
            )
            run_cmd(
                f"iptables -D FORWARD -p {proto} -s {ns_ip}/32 "
                f"-j LOG --log-prefix '[RET-{port}] ' --log-level 4 2>/dev/null || true",
                capture_output=False,
            )


def restore_from_config_file() -> None:
    """Manually restore a tunnel by selecting config file and entering port."""
    print(f"{BLUE}=== Restore Tunnel from Config File ==={NC}\n")
    
    # Find all .conf files in /root
    config_files = []
    if os.path.isdir("/root"):
        try:
            for filename in os.listdir("/root"):
                if filename.endswith(".conf"):
                    config_path = os.path.join("/root", filename)
                    if os.path.isfile(config_path):
                        # Try to verify it's a WireGuard config
                        try:
                            with open(config_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                if '[Interface]' in content or 'PrivateKey' in content:
                                    config_files.append(config_path)
                        except (OSError, UnicodeDecodeError):
                            continue
        except OSError:
            pass
    
    if not config_files:
        print(f"{RED}No WireGuard config files found in /root{NC}")
        print(f"{YELLOW}Please create a tunnel first using option 1.{NC}\n")
        input("Press Enter to continue...")
        return
    
    print(f"{YELLOW}Found {len(config_files)} config file(s):{NC}\n")
    for i, config_path in enumerate(config_files, 1):
        print(f"  {i}. {config_path}")
    
    print()
    try:
        choice = input(f"Select config file (1-{len(config_files)}): ").strip()
        idx = int(choice) - 1
        if idx < 0 or idx >= len(config_files):
            print(f"{RED}Invalid selection{NC}")
            input("Press Enter to continue...")
            return
        wg_config_path = config_files[idx]
    except (ValueError, IndexError):
        print(f"{RED}Invalid input{NC}")
        input("Press Enter to continue...")
        return
    
    # Get port
    port = read_port("Enter port number for this tunnel: ")
    
    # Check if namespace already exists
    ns_name = f"ns-{port}"
    ns_list = run_cmd("ip netns list 2>/dev/null | awk '{print $1}'").stdout.split()
    if ns_name in ns_list:
        print(f"{YELLOW}⚠ Tunnel on port {port} already exists.{NC}")
        ans = input(f"{YELLOW}Do you want to recreate it? (y/n): {NC}").strip().lower()
        if ans != "y":
            print(f"{YELLOW}Cancelled.{NC}")
            input("Press Enter to continue...")
            return
        # Delete existing
        delete_setup(port=port, skip_confirm=True)
    
    print(f"\n{BLUE}Restoring tunnel on port {port} from {wg_config_path}...{NC}\n")
    
    if restore_setup(port, wg_config_path):
        # Save state for future restores
        save_setup_state(port, wg_config_path)
        print(f"{GREEN}✓ Tunnel restored and state saved!{NC}\n")
    else:
        print(f"{RED}✗ Failed to restore tunnel{NC}\n")
    
    input("Press Enter to continue...")


def setup_auto_restore_service() -> None:
    """Setup systemd service for auto-restore tunnels after reboot."""
    print(f"{BLUE}=== Setup Auto-Restore Service ==={NC}\n")
    
    service_file = "/etc/systemd/system/setup-wg-restore.service"
    script_path = os.path.abspath(__file__)
    
    print(f"{YELLOW}This will create a systemd service that restores all tunnels after reboot.{NC}")
    print(f"{YELLOW}Service file: {service_file}{NC}\n")
    
    ans = input(f"{YELLOW}Continue? (y/n){NC}\n> ").strip().lower()
    if ans != "y":
        return
    
    service_content = f"""[Unit]
Description=WireGuard Namespace Manager - Restore Tunnels After Reboot
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {script_path} --restore
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open(service_file, "w", encoding="utf-8") as f:
            f.write(service_content)
        print(f"{GREEN}✓ Service file created{NC}")
        
        # Reload systemd
        run_cmd("systemctl daemon-reload", capture_output=False)
        print(f"{GREEN}✓ Systemd daemon reloaded{NC}")
        
        # Enable service
        run_cmd("systemctl enable setup-wg-restore.service", capture_output=False)
        print(f"{GREEN}✓ Service enabled (will run on boot){NC}")
        
        print(f"\n{GREEN}Auto-restore service setup complete!{NC}")
        print(f"{BLUE}Service will automatically restore all tunnels after reboot.{NC}")
        print(f"{YELLOW}To test: systemctl start setup-wg-restore{NC}")
        print(f"{YELLOW}To disable: systemctl disable setup-wg-restore{NC}\n")
        
    except Exception as e:
        print(f"{RED}Failed to setup service: {e}{NC}")
        debug_log(f"setup_auto_restore_service: failed: {e!r}")
    
    input("Press Enter to continue...")


def auto_refresh_main(interval_seconds: Optional[int] = None) -> None:
    """
    Run in pure auto-refresh mode (no menu, suitable for background execution).
    Every interval_seconds seconds, reads UUIDs from panel and refreshes tunnels.
    """
    require_root()
    debug_log("auto_refresh_mode: started")
    
    # Load interval from config if not provided
    if interval_seconds is None:
        config = load_config()
        interval_seconds = config.get("uuid_refresh_interval", 5)
    
    debug_log(f"auto_refresh_mode: using interval {interval_seconds} seconds")
    
    # Try to load previously selected panel DB (if any)
    load_panel_state()
    while True:
        try:
            refresh_uuids_for_all_namespaces_noninteractive()
        except Exception as e:
            debug_log(f"auto_refresh_mode: error during refresh: {e!r}")
        time.sleep(interval_seconds)


def main() -> None:
    require_root()

    # Check if first-time setup is needed
    # Only run wizard if config doesn't exist OR if panel_type is not configured
    config = load_config()
    needs_setup = False
    
    if not config.get("setup_completed", False):
        # Check if config file exists and has panel_type configured
        if os.path.isfile(CONFIG_FILE):
            # Config file exists, check if it's properly configured
            if not config.get("panel_type"):
                # Config exists but panel_type not set - needs setup
                needs_setup = True
            # If panel_type exists, assume setup is complete (even if flag is false)
            # This handles cases where config was created but flag wasn't set
        else:
            # No config file - definitely needs setup
            needs_setup = True
    
    if needs_setup:
        setup_wizard()
        # Reload config after setup
        config = load_config()

    # Try to restore previously selected panel DB (if any)
    load_panel_state()
    
    first_run_file = "/tmp/.setup-wg-first-run"
    if not os.path.exists(first_run_file):
        check_and_install_dependencies()
        open(first_run_file, "w").close()

    # Start background UUID watcher once; it will become active as soon as
    # PANEL_DB_PATH is configured via `choose_uuids_from_panel`.
    # This watcher reads UUIDs from panel every interval_seconds seconds and restarts Xray
    # so new users can also connect.
    if config.get("panel_type") and config.get("panel_db_path"):
        interval = config.get("uuid_refresh_interval", 5)
        if start_background_uuid_watcher():
            print(f"{GREEN}✓ UUID Auto-Refresh Watcher started (every {interval} seconds){NC}")
            print(f"{BLUE}  UUIDs will be automatically updated from panel every {interval} seconds{NC}")
            print(f"{BLUE}  New users will be able to connect automatically{NC}\n")
        else:
            print(f"{YELLOW}⚠ UUID watcher could not be started automatically{NC}")
            print(f"{YELLOW}  You can configure it from the menu{NC}\n")
    else:
        print(f"{YELLOW}⚠ UUID watcher not started: panel not configured{NC}")
        print(f"{YELLOW}  Configure panel in Xray management (option 2) to enable auto-refresh{NC}\n")

    while True:
        show_header()
        list_setups()
        print("1. Create New Setup")
        print("2. Manage Xray")
        print("3. Restart WireGuard")
        print("4. Delete Setup")
        print("5. Debug Setup")
        print("6. Restore All Tunnels")
        print("7. Restore Tunnel from Config File")
        print("8. Setup Auto-Restore")
        print("9. Exit\n")
        opt = input("Select option (1-9): ").strip()
        if opt == "1":
            create_setup()
        elif opt == "2":
            manage_xray()
        elif opt == "3":
            restart_wireguard()
        elif opt == "4":
            delete_setup()
        elif opt == "5":
            debug_setup()
        elif opt == "6":
            restore_all_setups()
            input("Press Enter to continue...")
        elif opt == "7":
            restore_from_config_file()
        elif opt == "8":
            setup_auto_restore_service()
        elif opt == "9":
            sys.exit(0)
        else:
            print("Invalid option")
            time.sleep(1)


if __name__ == "__main__":
    # If run with specific switch, only auto-refresh without menu is executed
    if len(sys.argv) > 1 and sys.argv[1] in ("--auto-refresh", "--watch"):
        auto_refresh_main(interval_seconds=None)  # Will load from config
    elif len(sys.argv) > 1 and sys.argv[1] == "--restore":
        # Restore all tunnels (called by systemd service)
        # This runs silently without any user interaction
        require_root()
        
        # Load config and panel state silently
        config = load_config()
        load_panel_state()
        
        # Restore tunnels immediately without prompts
        restore_all_setups()
        
        # Start UUID watcher if panel is configured
        if config.get("panel_type") and config.get("panel_db_path"):
            if start_background_uuid_watcher():
                interval = config.get("uuid_refresh_interval", 5)
                debug_log(f"restore: started UUID watcher with interval {interval}s")
            else:
                debug_log("restore: failed to start UUID watcher")
        
        # Exit silently (systemd will log output to journal)
        sys.exit(0)
    elif len(sys.argv) > 1 and sys.argv[1] == "--start-watcher":
        # Start watcher using systemd service (preferred) or as background process
        require_root()
        if ensure_uuid_watcher_service():
            print("UUID Watcher started via systemd service")
            print("To check status: systemctl status setup-wg-uuid-watcher")
            print("To stop: systemctl stop setup-wg-uuid-watcher")
            print("Logs: tail -f /tmp/setup-wg-watch.log")
        else:
            # Fallback: start as background process
            script_path = os.path.abspath(__file__)
            subprocess.Popen(
                [sys.executable, script_path, "--auto-refresh"],
                stdout=open("/tmp/watcher.log", "w"),
                stderr=subprocess.STDOUT,
                start_new_session=True
            )
            print("UUID Watcher started in background (fallback mode)")
            print("To stop: pkill -f 'auto_refresh_main'")
            print("Logs: tail -f /tmp/setup-wg-watch.log")
    else:
        main()


