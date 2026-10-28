"""Instructions to keep the receiver running: systemd, Windows Task Scheduler, Docker."""

from __future__ import annotations

import sys
from pathlib import Path

from .config import Config

PACKAGE_DIR = Path(__file__).resolve().parent.parent


def systemd_unit(config: Config) -> str:
    cfg = config.path or Path("/etc/lantrap/lantrap.toml")
    privileged = any(lst.port < 1024 for lst in config.listeners)
    caps = "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n" if privileged \
        else "CapabilityBoundingSet=\n"
    data_dirs = sorted({str(s.path.parent if s.type == "sqlite" else s.path) for s in config.stores}) or ["/var/lib/lantrap"]
    return f"""[Unit]
Description=LAN Trap Receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lantrap
Group=lantrap
WorkingDirectory={PACKAGE_DIR}
ExecStart={sys.executable} -m lantrap --config {cfg} run
ExecReload=/bin/kill -HUP $MAINPID
# secrets referenced with *_env in the configuration (file readable by root only)
EnvironmentFile=-{cfg.parent}/secrets.env
Restart=on-failure
RestartSec=5
{caps}NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths={' '.join(data_dirs)}
ReadOnlyPaths={cfg.parent}

[Install]
WantedBy=multi-user.target
"""


def windows_wrapper(config: Config) -> tuple[Path, str]:
    """A .cmd next to the configuration that starts the receiver with this Python and this copy of the program."""
    cfg = (config.path or Path("lantrap.toml")).resolve()
    wrapper = cfg.with_name("lantrap-service.cmd")
    content = (
        "@echo off\r\n"
        f'cd /d "{PACKAGE_DIR}"\r\n'
        f'"{sys.executable}" -m lantrap --config "{cfg}" --log-file "{cfg.with_name("lantrap.log")}" run\r\n'
    )
    return wrapper, content


def windows_task(config: Config) -> str:
    wrapper, _ = windows_wrapper(config)
    rules = "\n".join(
        f'netsh advfirewall firewall add rule name="LAN Trap Receiver {lst.protocol.upper()} {lst.port}" '
        f'dir=in action=allow protocol={"UDP" if lst.protocol == "udp" else "TCP"} localport={lst.port}'
        for lst in config.listeners
    )
    return f"""1. Write the start file (lantrap service windows --write creates it):
   {wrapper}

2. In an administrator command prompt:

{rules}
schtasks /Create /TN "LAN Trap Receiver" /SC ONSTART /RU SYSTEM /RL HIGHEST /F /TR "\\"{wrapper}\\""
schtasks /Run /TN "LAN Trap Receiver"

The task starts at boot without anyone signed in and logs to lantrap.log next to the configuration.
It runs as SYSTEM: keep the program, the configuration and the start file in folders that only
administrators can change (for example under C:\\Program Files and C:\\ProgramData), never in a user profile.
Python must be installed for all users. Stop it with: schtasks /End /TN "LAN Trap Receiver"
"""


def docker_hint() -> str:
    return f"""Files in {PACKAGE_DIR / 'deploy'}:
  Dockerfile    image with Python and the receiver (no extra packages)
  compose.yaml  service with the configuration and data mounted from ./config and ./data

  docker compose -f deploy/compose.yaml up -d --build
"""
