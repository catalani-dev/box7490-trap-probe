"""Shell script that turns an OpenWrt box into a trap for a configured trap entry."""

from __future__ import annotations

import ipaddress
import re
import shlex

from .config import Config, ConfigError, Trap

_SAFE_HOST = re.compile(r"^[A-Za-z0-9.-]{1,63}$")
_NFT_FILE = "/etc/nftables.d/10-lantrap.nft"
_BACKUP = "/tmp/10-lantrap.nft.previous"


def _q(value: str) -> str:
    return shlex.quote(value)


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    m = re.match(r"^\[([0-9A-Fa-f:]+)\]:(\d+)$", endpoint) or re.match(r"^([^:]+):(\d+)$", endpoint)
    if m:
        return m.group(1), m.group(2)
    return endpoint, "51820"


def _exclusions(config: Config, trap: Trap, version: int) -> list[str]:
    out: list[str] = []
    client = config.clients.get(trap.client)
    for matcher in (trap.exclude, client.exclude if client else None, config.exclude):
        if not matcher:
            continue
        for net in matcher.networks:
            if net.version == version:
                text = str(net) if net.num_addresses > 1 else str(net.network_address)
                if text not in out:
                    out.append(text)
    return out


def _has_mac_exclusions(config: Config, trap: Trap) -> bool:
    client = config.clients.get(trap.client)
    return any(m and m.macs for m in (trap.exclude, client.exclude if client else None, config.exclude))


def nft_rules(config: Config, trap: Trap) -> str:
    o = config.openwrt
    prefix = (config.prefixes[0] if config.prefixes else "LANTRAP:").strip() + " "
    ports = ", ".join(str(p) for p in o.ports)
    log = f'ct state new limit rate {o.rate_per_minute}/minute burst 20 packets log prefix "{prefix}" level warn'
    lines = []
    families = [("ip", "ipv4_addr", 4, o.set_name)]
    if o.ipv6:
        families.append(("ip6", "ipv6_addr", 6, f"{o.set_name}6"))
    for _family, kind, version, name in families:
        lines += [f"set {name} {{", f"\ttype {kind}", "\tflags interval", "\tauto-merge"]
        elements = _exclusions(config, trap, version)
        if elements:
            lines.append(f"\telements = {{ {', '.join(elements)} }}")
        lines += ["}", ""]
    lines += ["chain lantrap {", "\ttype filter hook input priority filter - 1; policy accept;"]
    for family, _kind, _version, name in families:
        lines.append(f'\tiifname "{o.interface}" {family} saddr != @{name} tcp dport {{ {ports} }} {log}')
    lines.append("}")
    return "\n".join(lines)


def box_script(config: Config, trap: Trap) -> str:
    o = config.openwrt
    wg = config.wireguard
    receiver = o.receiver or (wg.receiver_ip if wg else "")
    if not receiver:
        raise ConfigError("set openwrt.receiver (the address the trap sends logs to) or wireguard.receiver_ip")
    hostname = trap.hostname or trap.id
    if not _SAFE_HOST.match(hostname):
        raise ConfigError(f"trap {trap.id}: hostname {hostname!r} is not usable on OpenWrt")
    client = config.clients.get(trap.client)
    s: list[str] = [
        "#!/bin/sh",
        f"# LAN Trap Receiver - trap {trap.id} ({trap.name}), client {client.name if client else trap.client}",
        "# Run on the OpenWrt box as root. Running it again updates the settings (for example new exclusions).",
        "set -e",
        "",
    ]
    if wg and trap.tunnel_ip:
        host, port = _split_endpoint(wg.endpoint)
        if not host or not wg.public_key or not wg.receiver_ip:
            raise ConfigError("wireguard: endpoint, public_key and receiver_ip are needed to set up the tunnel")
        addr = ipaddress.ip_address(trap.tunnel_ip)
        bits = 32 if addr.version == 4 else 128
        rbits = 32 if ipaddress.ip_address(wg.receiver_ip).version == 4 else 128
        s += [
            "# --- WireGuard tunnel to the receiver",
            "if ! command -v wg >/dev/null 2>&1; then",
            "\tif command -v apk >/dev/null 2>&1; then apk update && apk add wireguard-tools kmod-wireguard",
            "\telse opkg update && opkg install wireguard-tools kmod-wireguard; fi",
            "fi",
            "umask 077",
            "mkdir -p /etc/wireguard",
            "[ -s /etc/wireguard/lantrap.key ] || wg genkey > /etc/wireguard/lantrap.key",
            "uci -q delete network.lantrap || true",
            "uci set network.lantrap=interface",
            "uci set network.lantrap.proto='wireguard'",
            'uci set network.lantrap.private_key="$(cat /etc/wireguard/lantrap.key)"',
            f"uci add_list network.lantrap.addresses={_q(f'{addr}/{bits}')}",
            "uci -q delete network.lantrap_receiver || true",
            "uci set network.lantrap_receiver=wireguard_lantrap",
            "uci set network.lantrap_receiver.description='LAN Trap Receiver'",
            f"uci set network.lantrap_receiver.public_key={_q(wg.public_key)}",
            f"uci set network.lantrap_receiver.endpoint_host={_q(host)}",
            f"uci set network.lantrap_receiver.endpoint_port={_q(port)}",
            f"uci set network.lantrap_receiver.persistent_keepalive={_q(str(wg.keepalive))}",
            "uci set network.lantrap_receiver.route_allowed_ips='1'",
            f"uci add_list network.lantrap_receiver.allowed_ips={_q(f'{wg.receiver_ip}/{rbits}')}",
            "uci commit network",
            "ifup lantrap || /etc/init.d/network reload",
            "",
        ]
    s += [
        "# --- Firewall rule: log new connections to unused TCP ports",
        f"rm -f {_BACKUP}",
        f"[ -f {_NFT_FILE} ] && cp {_NFT_FILE} {_BACKUP}",
        f"cat > {_NFT_FILE} <<'EOF'",
        nft_rules(config, trap),
        "EOF",
        "if ! fw4 check; then",
        f"\tif [ -f {_BACKUP} ]; then mv {_BACKUP} {_NFT_FILE}; else rm -f {_NFT_FILE}; fi",
        "\techo 'fw4 rejected the trap rule: the firewall was left as it was' >&2",
        "\texit 1",
        "fi",
        f"rm -f {_BACKUP}",
        "fw4 reload",
        "",
        "# --- Send the log to the receiver",
        f"uci set system.@system[0].log_ip={_q(receiver)}",
        f"uci set system.@system[0].log_port={_q(str(o.log_port))}",
        f"uci set system.@system[0].log_proto={_q(o.log_proto)}",
        f"uci set system.@system[0].log_hostname={_q(hostname)}",
        "uci commit system",
        "/etc/init.d/log restart",
        "",
        "# --- Clock: log times are useless without NTP",
        "uci set system.ntp.enabled='1'",
    ]
    if o.ntp_servers:
        s.append("uci -q delete system.ntp.server || true")
        s += [f"uci add_list system.ntp.server={_q(server)}" for server in o.ntp_servers]
    s += ["uci commit system", "/etc/init.d/sysntpd restart", ""]
    if o.heartbeat_minutes:
        line = f"*/{o.heartbeat_minutes} * * * * logger -t lantrap heartbeat"
        s += [
            "# --- Heartbeat: lets the receiver notice a trap that stopped sending",
            "touch /etc/crontabs/root",
            "sed -i '/logger -t lantrap heartbeat/d' /etc/crontabs/root",
            f"echo {_q(line)} >> /etc/crontabs/root",
            "/etc/init.d/cron enable",
            "/etc/init.d/cron restart",
            "",
        ]
    s.append("logger -t lantrap 'trap configured'")
    if wg and trap.tunnel_ip:
        s += [
            "echo",
            "echo 'Add this peer to the WireGuard configuration of the receiver:'",
            "echo '[Peer]'",
            f"echo '# trap {trap.id}'",
            'echo "PublicKey = $(wg pubkey < /etc/wireguard/lantrap.key)"',
            f"echo 'AllowedIPs = {trap.tunnel_ip}/{32 if ipaddress.ip_address(trap.tunnel_ip).version == 4 else 128}'",
        ]
    if _has_mac_exclusions(config, trap):
        s.append("# MAC exclusions are applied by the receiver only.")
    return "\n".join(s) + "\n"
