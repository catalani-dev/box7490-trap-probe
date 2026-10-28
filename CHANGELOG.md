# Changelog

## 0.1.0 - 2026-10-28

First public version.

### OpenWrt-7490.bat

- Single-file Windows tool (batch launcher with the PowerShell code in the same file), menus in Italian, self-elevating; the launcher clears `PSModulePath` so it also works when started from PowerShell 7.
- Boot in RAM through the AVM bootloader (EVA) with the official `eva_ramboot.py`, run by the embeddable Python from python.org.
- Downloads checked against the official `sha256sums`, the hash returned by sysupgrade.openwrt.org, or fixed hashes; Authenticode signature of `python.exe` checked.
- NAND variant read from the kernel log; the flash is written only with the image that matches the NAND (the tool boots the right one in RAM first) and never when the log shows NAND problems; explicit risk acceptance on Micron NAND; `sysupgrade -T` before `sysupgrade -n`.
- Trap profile: nftables log rule with exclusion set and rollback if `fw4 check` fails, remote syslog, heartbeat. It can also run the script printed by `lantrap openwrt`.
- Probe profile: WireGuard management tunnel, Zabbix agent or Prometheus node exporter, remote log, `[Peer]` block for the server.
- Common LAN client profile: DHCP or fixed address, DHCP server and IPv6 announcements off, firewall open only to SSH from management addresses, key-only SSH.
- Box status, SSH console, LuCI, diagnostic dump without secrets, reboot; bench addresses on the PC adapter with backup and restore.

### LAN Trap Receiver 0.1.0

- Syslog listeners on UDP, TCP and TLS; RFC 3164 as sent by OpenWrt `logd`, RFC 5424, lines copied from `logread`; LF, NUL and octet-counting framing.
- Trap identification by sender address with an optional hostname check; unknown senders dropped and listed, or accepted.
- Exclusions by address, network or MAC address: global, per client, per trap.
- Grouping of log lines into attempts and incidents, first alert after a collection window, reminders, alert on close, hourly limit per client that delays alerts instead of dropping them; pending alerts are sent at shutdown.
- Heartbeat: alerts when a trap goes silent and when it comes back.
- Alert channels: SMTP, Google Chat (thread per incident), JSON webhook with HMAC signature, external command; failed deliveries are retried for several hours.
- History: SQLite, JSON Lines, CSV, with retention.
- Live configuration reload (file change or SIGHUP).
- Interactive menu in English and Italian where every setting can be changed; subcommands `run`, `init`, `check`, `status`, `incidents`, `test-alert`, `simulate`, `import`, `openwrt`, `service`.
- OpenWrt setup script: nftables rule with exclusion set (rolled back if fw4 check fails), remote log, NTP, heartbeat cron job, WireGuard tunnel (apk or opkg).
- Limits against floods: frame size, TCP connections per sender and idle timeout, ports and targets per incident, unknown senders; hostnames and tags from the network restricted to printable ASCII.
- systemd unit, Windows scheduled task, Dockerfile and compose file.
