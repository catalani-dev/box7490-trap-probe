# FRITZ!Box 7490 + OpenWrt

**English** · [Italiano](README.it.md)

Give a second life to AVM FRITZ!Box 7490 routers. Run OpenWrt on them and turn them into **LAN traps**, which report anyone probing the network, or into **monitoring probes** reachable over WireGuard. The repository also contains the syslog receiver that collects the trap logs, groups them into incidents and sends alerts.

| Folder | What it is | Runs on |
|---|---|---|
| [`openwrt-7490/`](openwrt-7490/README.md) | `OpenWrt-7490.bat`: a menu-driven tool that boots OpenWrt in RAM, installs it on the flash and configures the box as a trap or a probe | Windows 10/11 (menus in Italian) |
| [`lan-trap-receiver/`](lan-trap-receiver/README.md) | LAN Trap Receiver: an always-on syslog receiver that groups trap log lines into incidents and sends one alert by e-mail, Google Chat, webhook or command | Linux, Windows or Docker, Python 3.11+, no dependencies |

## How the pieces fit

```
 Windows PC                    FRITZ!Box 7490 with OpenWrt               receiver
 ┌──────────────────────┐      ┌─────────────────────────────────┐      ┌──────────────────────────┐
 │ OpenWrt-7490.bat     │ ───► │ trap: logs new TCP connections  │ ───► │ lantrap: which trap,     │
 │ 1. OpenWrt in RAM    │ cable│ to unused ports (SMB, RDP, …)   │syslog│ exclusions, one incident │
 │ 2. install on flash  │      │ probe: WireGuard, Zabbix or     │ (UDP,│ per scan, alerts,        │
 │ 3. trap/probe profile│      │ Prometheus, iperf3, tcpdump, mtr│ TCP, │ history                  │
 └──────────────────────┘      └─────────────────────────────────┘  TLS)└──────────────────────────┘
```

A trap is useful because nobody has a reason to connect to SMB, RDP or a database on a box that offers none of them: every attempt is a scan, a worm or someone moving through the network. It also sees devices where no endpoint agent can be installed, such as printers, cameras and visitors' laptops.

## Quick start

**Windows tool:** download the repository (Code > Download ZIP), extract it and run `openwrt-7490\OpenWrt-7490.bat`. Keep the `profili` folder next to the script. The steps are in [openwrt-7490/README.md](openwrt-7490/README.md).

**Receiver:**

```bash
git clone https://github.com/catalani-dev/fritzbox-7490-openwrt.git
cd fritzbox-7490-openwrt/lan-trap-receiver
python3 -m lantrap init     # writes lantrap.toml
python3 -m lantrap          # interactive menu, English or Italian
```

Details in [lan-trap-receiver/README.md](lan-trap-receiver/README.md).

## Status

Version 0.1.0, first public release.

| Part | Checked | Not checked yet |
|---|---|---|
| OpenWrt 25.12.6 in RAM on a 7490 with Micron NAND | By hand on real hardware: boot through EVA, SSH, LuCI, dmesg | |
| Trap rule | By hand in RAM on real hardware | Permanent installation |
| `OpenWrt-7490.bat` and its profiles | Parsers, forms with scripted answers, scripts run in a simulated OpenWrt | A complete run on real hardware; flash installation |
| LAN Trap Receiver | 111 automated tests (one is skipped on Windows), including a run over real UDP and TCP sockets | With a real box |

## Safety

- Installing OpenWrt replaces FRITZ!OS: Wi-Fi, DECT, telephony and AVM updates are lost.
- The flash installation has not been tried with this tool yet. On units with Micron NAND, problems have been reported with some OpenWrt versions: do the first flash on a unit without Micron NAND.
- Only the FRITZ!Box 7490 is supported.
- Use traps and probes only on networks you are responsible for.
- The software comes without any warranty: see the license.

## License

[MIT](LICENSE)
