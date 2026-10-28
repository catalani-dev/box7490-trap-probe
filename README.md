# box7490-trap-probe

**English** · [Italiano](README.it.md)

> Not affiliated with the *OpenWrt* project or with FRITZ! GmbH (formerly AVM). *OpenWrt* is a registered trademark owned by Software Freedom Conservancy (SFC); FRITZ!Box is a trademark of FRITZ! GmbH. See [License, third-party software and trademarks](#license-third-party-software-and-trademarks).

Give a second life to AVM FRITZ!Box 7490 routers. Run *OpenWrt* on them and turn them into **LAN traps**, which report anyone probing the network, or into **monitoring probes** reachable over WireGuard. The repository also contains the syslog receiver that collects the trap logs, groups them into incidents and sends alerts.

| Folder | What it is | Runs on |
|---|---|---|
| [`box7490/`](box7490/README.md) | `Box7490.bat`: a menu-driven tool that boots *OpenWrt* in RAM, installs it on the flash and configures the box as a trap or a probe | Windows 10/11 (menus in Italian) |
| [`lan-trap-receiver/`](lan-trap-receiver/README.md) | LAN Trap Receiver: an always-on syslog receiver that groups trap log lines into incidents and sends one alert by e-mail, Google Chat, webhook or command | Linux, Windows or Docker, Python 3.11+, no dependencies |

## How the pieces fit

```
 Windows PC                    FRITZ!Box 7490 with OpenWrt               receiver
 ┌──────────────────────┐      ┌─────────────────────────────────┐      ┌──────────────────────────┐
 │ Box7490.bat          │ ───► │ trap: logs new TCP connections  │ ───► │ lantrap: which trap,     │
 │ 1. OpenWrt in RAM    │ cable│ to unused ports (SMB, RDP, …)   │syslog│ exclusions, one incident │
 │ 2. install on flash  │      │ probe: WireGuard, Zabbix or     │ (UDP,│ per scan, alerts,        │
 │ 3. trap/probe profile│      │ Prometheus, iperf3, tcpdump, mtr│ TCP, │ history                  │
 └──────────────────────┘      └─────────────────────────────────┘  TLS)└──────────────────────────┘
```

A trap is useful because nobody has a reason to connect to SMB, RDP or a database on a box that offers none of them: every attempt is a scan, a worm or someone moving through the network. It also sees devices where no endpoint agent can be installed, such as printers, cameras and visitors' laptops.

## Quick start

**Windows tool:** download the repository (Code > Download ZIP), extract it and run `box7490\Box7490.bat`. Keep the `profili` folder next to the script. The steps are in [box7490/README.md](box7490/README.md).

**Receiver:**

```bash
git clone https://github.com/catalani-dev/box7490-trap-probe.git
cd box7490-trap-probe/lan-trap-receiver
python3 -m lantrap init     # writes lantrap.toml
python3 -m lantrap          # interactive menu, English or Italian
```

Details in [lan-trap-receiver/README.md](lan-trap-receiver/README.md).

## Status

Version 0.1.0, first public release.

| Part | Checked | Not checked yet |
|---|---|---|
| *OpenWrt* 25.12.6 in RAM on a 7490 with Micron NAND | On real hardware: boot through EVA, SSH, LuCI, dmesg | |
| Trap rule | In RAM on real hardware | |
| Flash installation | | Not tried yet |
| LAN Trap Receiver | 111 automated tests (one is skipped on Windows), including a run over real UDP and TCP sockets | With a real box |

## Safety

- Installing *OpenWrt* replaces FRITZ!OS: Wi-Fi, DECT, telephony and AVM updates are lost.
- The flash installation has not been tried yet. On units with Micron NAND, problems have been reported with some *OpenWrt* versions: do the first flash on a unit without Micron NAND.
- Only the FRITZ!Box 7490 is supported.
- Use traps and probes only on networks you are responsible for.
- The software comes without any warranty: see the license.

## License, third-party software and trademarks

The code in this repository is released under the [MIT License](LICENSE).

This repository does not contain or redistribute *OpenWrt*, `eva_ramboot.py` or Python. `Box7490.bat` downloads them when it runs, from their official sources:
- *OpenWrt* images from downloads.openwrt.org and from the official build service sysupgrade.openwrt.org. *OpenWrt* is released under the GPL-2.0-only license; some of its components are under other free licenses.
- `eva_ramboot.py` from the *OpenWrt* source repository, under the same license.
- The embeddable Python from python.org, under the PSF License.

If you install *OpenWrt* on devices that you give to others, for example to customers, you are distributing GPL software and have to meet the obligations of the GPL-2.0: in short, provide the corresponding source code or a written offer for it (section 3 of the license). The *OpenWrt* project publishes the source code of every release.

This project is not affiliated with *OpenWrt*. *OpenWrt* is a registered trademark owned by Software Freedom Conservancy (SFC): https://openwrt.org

This project is not affiliated with, sponsored or endorsed by FRITZ! GmbH (formerly AVM GmbH). FRITZ!, FRITZ!Box and FRITZ!OS are trademarks of FRITZ! GmbH, named here only to identify the hardware the tool works with.
