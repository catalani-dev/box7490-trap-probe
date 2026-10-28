# Box7490.bat

**English** · [Italiano](README.it.md)

A single Windows file that runs *OpenWrt* on an **AVM FRITZ!Box 7490**: first in RAM only, then, if you want, installed on the flash. It also turns the box into a **LAN trap** or a **monitoring probe**. The menus and messages are in Italian.

Part of [box7490-trap-probe](../README.md). The trap works with the [LAN Trap Receiver](../lan-trap-receiver/README.md).

> Not affiliated with the *OpenWrt* project or with FRITZ! GmbH (formerly AVM). *OpenWrt* is a registered trademark owned by Software Freedom Conservancy (SFC); FRITZ!Box is a trademark of FRITZ! GmbH. The tool downloads *OpenWrt* from https://openwrt.org and does not redistribute it: see [License, third-party software and trademarks](../README.md#license-third-party-software-and-trademarks).

> [!WARNING]
> Installing *OpenWrt* **replaces FRITZ!OS**. The 7490 loses Wi-Fi, DECT, telephony, the AVM apps and AVM updates. The flash installation has not been tried with this tool yet: read [Status](#status) first.

## What it does

| Menu item | What happens |
|---|---|
| **Avvia in RAM** (boot in RAM) | Downloads the official initramfs image, checks it and loads it into RAM through the AVM bootloader (EVA). Nothing is written to the flash: switching the box off brings FRITZ!OS back. |
| **Installa sulla flash** (install on flash) | Replaces FRITZ!OS with *OpenWrt* (`sysupgrade -n`). Before writing it checks the NAND variant and the kernel log, and on Micron NAND it asks you to type that you accept the risk. |
| **Configura come trappola** (trap) | The box becomes a client of the LAN and logs every attempt to connect to ports such as SMB, RDP, Telnet or databases. |
| **Configura come sonda** (probe) | The box becomes a client of the LAN with a WireGuard management tunnel, a Zabbix or Prometheus agent, and iperf3, tcpdump and mtr. |
| **Stato del box** (status) | Version, NAND, address, clock, trap, tunnels and agents of the box. |
| **Strumenti** (tools) | SSH console, LuCI in the browser, save dmesg and logs (without keys or passwords), reboot. |
| **Rete del PC** (PC network) | Sets the work addresses on the network adapter connected to the box, or puts back the previous settings. |
| **Impostazioni** (settings) | Box address, *OpenWrt* version, network adapter, program folder. |

## Requirements

- Windows 10 or 11 with Windows PowerShell 5.1 (built in) and the OpenSSH client (Settings > Apps > Optional features).
- An administrator account: the tool sets the IP addresses of the network adapter. It asks for elevation by itself.
- A cable from the PC to a LAN port of the FRITZ!Box, and internet on the PC through another adapter, for example Wi-Fi.

## Downloads and checks

| File | Source | Check |
|---|---|---|
| *OpenWrt* images (initramfs, sysupgrade) | downloads.openwrt.org | SHA256 compared with the official `sha256sums` of the same release |
| Images with extra packages (trap, probe) | the official build service sysupgrade.openwrt.org | SHA256 returned by the service; the package list is checked against the build manifest |
| `eva_ramboot.py` | *OpenWrt* repository, pinned commit | fixed SHA256 |
| Python embeddable (runs `eva_ramboot.py`, nothing is installed) | python.org | fixed SHA256 and Authenticode signature of the Python Software Foundation |

Files created next to the script: `cache\` (downloads), `stato\` (settings, last answers, saved adapter configuration), `log\` (session transcripts and the output of each configuration, including the WireGuard `[Peer]` block). The tool uses its own SSH key, `%USERPROFILE%\.ssh\box7490_ed25519`, and installs it on the box when it configures it.

## Step by step

1. **Find the NAND maker.** In FRITZ!OS open `http://192.168.178.1/support.lua`, save the support data (it takes a couple of minutes) and search for `NAND device`. Manufacturer ID `0x2c` is Micron and needs the `-micron` images; `0x98` (Toshiba), `0xad` (Hynix), `0xec` (Samsung) and `0xc2` (Macronix) use the standard ones. The same file shows `HWRevision` (185 = 7490).
2. **Boot in RAM.** Choose the NAND variant, let the tool set the work addresses on the adapter, then switch the FRITZ!Box off, wait 5 seconds and switch it on. EVA accepts the upload only for a few seconds after power-on: the tool waits for it. *OpenWrt* answers on `192.168.1.1` after 1-2 minutes (SSH as `root`, no password; LuCI with the same login).
3. **Check the kernel log**, shown by the tool. On a healthy box with FRITZ!OS still on the flash you see `nand: device found, Manufacturer ID: …` and `UBI error: no valid UBI magic found inside mtd1`. That UBI line is normal: FRITZ!OS does not use UBI, so *OpenWrt* does not attach the partition and writes nothing. Lines with `Bad eraseblock`, ECC errors, bitflips or other UBI errors are a reason to stop: the tool refuses to install in that case.
4. **Try a profile in RAM** if you like. The settings are lost when the box is switched off.
5. **Install on the flash** with the image that matches the NAND. The tool copies the image to the box, compares its SHA256, runs `sysupgrade -T` and asks you to type `INSTALLA` before `sysupgrade -n`. Then configure the trap or the probe again: the installed system starts from defaults.

### Why the PC uses fixed addresses without a gateway

The tool sets `192.168.178.2/24` (for EVA, which has no DHCP) and `192.168.1.2/24` (for *OpenWrt*) on the cable, with **no gateway**. A FRITZ!Box without a DSL line answers every DNS query with its own address: a PC that uses it as gateway loses internet and TLS. The previous settings of the adapter are saved and can be restored from **Rete del PC**, or when you exit.

## Profiles

The configuration is plain shell code in [`profili/`](profili), sent to the box over SSH together with your answers.

**Common part** ([`base-lan.sh`](profili/base-lan.sh)):
- hostname, time zone Europe/Rome, NTP;
- LAN address from the customer's DHCP or fixed, with gateway and DNS;
- WAN and DSL off; DHCP server and IPv6 announcements off, so the box cannot disturb the LAN;
- firewall: from the LAN only SSH from the management addresses you list, ping and DHCP replies;
- SSH with keys only once a key is installed; root password required on the flash;
- LuCI off (on the probe it can stay on, reachable only through the tunnel).

**Trap** ([`trappola.sh`](profili/trappola.sh)): a file in `/etc/nftables.d/` adds a chain with higher priority than fw4 and an `accept` policy, so it only logs. New TCP connections to the chosen ports are logged with the prefix `LANTRAP:`, rate limited, except for an exclusion set (for example your own scanners) that can be changed live with `nft add element inet fw4 lantrap_exclude { … }`. Nothing listens on those ports, so the box still refuses the connection. The log can go to a syslog receiver, and a cron job writes a heartbeat every 10 minutes. If `fw4 check` rejects the rule, the previous file is put back. Instead of the built-in trap you can run the script printed by `lantrap openwrt <trap>` on the receiver.

**Probe** ([`sonda.sh`](profili/sonda.sh)): a WireGuard interface `mgmt` towards your server, a firewall zone that accepts everything from the tunnel, optional NAT from the tunnel to the LAN, the Zabbix agent or the Prometheus node exporter, optional remote log. At the end it prints the `[Peer]` block to add to the WireGuard server. The packages must be in the image (menu: install the probe image) or the box needs internet to install them.

## Troubleshooting

- **Started from PowerShell 7:** the launcher clears `PSModulePath`, otherwise Windows PowerShell 5.1 inherits the module paths of PowerShell 7 and does not find `Get-FileHash` or `Get-AuthenticodeSignature`.
- **A LuCI page does not load** (for example Status > Firewall): some antivirus products with network attack protection block LuCI requests to `/cgi-bin/cgi-exec` that run commands.
- **Log times in 1970:** the box has no NTP server it can reach. Set a gateway or an NTP server in the LAN.
- **The box is unreachable after configuring it in RAM with DHCP:** on a bench without a DHCP server it gets no address. Switch it off and boot it in RAM again.

## Status

| Part | Checked | Not checked yet |
|---|---|---|
| *OpenWrt* 25.12.6 in RAM on a 7490 with Micron NAND (HWRevision 185, FRITZ!OS 7.62), with the official `eva_ramboot.py` | On real hardware: boot, SSH, LuCI, dmesg | |
| Trap rule | In RAM on real hardware: 5 log lines per attempt (Windows retries a refused SYN), exclusion set changed live | |
| Flash installation and return to FRITZ!OS | | Not tried. The usual way back is the AVM recovery tool for the model, through EVA |
| DSL | Firmware and driver load | A real line; Italian lines probably need annex A instead of the default annex B |

Only the FRITZ!Box 7490 is supported. Other FRITZ!Box models supported by *OpenWrt* need different procedures (for example the 7520 and 7530 need U-Boot on the flash).

## License

[MIT](../LICENSE). Third-party licenses and trademarks: [main README](../README.md#license-third-party-software-and-trademarks).
