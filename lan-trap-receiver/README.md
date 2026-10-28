# LAN Trap Receiver

**English** · [Italiano](README.it.md)

Part of [box7490-trap-probe](../README.md): the Windows tool [`Box7490.bat`](../box7490/README.md) sets up a FRITZ!Box 7490 as a trap, also with the script printed by `lantrap openwrt`.

A small, always-on syslog receiver for **LAN traps**: *OpenWrt* boxes placed in a local network that offer no services but log every attempt to connect to ports such as SMB, RDP, Telnet or databases. Nobody has a reason to touch those ports on that box, so every attempt is worth a look: a port scan, a worm, someone moving sideways.

The receiver recognises which trap and which customer a message comes from, drops the addresses that are allowed to scan (for example the IT team's scanners), groups the many log lines of one scan into a single incident, sends one alert by e-mail, Google Chat, webhook or an external command, and keeps the history.

It complements endpoint protection: an agent sees scans only on the computers where it is installed, while a trap sees whatever touches it, including printers, cameras, unmanaged laptops and visitors' devices.

## How it works

```
 LAN of a site                                   receiver (Linux, Windows or Docker)
 ┌──────────────────────────────┐                ┌──────────────────────────────────────────┐
 │ PC ──SYN 445──► OpenWrt trap │  syslog (UDP,  │ 1. which trap / customer (sender address)│
 │                  nft rule    │  TCP or TLS),  │ 2. exclusions (global, customer, trap)   │
 │                  logs SYN,   │ ─────────────► │ 3. lines → attempts → one incident       │
 │                  box refuses │  inside a      │ 4. one alert: SMTP, Google Chat,         │
 │                  logd sends  │  WireGuard     │    webhook, command (ticketing)          │
 └──────────────────────────────┘  tunnel        │ 5. history: SQLite, JSON Lines, CSV      │
                                                 └──────────────────────────────────────────┘
```

A log line from the box looks like this:

```
kern.warn kernel: [19765.020000] LANTRAP: IN=br-lan OUT= MAC=… SRC=192.168.1.2 DST=192.168.1.1 LEN=52 … PROTO=TCP SPT=53463 DPT=8080 WINDOW=65535 RES=0x00 SYN URGP=0
```

## Features

- **No dependencies.** Python 3.11 or later with the standard library only. Runs on Linux, Windows, macOS and in Docker.
- **Interactive menu** with arrow keys, number keys, Enter and Esc, in **English** (default) or **Italian**. Every setting of the configuration can be changed from it, and every action is also a subcommand for scripts and services.
- **Listeners:** UDP, TCP and TLS (optionally with client certificates), any combination and any port. TCP accepts LF or NUL trailers (*OpenWrt* `logd`) and RFC 6587 octet counting (rsyslog, syslog-ng).
- **Formats:** RFC 3164 as sent by *OpenWrt* `logd`, RFC 5424, and lines copied from `logread`.
- **Trap identity** from the sender address (best inside WireGuard, where the address is tied to the key) with an optional hostname check. Unknown senders are dropped and listed, so they can be added as traps from the menu.
- **Exclusions** by IP address, network or MAC address, globally, per customer or per trap. Excluded hits are recorded but never alert.
- **Grouping:** repeated lines for the same port are one attempt, and attempts from the same source to the same trap are one incident until it goes quiet. A port scan produces one alert, not dozens.
- **Alerts:** SMTP, Google Chat (one thread per incident), generic JSON webhook with an optional HMAC signature, and external command (the JSON alert on standard input, for example to open a ticket). Any combination, with filters by event and customer, an hourly limit and reminders while an incident goes on.
- **Heartbeat:** an alert when a trap stops sending logs, and another when it comes back.
- **History:** SQLite (needed for status and reports), JSON Lines and CSV files, any combination, with retention in days.
- **Live configuration reload:** exclusions, traps and alert channels change without a restart.
- **Box setup:** `lantrap openwrt <trap>` prints the shell script for the *OpenWrt* box: firewall rule, remote log, NTP, heartbeat and WireGuard.

## Quick start

```bash
git clone https://github.com/catalani-dev/box7490-trap-probe.git && cd box7490-trap-probe/lan-trap-receiver
python3 -m lantrap init          # writes lantrap.toml with default settings
python3 -m lantrap               # interactive menu
```

On Windows, double-click `lantrap.bat` or run `lantrap.bat` from a command prompt; it uses the `py` launcher or `python`. `pip install .` also installs a `lantrap` command.

The menu starts in English. Italian is chosen from the **Language / Lingua** item, which saves the choice and also applies to alerts; on the first start the menu asks for the language with English preselected. `--lang it` switches for one run only.

### The menu

Every setting can be changed from the menu, and only the ones you choose:

- **Forms.** Each section lists all of its settings with their current value; a setting that was never changed shows its default. Pick a line and press Enter to change it: yes/no settings switch at once, choices and event filters open a list, the other values are typed. `-` puts a setting back to its default. **Save** checks the whole configuration and writes it; **Cancel** or Esc leaves everything as it was.
- **Lists.** Listeners, alert channels, history formats, customers and traps are lists: add as many entries as you need, including several channels of the same type, then edit or remove each one. A channel can also send a test alert from its own page.
- **Secrets** (SMTP password, webhook URLs, HMAC secret) can be stored as an environment variable name, a file path or the value itself.
- **Sections:** General, Listeners, Alert channels, Storage, Grouping, Heartbeat, *OpenWrt* box setup, WireGuard; and, under Clients, the customers with their traps and exclusions, all traps, the exclusions for every customer, and new traps from senders that are not configured yet.

Typical first steps:

1. **Settings → Alert channels → + Add**, choose the type and fill in what you need.
2. **Clients, traps and exclusions → + Add** a customer, open it, then **Traps of this client → + Add** with the address the trap sends from.
3. **Send a test alert.**
4. **Start receiver**, and from a second window **Simulate a trap** to see a complete alert.

To try it without a box: `python3 -m lantrap simulate --port 5514` sends the 25 lines of a five-port scan from a Windows client (five lines per port, because Windows retries a refused connection).

## Configuration

One file, TOML (`lantrap.toml`) or JSON (`lantrap.json`). The program looks for `--config`, then the `LANTRAP_CONFIG` variable, then `./lantrap.toml`, `./lantrap.json` and `/etc/lantrap/lantrap.toml`. [`config.example.toml`](config.example.toml) documents every setting. The menu edits the same file and validates it before saving.

| Section | What it holds |
|---|---|
| top level | `language`, accepted log `prefixes`, `unknown_sources` (`drop` or `accept`), global `exclude`, `store_excluded`, `store_other` |
| `[grouping]` | `collect_seconds` (60), `quiet_minutes` (15), `retry_seconds` (5), `reminder_minutes` (60), `scan_ports` (3), `notify_on_close`, `max_alerts_per_hour` (30) |
| `[heartbeat]` | `enabled`, `missing_minutes` (30) |
| `[[listen]]` | `protocol` (`udp`, `tcp`, `tls`), `address`, `port`, `allow`; for TLS `certfile`, `keyfile`, optional `cafile` |
| `[[store]]` | `type` (`sqlite`, `jsonl`, `csv`), `path` or `directory`, `retention_days` |
| `[[notify]]` | `type` (`smtp`, `google_chat`, `webhook`, `command`), `name`, `events`, `clients`, `language`, `enabled` and the options of the channel |
| `[[client]]` | `id`, `name`, `exclude` |
| `[[trap]]` | `id`, `name`, `client`, `source` (addresses or networks), `hostname`, `exclude`, `heartbeat`, `tunnel_ip` |
| `[openwrt]`, `[wireguard]` | values used to write the box setup script |

Relative paths are relative to the configuration file. Secrets can be written inline (`password`, `url`, `secret`), read from an environment variable (`password_env`, `url_env`, `secret_env`) or from a file (`password_file`, `url_file`, `secret_file`). Keep the configuration readable only by the account that runs the receiver.

The receiver checks the file every few seconds (and on `SIGHUP` on Linux). A file with errors is rejected and the previous configuration stays in use. Changes to listeners and storage need a restart.

## Grouping

| Term | Meaning |
|---|---|
| line | one log message from the trap |
| attempt | lines for the same source, trap and port with less than `retry_seconds` between them, for example a Windows client retrying a refused SYN several times |
| incident | attempts from one source address to one trap, until `quiet_minutes` without lines |
| port scan | an incident that touched at least `scan_ports` different ports; otherwise a connection attempt |

The first alert of an incident leaves after `collect_seconds`, so that a fast scan arrives complete in one message. While the incident goes on, a reminder follows every `reminder_minutes` if there is new activity. `max_alerts_per_hour` is a budget per customer: further incident alerts wait for a free slot and go out later, never dropped, and each alert shows how many others of the same customer are waiting. When the receiver stops, the first alerts still in their collection window are sent before it exits.

## Alerts

Example (e-mail, English):

```
Subject: [LAN Trap] [Example Ltd] Port scan from 192.168.1.2

Client:     Example Ltd
Trap:       Example head office (example-hq)
Source:     192.168.1.2 (MAC 00:11:22:33:44:55)
Target:     192.168.1.1
Type:       port scan (5 ports)
Ports:      21/tcp FTP, 23/tcp Telnet, 445/tcp SMB, 3389/tcp RDP, 8080/tcp HTTP-alt
Attempts:   5 (25 log lines)
First seen: 2026-10-23 14:01:02
Last seen:  2026-10-23 14:01:10
Status:     in progress
Incident:   20261023-140102-a1b2c3
```

Events: `incident`, `incident_update`, `incident_closed`, `trap_silent`, `trap_back`, plus `test` from the menu or `lantrap test-alert`.

Webhooks and commands receive this JSON document (schema `lantrap.alert/1`):

```json
{
  "schema": "lantrap.alert/1",
  "id": "4f0c2a9d1e6b7c88",
  "kind": "incident",
  "created_at": "2026-10-23T12:02:02+00:00",
  "language": "en",
  "title": "[Example Ltd] Port scan from 192.168.1.2",
  "text": "Client: Example Ltd\n...",
  "client": {"id": "example", "name": "Example Ltd"},
  "trap": {"id": "example-hq", "name": "Example head office"},
  "incident": {
    "id": "20261023-140102-a1b2c3", "source_ip": "192.168.1.2", "source_macs": ["00:11:22:33:44:55"],
    "destinations": ["192.168.1.1"], "first_seen": "...", "last_seen": "...", "lines": 25, "attempts": 5,
    "ports": [{"proto": "tcp", "port": 445, "service": "SMB", "attempts": 1, "lines": 5}],
    "classification": "port_scan", "status": "open", "alerts_sent": 1
  },
  "details": {},
  "waiting_alerts": 0,
  "receiver": {"host": "receiver-01", "version": "0.1.0"}
}
```

With `secret` set, a webhook request carries `X-Lantrap-Signature: sha256=<HMAC-SHA256 of the body>`; every request carries `X-Lantrap-Event: <kind>`. A `command` channel gets the same JSON on standard input and the variables `LANTRAP_EVENT` and `LANTRAP_ALERT_ID`; a non-zero exit code counts as a failure. This is the place to plug in a ticketing system. Every channel is tried three times; if it still fails, the alert is tried again after 1, 5, 15, 30, 60, 120 and 240 minutes (in memory, so a restart forgets those retries). The result of each delivery is recorded in the history.

## Setting up a trap (*OpenWrt*)

```bash
python3 -m lantrap openwrt example-hq -o lantrap-example-hq.sh
scp -O lantrap-example-hq.sh root@192.168.1.1:/tmp/ && ssh root@192.168.1.1 sh /tmp/lantrap-example-hq.sh
```

The script, which can be run again after a change:

1. With `[wireguard]` and `tunnel_ip` set: installs WireGuard (`apk` on *OpenWrt* 25.12 and later, `opkg` before), creates a key on the box, sets up the tunnel to the receiver and prints the `[Peer]` block for the receiver.
2. Writes `/etc/nftables.d/10-lantrap.nft` ([example](openwrt/10-lantrap.nft)) with the ports, the rate limit and the excluded IPv4 addresses (IPv6 with `ipv6 = true`), then runs `fw4 check`. If the check fails, the previous file is put back and the script stops before reloading the firewall; otherwise it runs `fw4 reload`.
3. Sets `log_ip`, `log_port`, `log_proto` and `log_hostname` in `/etc/config/system` and restarts the log service.
4. Enables NTP. Without a correct clock, the times written by the box are wrong; the receiver groups by its own clock and reports traps whose clock is off.
5. Adds a cron job `logger -t lantrap heartbeat` every 10 minutes for the heartbeat.

Notes:
- The box must give the trap address to nothing else and run no services on the logged ports: it refuses the connection after logging it.
- The rate limit on the box (60 lines per minute) protects the box and the receiver from floods. Exclude known scanners on the box as well as in the receiver, so that their traffic does not use up the limit.
- MAC exclusions are applied only by the receiver.

The receiver side of WireGuard is a normal `wg-quick` interface: see [`deploy/wg0.conf.example`](deploy/wg0.conf.example). The traps connect out to the receiver, so nothing has to be opened at the customer sites.

## Keeping it running

- **Linux (systemd):** [`deploy/lantrap.service`](deploy/lantrap.service), or `lantrap service systemd` for a unit with the paths of the current installation. Ports below 1024 need `CAP_NET_BIND_SERVICE`; the default port is 5514.
- **Windows:** `lantrap service windows --write` writes a start file next to the configuration and prints the `schtasks` and firewall commands for a task that starts at boot as SYSTEM. Install Python for all users, so that SYSTEM can run it, and keep the program, the configuration and the start file in folders that only administrators can change (for example `C:\Program Files` and `C:\ProgramData`), never in a user profile.
- **Docker:** [`deploy/Dockerfile`](deploy/Dockerfile) and [`deploy/compose.yaml`](deploy/compose.yaml). Host networking keeps the real sender addresses.

## Command line

```
lantrap [-c CONFIG] [--lang en|it] [-v] [--log-file FILE] [command]

  menu         interactive menu (default)
  run          run the receiver in the foreground
  init         create a configuration file with default settings
  check        validate the configuration and the alert channels
  status       traps with their last message, unknown senders, latest incidents
  incidents    latest incidents (--json)
  test-alert   send a test alert (--channel NAME, repeatable)
  simulate     send fake trap lines to a running receiver
  import FILE  analyse saved log lines offline (--trap ID, --save)
  openwrt ID   print the setup script for a trap box
  service      how to keep the receiver running: systemd, windows, docker
```

Exit codes: 0 success, 1 failure, 2 configuration error.

## Security

- Run the receiver as an unprivileged user and expose the syslog ports only on the tunnel or management interface (`address`, `allow`, host firewall).
- Syslog over UDP or TCP is neither authenticated nor encrypted: use WireGuard or TLS across untrusted networks. Inside WireGuard the sender address is bound to the peer key, which is what makes it a reliable trap identity. The hostname in a message can be written by anyone, so it is only an extra check.
- Secrets can stay out of the configuration file through environment variables or files.
- CSV cells that start with `=`, `+`, `-` or `@` are prefixed with a quote, so that they do not run as spreadsheet formulas.
- Frames are limited to 64 KiB; TCP connections to 512 in total and 16 per sender, closed after 30 minutes without data. Incidents keep at most 1024 ports, 64 targets and 16 MAC addresses, and at most 1024 unknown senders are remembered. The box rate limit bounds the traffic of a single trap.
- Hostnames and tags received over the network are kept only if they are printable ASCII, so they cannot inject terminal escape sequences into logs or the menu.
- Log prefixes and names written into the box script are validated, so they cannot break the nft file or the shell script.

## Limitations

- Incidents live in memory. After a restart, incidents left open are closed in the history, and new activity starts a new incident.
- Delivery retries live in memory: an alert that is still failing when the receiver stops is recorded as failed and not tried again.
- With `unknown_sources = "accept"`, every new sender address is tracked as a trap: use it only behind a tunnel or an allow list.
- One remote log destination per *OpenWrt* box, which is a limit of `logd`. For a second receiver, use rsyslog or syslog-ng on the box.
- The receiver does not check that a trap is reachable: the heartbeat only notices that its messages stopped.

## Development

```bash
python3 -m unittest discover -s tests
```

The tests cover parsing of real *OpenWrt* lines, grouping, exclusions, heartbeat, every alert channel (against local fake SMTP and HTTP servers), the history formats, the menu and an end-to-end run over real UDP and TCP sockets.

## License

[MIT](../LICENSE). Not affiliated with the *OpenWrt* project; *OpenWrt* is a registered trademark owned by Software Freedom Conservancy (SFC), https://openwrt.org. More in the [main README](../README.md#license-third-party-software-and-trademarks).
