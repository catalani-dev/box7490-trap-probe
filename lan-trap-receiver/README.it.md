# LAN Trap Receiver

[English](README.md) · **Italiano**

Fa parte di [fritzbox-7490-openwrt](../README.it.md): lo strumento per Windows [`OpenWrt-7490.bat`](../openwrt-7490/README.it.md) configura un FRITZ!Box 7490 come trappola, anche con lo script stampato da `lantrap openwrt`.

Un piccolo ricevitore syslog da tenere sempre acceso per le **trappole di rete**. Una trappola è un box OpenWrt messo in una rete locale: non offre servizi, ma registra ogni tentativo di collegarsi a porte come SMB, RDP, Telnet o i database. Nessuno ha motivo di toccare quelle porte su quel box, quindi ogni tentativo merita un'occhiata: una scansione, un worm, qualcuno che si muove nella rete.

Il ricevitore:
- riconosce da quale trappola e da quale cliente arriva un messaggio;
- scarta gli indirizzi autorizzati a scansionare, per esempio gli scanner dei tecnici;
- raggruppa le tante righe di una scansione in un solo incidente;
- manda un solo avviso per e-mail, Google Chat, webhook o comando esterno;
- conserva lo storico.

Completa la protezione degli endpoint. Un agente vede le scansioni solo sui computer dove è installato. La trappola vede chiunque la tocchi, comprese stampanti, telecamere, portatili non gestiti e dispositivi degli ospiti.

## Come funziona

```
 LAN di una sede                                 ricevitore (Linux, Windows o Docker)
 ┌──────────────────────────────┐                ┌──────────────────────────────────────────┐
 │ PC ──SYN 445──► trappola     │  syslog (UDP,  │ 1. quale trappola / cliente (mittente)   │
 │                 OpenWrt:     │  TCP o TLS),   │ 2. eccezioni (globali, cliente, trappola)│
 │                 la regola nft│ ─────────────► │ 3. righe → tentativi → un incidente      │
 │                 registra il  │  dentro un     │ 4. un avviso: SMTP, Google Chat,         │
 │                 SYN e rifiuta│  tunnel        │    webhook, comando (ticket)             │
 │                 logd invia   │  WireGuard     │ 5. storico: SQLite, JSON Lines, CSV      │
 └──────────────────────────────┘                └──────────────────────────────────────────┘
```

Una riga di log del box ha questa forma:

```
kern.warn kernel: [19765.020000] LANTRAP: IN=br-lan OUT= MAC=… SRC=192.168.1.2 DST=192.168.1.1 LEN=52 … PROTO=TCP SPT=53463 DPT=8080 WINDOW=65535 RES=0x00 SYN URGP=0
```

## Caratteristiche

- **Nessuna dipendenza.** Python 3.11 o successivo, solo la libreria standard. Gira su Linux, Windows, macOS e in Docker.
- **Menu interattivo** con frecce, tasti numerici, Invio ed Esc, in **inglese** (predefinito) o **italiano**. Dal menu si cambia ogni impostazione della configurazione, e ogni azione è anche un sottocomando, per script e servizi.
- **Ascolto:** UDP, TCP e TLS (anche con certificati client), in qualsiasi combinazione e su qualsiasi porta. In TCP accetta i terminatori LF o NUL (`logd` di OpenWrt) e il conteggio di ottetti dell'RFC 6587 (rsyslog, syslog-ng).
- **Formati:** RFC 3164 come lo invia `logd` di OpenWrt, RFC 5424 e righe copiate da `logread`.
- **Identità della trappola** dall'indirizzo del mittente, con un controllo facoltativo dell'hostname. Il posto migliore è dentro WireGuard, dove l'indirizzo è legato alla chiave. I mittenti sconosciuti vengono scartati ed elencati, e dal menu si possono aggiungere come trappole.
- **Eccezioni** per indirizzo IP, rete o MAC, globali, per cliente o per trappola. I colpi esclusi restano nello storico ma non generano avvisi.
- **Raggruppamento:** le righe ripetute sulla stessa porta sono un solo tentativo. I tentativi dalla stessa origine verso la stessa trappola sono un solo incidente, finché non torna il silenzio. Una scansione produce un avviso, non decine.
- **Avvisi**, in qualsiasi combinazione:
  - SMTP;
  - Google Chat, con un thread per incidente;
  - webhook JSON generico, con firma HMAC facoltativa;
  - comando esterno, che riceve l'avviso in JSON sullo standard input, per esempio per aprire un ticket.

  Si possono filtrare per evento e per cliente. C'è un limite orario, e finché l'incidente continua partono dei promemoria.
- **Segnale di vita:** un avviso quando una trappola smette di mandare log e un altro quando torna.
- **Storico:** SQLite (serve per stato e rapporti), file JSON Lines e CSV, in qualsiasi combinazione, con la durata in giorni.
- **Ricarica a caldo:** eccezioni, trappole e canali di avviso cambiano senza riavvio.
- **Configurazione del box:** `lantrap openwrt <trappola>` stampa lo script per il box OpenWrt: regola del firewall, log remoto, NTP, segnale di vita e WireGuard.

## Avvio rapido

```bash
git clone https://github.com/catalani-dev/fritzbox-7490-openwrt.git && cd fritzbox-7490-openwrt/lan-trap-receiver
python3 -m lantrap init          # scrive lantrap.toml con le impostazioni predefinite
python3 -m lantrap               # menu interattivo
```

Su Windows basta un doppio clic su `lantrap.bat`, oppure lanciarlo da un prompt dei comandi; usa il launcher `py` oppure `python`. Con `pip install .` si installa anche il comando `lantrap`. Il menu parte in inglese. L'italiano si sceglie dalla voce **Language / Lingua**, che salva la scelta e vale anche per gli avvisi; al primo avvio il menu chiede subito la lingua, con l'inglese già selezionato. Per una sola volta si può usare anche `--lang it`.

### Il menu

Dal menu si cambia qualsiasi impostazione, e solo quelle che scegli:

- **Schede.** Ogni sezione elenca tutte le sue impostazioni con il valore attuale; quelle mai cambiate mostrano il valore predefinito. Scegli una riga e premi Invio per cambiarla:
  - le impostazioni sì/no si invertono subito;
  - scelte e filtri degli eventi aprono un elenco;
  - gli altri valori si scrivono;
  - `-` riporta un'impostazione al valore predefinito.

  **Salva** controlla tutta la configurazione e la scrive; **Annulla** o Esc lasciano tutto com'era.
- **Elenchi.** Ascolti, canali di avviso, formati dello storico, clienti e trappole sono elenchi. Aggiungi tutte le voci che servono, anche più canali dello stesso tipo, poi modifica o rimuovi ciascuna. Dalla pagina di un canale si può anche mandare un avviso di prova.
- **Segreti** (password SMTP, URL dei webhook, segreto HMAC): si possono indicare come nome di una variabile d'ambiente, percorso di un file o valore scritto direttamente.
- **Sezioni:** Generali, Ascolto, Canali di avviso, Storico, Raggruppamento, Segnale di vita, Configurazione dei box OpenWrt, Tunnel WireGuard. Sotto Clienti ci sono anche:
  - i clienti con le loro trappole ed eccezioni;
  - tutte le trappole;
  - le eccezioni per tutti i clienti;
  - le nuove trappole da mittenti non ancora configurati.

Primi passi tipici:

1. **Impostazioni → Canali di avviso → + Aggiungi**: scegli il tipo e compila quello che ti serve.
2. **Clienti, trappole ed eccezioni → + Aggiungi** un cliente. Poi aprilo e scegli **Trappole di questo cliente → + Aggiungi**, con l'indirizzo da cui la trappola manda i log.
3. **Invia un avviso di prova.**
4. **Avvia il ricevitore**, e da una seconda finestra **Simula una trappola** per vedere un avviso completo.

Per provarlo senza un box: `python3 -m lantrap simulate --port 5514` manda le 25 righe di una scansione di cinque porte da un client Windows. Sono cinque righe per porta, perché Windows ritenta la connessione rifiutata.

## Configurazione

C'è un solo file, TOML (`lantrap.toml`) o JSON (`lantrap.json`). Il programma lo cerca in quest'ordine:
1. `--config`;
2. la variabile `LANTRAP_CONFIG`;
3. `./lantrap.toml` e `./lantrap.json`;
4. `/etc/lantrap/lantrap.toml`.

[`config.example.toml`](config.example.toml) descrive ogni impostazione. Il menu modifica lo stesso file e lo controlla prima di salvare.

| Sezione | Contenuto |
|---|---|
| primo livello | `language`, `prefixes` (prefissi di log accettati), `unknown_sources` (`drop` o `accept`), `exclude` globale, `store_excluded`, `store_other` |
| `[grouping]` | `collect_seconds` (60), `quiet_minutes` (15), `retry_seconds` (5), `reminder_minutes` (60), `scan_ports` (3), `notify_on_close`, `max_alerts_per_hour` (30) |
| `[heartbeat]` | `enabled`, `missing_minutes` (30) |
| `[[listen]]` | `protocol` (`udp`, `tcp`, `tls`), `address`, `port`, `allow`; per TLS `certfile`, `keyfile` e, se serve, `cafile` |
| `[[store]]` | `type` (`sqlite`, `jsonl`, `csv`), `path` o `directory`, `retention_days` |
| `[[notify]]` | `type` (`smtp`, `google_chat`, `webhook`, `command`), `name`, `events`, `clients`, `language`, `enabled` e le opzioni del canale |
| `[[client]]` | `id`, `name`, `exclude` |
| `[[trap]]` | `id`, `name`, `client`, `source` (indirizzi o reti), `hostname`, `exclude`, `heartbeat`, `tunnel_ip` |
| `[openwrt]`, `[wireguard]` | valori usati per scrivere lo script del box |

I percorsi relativi partono dalla cartella del file di configurazione. Un segreto si può indicare in tre modi:
- scritto nel file: `password`, `url`, `secret`;
- letto da una variabile d'ambiente: `password_env`, `url_env`, `secret_env`;
- letto da un file: `password_file`, `url_file`, `secret_file`.

Il file di configurazione deve essere leggibile solo dall'account che fa girare il ricevitore.

Il ricevitore ricontrolla il file ogni pochi secondi, e su Linux anche con `SIGHUP`. Un file con errori viene rifiutato e resta in uso la configurazione precedente. Le modifiche ad ascolti e storico richiedono un riavvio.

## Raggruppamento

| Termine | Significato |
|---|---|
| riga | un messaggio di log della trappola |
| tentativo | le righe con la stessa origine, la stessa trappola e la stessa porta, a meno di `retry_seconds` l'una dall'altra; per esempio un client Windows che ritenta più volte un SYN rifiutato |
| incidente | i tentativi da un indirizzo di origine verso una trappola, finché non passano `quiet_minutes` senza righe |
| scansione di porte | un incidente che ha toccato almeno `scan_ports` porte diverse; altrimenti è un tentativo di connessione |

Il primo avviso di un incidente parte dopo `collect_seconds`, così una scansione veloce arriva completa in un solo messaggio. Se l'incidente continua, ogni `reminder_minutes` parte un promemoria, purché ci sia attività nuova. `max_alerts_per_hour` è un tetto per cliente. Oltre il tetto gli avvisi di incidente aspettano un posto libero e partono più tardi, senza perdersi, e ogni avviso dice quanti altri dello stesso cliente sono in attesa. Quando il ricevitore si ferma, i primi avvisi ancora nella finestra di raccolta partono prima dell'uscita.

## Avvisi

Esempio (e-mail, italiano):

```
Subject: [LAN Trap] [Esempio Srl] Scansione di porte da 192.168.1.2

Cliente:      Esempio Srl
Trappola:     Sede principale (example-hq)
Origine:      192.168.1.2 (MAC 00:11:22:33:44:55)
Destinazione: 192.168.1.1
Tipo:         scansione di porte (5 porte)
Porte:        21/tcp FTP, 23/tcp Telnet, 445/tcp SMB, 3389/tcp RDP, 8080/tcp HTTP-alt
Tentativi:    5 (25 righe di log)
Primo:        2026-10-23 14:01:02
Ultimo:       2026-10-23 14:01:10
Stato:        in corso
Incidente:    20261023-140102-a1b2c3
```

Gli eventi sono `incident`, `incident_update`, `incident_closed`, `trap_silent` e `trap_back`. A questi si aggiunge `test`, dal menu o con `lantrap test-alert`.

Webhook e comandi ricevono un documento JSON con lo schema `lantrap.alert/1`; la struttura completa è nel [README in inglese](README.md#alerts).
- Con `secret`, la richiesta del webhook porta l'intestazione `X-Lantrap-Signature: sha256=<HMAC-SHA256 del corpo>`.
- Ogni richiesta porta `X-Lantrap-Event: <tipo>`.
- Un canale `command` riceve lo stesso JSON sullo standard input, più le variabili `LANTRAP_EVENT` e `LANTRAP_ALERT_ID`. Un codice di uscita diverso da 0 conta come errore. È il punto in cui collegare un sistema di ticket.

Ogni canale viene provato tre volte. Se fallisce ancora, l'avviso viene ritentato dopo 1, 5, 15, 30, 60, 120 e 240 minuti; i tentativi restano in memoria, quindi un riavvio li perde. L'esito di ogni invio finisce nello storico.

## Configurare una trappola (OpenWrt)

```bash
python3 -m lantrap openwrt example-hq -o lantrap-example-hq.sh
scp -O lantrap-example-hq.sh root@192.168.1.1:/tmp/ && ssh root@192.168.1.1 sh /tmp/lantrap-example-hq.sh
```

Lo script si può rilanciare dopo ogni modifica e fa queste cose:

1. Se sono impostati `[wireguard]` e `tunnel_ip`, installa WireGuard (con `apk` da OpenWrt 25.12, con `opkg` nelle versioni precedenti), crea una chiave sul box, configura il tunnel verso il ricevitore e stampa il blocco `[Peer]` da aggiungere al ricevitore.
2. Scrive `/etc/nftables.d/10-lantrap.nft` ([esempio](openwrt/10-lantrap.nft)) con le porte, il limite di righe e gli indirizzi IPv4 esclusi (anche IPv6, con `ipv6 = true`). Poi esegue `fw4 check`. Se il controllo fallisce, rimette il file precedente e si ferma senza ricaricare il firewall; altrimenti esegue `fw4 reload`.
3. Imposta `log_ip`, `log_port`, `log_proto` e `log_hostname` in `/etc/config/system` e riavvia il servizio dei log.
4. Attiva NTP. Senza un orologio corretto, gli orari scritti dal box sono sbagliati. Il ricevitore raggruppa con il proprio orologio e segnala le trappole con l'ora sballata.
5. Aggiunge al cron `logger -t lantrap heartbeat` ogni 10 minuti, per il segnale di vita.

Note:
- L'indirizzo della trappola non deve servire a nient'altro, e sulle porte registrate non deve girare nessun servizio: il box rifiuta la connessione dopo averla registrata.
- Il limite sul box (60 righe al minuto) protegge box e ricevitore dalle raffiche. Conviene escludere gli scanner noti anche sul box, oltre che nel ricevitore, così il loro traffico non consuma il limite.
- Le eccezioni per MAC le applica solo il ricevitore.

Dal lato del ricevitore, WireGuard è una normale interfaccia `wg-quick`: vedi [`deploy/wg0.conf.example`](deploy/wg0.conf.example). Sono le trappole a collegarsi al ricevitore, quindi nelle sedi dei clienti non va aperto niente.

## Tenerlo acceso

- **Linux (systemd):** usa [`deploy/lantrap.service`](deploy/lantrap.service), oppure `lantrap service systemd` per un'unità con i percorsi dell'installazione corrente. Le porte sotto 1024 richiedono `CAP_NET_BIND_SERVICE`; la porta predefinita è la 5514.
- **Windows:** `lantrap service windows --write` scrive un file di avvio accanto alla configurazione. Stampa anche i comandi `schtasks` e quelli del firewall per un'attività che parte all'avvio come SYSTEM. Python va installato per tutti gli utenti, perché SYSTEM possa eseguirlo. Programma, configurazione e file di avvio vanno tenuti in cartelle che solo gli amministratori possono modificare (per esempio `C:\Program Files` e `C:\ProgramData`), mai nel profilo di un utente.
- **Docker:** usa [`deploy/Dockerfile`](deploy/Dockerfile) e [`deploy/compose.yaml`](deploy/compose.yaml). La rete dell'host conserva gli indirizzi reali dei mittenti.

## Riga di comando

```
lantrap [-c CONFIG] [--lang en|it] [-v] [--log-file FILE] [comando]

  menu         menu interattivo (predefinito)
  run          avvia il ricevitore in primo piano
  init         crea un file di configurazione con le impostazioni predefinite
  check        controlla la configurazione e i canali di avviso
  status       trappole con l'ultimo messaggio, mittenti sconosciuti, ultimi incidenti
  incidents    ultimi incidenti (--json)
  test-alert   manda un avviso di prova (--channel NOME, ripetibile)
  simulate     manda finte righe di trappola a un ricevitore avviato
  import FILE  analizza offline righe di log salvate (--trap ID, --save)
  openwrt ID   stampa lo script di configurazione di un box
  service      come tenerlo acceso: systemd, windows, docker
```

Codici di uscita: 0 riuscito, 1 errore, 2 errore di configurazione.

## Sicurezza

- Fai girare il ricevitore con un utente senza privilegi. Esponi le porte syslog solo sull'interfaccia del tunnel o di gestione, con `address`, `allow` e il firewall dell'host.
- Il syslog in UDP o TCP non è né autenticato né cifrato: attraverso reti non fidate usa WireGuard o TLS. Dentro WireGuard l'indirizzo del mittente è legato alla chiave del peer, ed è questo che lo rende un'identità affidabile per la trappola. L'hostname di un messaggio lo può scrivere chiunque, quindi è solo un controllo in più.
- I segreti possono restare fuori dal file di configurazione, nelle variabili d'ambiente o in file a parte.
- Nei CSV, le celle che iniziano con `=`, `+`, `-` o `@` ricevono un apice davanti, così un foglio di calcolo non le esegue come formule.
- I frame sono limitati a 64 KiB.
- Le connessioni TCP sono al massimo 512 in tutto e 16 per mittente, e si chiudono dopo 30 minuti senza dati.
- Un incidente tiene al massimo 1024 porte, 64 destinazioni e 16 indirizzi MAC, e il ricevitore ricorda al massimo 1024 mittenti sconosciuti.
- Il limite sul box contiene il traffico di una singola trappola.
- Hostname e tag ricevuti dalla rete si tengono solo se sono ASCII stampabile, così non possono iniettare sequenze di escape nei log o nel menu.
- I prefissi di log e i nomi scritti nello script del box vengono controllati, così non possono rompere il file nft o lo script di shell.

## Limiti

- Gli incidenti vivono in memoria. Dopo un riavvio, quelli rimasti aperti vengono chiusi nello storico, e la nuova attività apre un nuovo incidente.
- Anche i nuovi tentativi di consegna vivono in memoria: un avviso che fallisce ancora quando il ricevitore si ferma resta registrato come non inviato e non viene più ritentato.
- Con `unknown_sources = "accept"` ogni nuovo indirizzo mittente diventa una trappola: usalo solo dietro un tunnel o con un elenco `allow`.
- Un box OpenWrt manda i log a una sola destinazione remota: è un limite di `logd`. Per un secondo ricevitore serve rsyslog o syslog-ng sul box.
- Il ricevitore non controlla che una trappola sia raggiungibile: il segnale di vita si accorge solo che i suoi messaggi si sono fermati.

## Sviluppo

```bash
python3 -m unittest discover -s tests
```

I test coprono:
- il parsing di righe reali di OpenWrt;
- raggruppamento, eccezioni e segnale di vita;
- tutti i canali di avviso, verso server SMTP e HTTP locali finti;
- i formati dello storico e il menu;
- una prova completa su socket UDP e TCP veri.

## Licenza

[MIT](../LICENSE)
