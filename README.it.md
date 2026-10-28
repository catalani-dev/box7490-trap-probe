# FRITZ!Box 7490 + OpenWrt

[English](README.md) · **Italiano**

Una seconda vita per i FRITZ!Box 7490 di AVM: ci si installa OpenWrt e li si trasforma in **trappole di rete**, che segnalano chi esplora la rete, oppure in **sonde di monitoraggio** raggiungibili via WireGuard. Il repository contiene anche il ricevitore syslog che raccoglie i log delle trappole, li raggruppa in incidenti e manda gli avvisi.

| Cartella | Cos'è | Dove gira |
|---|---|---|
| [`openwrt-7490/`](openwrt-7490/README.it.md) | `OpenWrt-7490.bat`: strumento a menu che avvia OpenWrt in RAM, lo installa sulla flash e configura il box come trappola o come sonda | Windows 10/11 |
| [`lan-trap-receiver/`](lan-trap-receiver/README.it.md) | LAN Trap Receiver: ricevitore syslog sempre acceso che raggruppa le righe delle trappole in incidenti e manda un solo avviso via email, Google Chat, webhook o comando | Linux, Windows o Docker, Python 3.11+, senza dipendenze |

## Come si collegano le parti

```
 PC Windows                    FRITZ!Box 7490 con OpenWrt                ricevitore
 ┌──────────────────────┐      ┌─────────────────────────────────┐      ┌──────────────────────────┐
 │ OpenWrt-7490.bat     │ ───► │ trappola: registra le nuove     │ ───► │ lantrap: quale trappola, │
 │ 1. OpenWrt in RAM    │ cavo │ connessioni TCP a porte inutili │syslog│ eccezioni, un incidente  │
 │ 2. installa su flash │      │ (SMB, RDP, …)                   │ (UDP,│ per scansione, avvisi,   │
 │ 3. profilo trappola  │      │ sonda: WireGuard, Zabbix o      │ TCP, │ storico                  │
 │    o sonda           │      │ Prometheus, iperf3, tcpdump, mtr│ TLS) │                          │
 └──────────────────────┘      └─────────────────────────────────┘      └──────────────────────────┘
```

Una trappola è utile perché nessuno ha motivo di collegarsi a SMB, RDP o a un database su un box che non offre niente di tutto questo: ogni tentativo è una scansione, un worm o qualcuno che si muove nella rete. Vede anche i dispositivi dove non si può installare un agente, come stampanti, telecamere e i portatili degli ospiti.

## Avvio rapido

**Strumento per Windows:**
- Scarica il repository (Code > Download ZIP), estrailo e avvia `openwrt-7490\OpenWrt-7490.bat`.
- La cartella `profili` deve restare accanto allo script.
- I passi sono in [openwrt-7490/README.it.md](openwrt-7490/README.it.md).

**Ricevitore:**

```bash
git clone https://github.com/catalani-dev/fritzbox-7490-openwrt.git
cd fritzbox-7490-openwrt/lan-trap-receiver
python3 -m lantrap init     # scrive lantrap.toml
python3 -m lantrap          # menu interattivo, in inglese o in italiano
```

I dettagli sono in [lan-trap-receiver/README.it.md](lan-trap-receiver/README.it.md).

## Stato

Versione 0.1.0, la prima pubblica.

| Parte | Verificato | Non ancora verificato |
|---|---|---|
| OpenWrt 25.12.6 in RAM su un 7490 con NAND Micron | A mano su hardware vero: avvio tramite EVA, SSH, LuCI, dmesg | |
| Regola della trappola | A mano, in RAM, su hardware vero | Installazione permanente |
| `OpenWrt-7490.bat` e i suoi profili | Parser, moduli con risposte simulate, script eseguiti in un OpenWrt simulato | Un'esecuzione completa su hardware vero; installazione sulla flash |
| LAN Trap Receiver | 111 test automatici (uno viene saltato su Windows), compresa una prova su socket UDP e TCP veri | Con un box vero |

## Sicurezza

- Installare OpenWrt sostituisce FRITZ!OS: si perdono Wi-Fi, DECT, telefonia e aggiornamenti di AVM.
- L'installazione sulla flash non è ancora stata provata con questo strumento. Sui box con NAND Micron sono stati segnalati problemi con alcune versioni di OpenWrt: la prima installazione va fatta su un box senza NAND Micron.
- È supportato solo il FRITZ!Box 7490.
- Usa trappole e sonde solo su reti di cui sei responsabile.
- Il software è fornito senza alcuna garanzia: vedi la licenza.

## Licenza

[MIT](LICENSE)
