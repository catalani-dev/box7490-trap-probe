# OpenWrt-7490.bat

[English](README.md) · **Italiano**

Un solo file per Windows che fa girare OpenWrt su un **AVM FRITZ!Box 7490**: prima solo in RAM, poi, se lo si vuole, installato sulla flash. Trasforma anche il box in una **trappola di rete** o in una **sonda di monitoraggio**.

Fa parte di [fritzbox-7490-openwrt](../README.it.md). La trappola funziona con il [LAN Trap Receiver](../lan-trap-receiver/README.it.md).

> [!WARNING]
> Installare OpenWrt **sostituisce FRITZ!OS**. Il 7490 perde Wi-Fi, DECT, telefonia, app e aggiornamenti di AVM. L'installazione sulla flash non è ancora stata provata con questo strumento: leggi prima [Stato](#stato).

## Cosa fa

| Voce del menu | Cosa succede |
|---|---|
| **Avvia in RAM** | Scarica l'immagine initramfs ufficiale, la verifica e la carica in RAM tramite il bootloader di AVM (EVA). La flash non viene scritta: spegnendo il box torna FRITZ!OS. |
| **Installa sulla flash** | Sostituisce FRITZ!OS con OpenWrt (`sysupgrade -n`). Prima controlla la variante del NAND e il log del kernel; sui NAND Micron chiede di scrivere che si accetta il rischio. |
| **Configura come trappola** | Il box diventa un client della LAN e registra ogni tentativo di collegarsi a porte come SMB, RDP, Telnet o i database. |
| **Configura come sonda** | Il box diventa un client della LAN con un tunnel WireGuard di gestione, un agente Zabbix o Prometheus, iperf3, tcpdump e mtr. |
| **Stato del box** | Versione, NAND, indirizzo, ora, trappola, tunnel e agenti del box. |
| **Strumenti** | Console SSH, LuCI nel browser, salvataggio di dmesg e log (senza chiavi né password), riavvio. |
| **Rete del PC** | Imposta gli indirizzi di lavoro sulla scheda collegata al box, oppure rimette la configurazione di prima. |
| **Impostazioni** | Indirizzo del box, versione di OpenWrt, scheda di rete, cartella del programma. |

## Requisiti

- Windows 10 o 11 con Windows PowerShell 5.1 (già incluso) e il client OpenSSH (Impostazioni > App > Funzionalità facoltative).
- Un account amministratore, perché lo strumento imposta gli indirizzi IP della scheda di rete. L'elevazione la chiede da solo.
- Un cavo dal PC a una porta LAN del FRITZ!Box e internet sul PC da un'altra scheda, per esempio il Wi-Fi.

## Download e controlli

| File | Provenienza | Controllo |
|---|---|---|
| Immagini OpenWrt (initramfs, sysupgrade) | downloads.openwrt.org | SHA256 confrontato con il file `sha256sums` ufficiale della stessa versione |
| Immagini con pacchetti aggiunti (trappola, sonda) | servizio ufficiale di build sysupgrade.openwrt.org | SHA256 restituito dal servizio; l'elenco dei pacchetti viene confrontato con il manifest della build |
| `eva_ramboot.py` | repository di OpenWrt, commit fissato | SHA256 fisso |
| Python embeddable (esegue `eva_ramboot.py`, non installa niente) | python.org | SHA256 fisso e firma Authenticode della Python Software Foundation |

File creati accanto allo script:
- `cache\`: i file scaricati;
- `stato\`: impostazioni, ultime risposte, configurazione salvata della scheda;
- `log\`: trascrizioni delle sessioni e output di ogni configurazione, compreso il blocco `[Peer]` di WireGuard.

Lo strumento usa una sua chiave SSH, `%USERPROFILE%\.ssh\openwrt-7490_ed25519`, e la installa sul box quando lo configura.

## Passo per passo

1. **Scopri chi ha prodotto il NAND.** In FRITZ!OS apri `http://192.168.178.1/support.lua`, salva i dati di assistenza (ci vogliono un paio di minuti) e cerca `NAND device`.
   - Manufacturer ID `0x2c` è Micron e vuole le immagini `-micron`.
   - `0x98` (Toshiba), `0xad` (Hynix), `0xec` (Samsung) e `0xc2` (Macronix) usano quelle standard.
   - Nello stesso file c'è `HWRevision` (185 = 7490).
2. **Avvia in RAM.**
   - Scegli la variante del NAND e lascia che lo strumento imposti gli indirizzi di lavoro sulla scheda.
   - Spegni il FRITZ!Box, aspetta 5 secondi e riaccendilo. EVA accetta il caricamento solo per pochi secondi dopo l'accensione: lo strumento lo aspetta.
   - Dopo 1-2 minuti OpenWrt risponde su `192.168.1.1`: SSH come `root` senza password, LuCI con le stesse credenziali.
3. **Controlla il log del kernel**, che lo strumento mostra.
   - Su un box sano, con FRITZ!OS ancora nella flash, si vedono `nand: device found, Manufacturer ID: …` e `UBI error: no valid UBI magic found inside mtd1`.
   - La riga di UBI è normale: FRITZ!OS non usa UBI, quindi OpenWrt non collega la partizione e non scrive niente.
   - Righe con `Bad eraseblock`, errori ECC, bitflip o altri errori UBI sono un motivo per fermarsi, e in quel caso lo strumento rifiuta l'installazione.
4. **Prova un profilo in RAM**, se vuoi. Le impostazioni si perdono quando il box si spegne.
5. **Installa sulla flash** con l'immagine adatta al NAND.
   - Lo strumento copia l'immagine nel box, ne confronta lo SHA256, esegue `sysupgrade -T` e chiede di scrivere `INSTALLA` prima di `sysupgrade -n`.
   - Poi configura di nuovo la trappola o la sonda: il sistema installato parte dalle impostazioni predefinite.

### Perché il PC usa indirizzi fissi senza gateway

Sul cavo lo strumento imposta `192.168.178.2/24` (per EVA, che non ha DHCP) e `192.168.1.2/24` (per OpenWrt), **senza gateway**. Un FRITZ!Box senza linea DSL risponde a ogni richiesta DNS con il proprio indirizzo: un PC che lo usa come gateway perde internet e TLS.

La configurazione precedente della scheda viene salvata e si ripristina da **Rete del PC**, oppure all'uscita.

## Profili

La configurazione è semplice codice shell nella cartella [`profili/`](profili), che viene mandato al box via SSH insieme alle risposte date.

**Parte comune** ([`base-lan.sh`](profili/base-lan.sh)):
- nome del box, fuso orario Europe/Rome, NTP;
- indirizzo LAN dal DHCP del cliente oppure fisso, con gateway e DNS;
- WAN e DSL spente;
- server DHCP e annunci IPv6 spenti, così il box non disturba la LAN;
- firewall: dalla LAN passano solo SSH dagli indirizzi di gestione indicati, ping e risposte DHCP;
- SSH solo con chiave, una volta installata la chiave; sulla flash la password di root è obbligatoria;
- LuCI spento (sulla sonda può restare acceso, raggiungibile solo dal tunnel).

**Trappola** ([`trappola.sh`](profili/trappola.sh)):
- Un file in `/etc/nftables.d/` aggiunge una catena con priorità più alta di quella di fw4 e politica `accept`, quindi si limita a registrare.
- Le nuove connessioni TCP verso le porte scelte vengono registrate con il prefisso `LANTRAP:`, con un limite di righe al minuto.
- Gli indirizzi del set di esclusione (per esempio i propri scanner) non vengono registrati. Il set si cambia a caldo con `nft add element inet fw4 lantrap_exclude { … }`.
- Su quelle porte non ascolta niente, quindi il box rifiuta comunque la connessione.
- Il log può andare a un ricevitore syslog, e un job del cron scrive un segnale di vita ogni 10 minuti.
- Se `fw4 check` rifiuta la regola, rimette il file precedente.

Al posto della trappola integrata si può usare lo script stampato da `lantrap openwrt <trappola>` sul ricevitore.

**Sonda** ([`sonda.sh`](profili/sonda.sh)):
- un'interfaccia WireGuard `mgmt` verso il proprio server, con una zona del firewall che accetta tutto dal tunnel;
- NAT dal tunnel verso la LAN, se lo si sceglie;
- l'agente Zabbix o il Prometheus node exporter, e il log remoto se lo si vuole;
- alla fine stampa il blocco `[Peer]` da aggiungere al server WireGuard.

I pacchetti devono essere già nell'immagine, cioè installata con la voce "Immagine per la sonda", oppure il box deve avere internet per installarli.

## Problemi noti

- **Avviato da PowerShell 7:** il lanciatore svuota `PSModulePath`. Altrimenti Windows PowerShell 5.1 eredita i percorsi dei moduli di PowerShell 7 e non trova `Get-FileHash` né `Get-AuthenticodeSignature`.
- **Una pagina di LuCI non si apre** (per esempio Stato > Firewall): alcuni antivirus con protezione dagli attacchi di rete bloccano le richieste di LuCI a `/cgi-bin/cgi-exec` che eseguono comandi.
- **Orari dei log nel 1970:** il box non raggiunge nessun server NTP. Imposta un gateway oppure un server NTP nella LAN.
- **Il box non si raggiunge dopo averlo configurato in RAM con il DHCP:** sul banco non c'è un server DHCP e il box resta senza indirizzo. Spegnilo e riavvialo in RAM.

## Stato

| Parte | Verificato | Non ancora verificato |
|---|---|---|
| OpenWrt 25.12.6 in RAM su un 7490 con NAND Micron (HWRevision 185, FRITZ!OS 7.62), con il `eva_ramboot.py` ufficiale | Su hardware vero: avvio, SSH, LuCI, dmesg | |
| Regola della trappola | In RAM, su hardware vero: 5 righe di log per tentativo (Windows ritenta il SYN rifiutato), set di esclusione cambiato a caldo | |
| Installazione sulla flash e ritorno a FRITZ!OS | | Non provati. Di solito si torna indietro con il programma di ripristino AVM del modello, che passa da EVA |
| DSL | Firmware e driver si caricano | Una linea vera; per le linee italiane serve probabilmente l'annex A al posto dell'annex B predefinito |

È supportato solo il FRITZ!Box 7490. Gli altri FRITZ!Box supportati da OpenWrt hanno procedure diverse (per esempio il 7520 e il 7530 richiedono U-Boot scritto nella flash).

## Licenza

[MIT](../LICENSE)
