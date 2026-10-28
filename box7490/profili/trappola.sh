# Built-in trap, used when there is no script from the LAN Trap Receiver.
# Same file, prefix and heartbeat as the receiver, so the box can be connected to it later.
# Variables set by the tool: TRAP_PORTS TRAP_EXCLUDE TRAP_RATE LOG_IP LOG_PORT LOG_PROTO HOSTNAME_BOX
# Defines profile_check and profile_apply.

NFT_FILE=/etc/nftables.d/10-lantrap.nft
NFT_BACKUP=/tmp/10-lantrap.nft.previous

profile_check() {
	command -v fw4 >/dev/null 2>&1 || { echo "fw4 non trovato: serve OpenWrt 22.03 o successivo" >&2; return 1; }
	return 0
}

profile_apply() {
	say "Regola trappola: porte TCP $TRAP_PORTS"
	ports=$(echo $TRAP_PORTS | sed 's/ /, /g')
	excl=$(echo $TRAP_EXCLUDE | sed 's/ /, /g')
	rm -f "$NFT_BACKUP" /etc/nftables.d/10-trappola.nft
	[ -f "$NFT_FILE" ] && cp "$NFT_FILE" "$NFT_BACKUP"
	{
		echo 'set lantrap_exclude {'
		echo '	type ipv4_addr'
		echo '	flags interval'
		echo '	auto-merge'
		[ -n "$excl" ] && echo "	elements = { $excl }"
		echo '}'
		echo ''
		echo 'chain lantrap {'
		echo '	type filter hook input priority filter - 1; policy accept;'
		echo "	iifname \"br-lan\" ip saddr != @lantrap_exclude tcp dport { $ports } ct state new limit rate $TRAP_RATE/minute burst 20 packets log prefix \"LANTRAP: \" level warn"
		echo '}'
	} > "$NFT_FILE"
	if ! fw4 check; then
		if [ -f "$NFT_BACKUP" ]; then mv "$NFT_BACKUP" "$NFT_FILE"; else rm -f "$NFT_FILE"; fi
		echo "fw4 ha rifiutato la regola: il firewall resta com'era" >&2
		return 1
	fi
	rm -f "$NFT_BACKUP"
	fw4 reload

	if [ -n "$LOG_IP" ]; then
		say "Log inviato a $LOG_IP:$LOG_PORT ($LOG_PROTO)"
		uci set system.@system[0].log_ip="$LOG_IP"
		uci set system.@system[0].log_port="$LOG_PORT"
		uci set system.@system[0].log_proto="$LOG_PROTO"
		uci set system.@system[0].log_hostname="$HOSTNAME_BOX"
	else
		say "Nessun ricevitore: le righe restano nel log del box (logread -e LANTRAP)"
		uci -q delete system.@system[0].log_ip
	fi
	uci commit system
	/etc/init.d/log restart

	say "Segnale di vita ogni 10 minuti (logger -t lantrap heartbeat)"
	touch /etc/crontabs/root
	sed -i '/logger -t lantrap heartbeat/d' /etc/crontabs/root
	echo '*/10 * * * * logger -t lantrap heartbeat' >> /etc/crontabs/root
	/etc/init.d/cron enable
	/etc/init.d/cron restart
	logger -t lantrap 'trap configured'
	return 0
}
