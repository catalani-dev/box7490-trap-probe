# Probe: management tunnel (WireGuard), monitoring agent and diagnostic tools.
# Variables set by the tool: HOSTNAME_BOX WG_ENDPOINT_HOST WG_ENDPOINT_PORT WG_SERVER_PUBKEY WG_ADDRESS
#                            WG_ALLOWED WG_KEEPALIVE VPN_TO_LAN MONITOR ZABBIX_SERVER
#                            LOG_IP LOG_PORT LOG_PROTO INSTALL_ONLINE
# Defines profile_check and profile_apply.

probe_packages() {
	p="wireguard-tools kmod-wireguard iperf3 tcpdump mtr-nojson"
	case "$MONITOR" in
		zabbix) p="$p zabbix-agentd" ;;
		prometheus) p="$p prometheus-node-exporter-lua prometheus-node-exporter-lua-netstat" ;;
	esac
	echo "$p"
}

profile_check() {
	command -v apk >/dev/null 2>&1 || { echo "Serve OpenWrt 25.12 o successivo (gestore pacchetti apk)" >&2; return 1; }
	missing=''
	for p in $(probe_packages); do
		apk info -e "$p" >/dev/null 2>&1 || missing="$missing $p"
	done
	[ -z "$missing" ] && { say "Pacchetti della sonda già presenti"; return 0; }
	say "Pacchetti mancanti:$missing"
	if [ "$INSTALL_ONLINE" != 1 ]; then
		echo "Installa l'immagine con i pacchetti della sonda, oppure scegli l'installazione da internet." >&2
		return 1
	fi
	say "Installo i pacchetti dai repository ufficiali (serve internet sul box)"
	apk update && apk add $missing || {
		echo "Installazione non riuscita: il box non raggiunge i repository ufficiali." >&2
		return 1
	}
	return 0
}

profile_apply() {
	say "Tunnel WireGuard di gestione verso $WG_ENDPOINT_HOST:$WG_ENDPOINT_PORT"
	umask 077
	mkdir -p /etc/wireguard
	[ -s /etc/wireguard/mgmt.key ] || wg genkey > /etc/wireguard/mgmt.key
	uci -q delete network.mgmt
	uci set network.mgmt=interface
	uci set network.mgmt.proto='wireguard'
	uci set network.mgmt.private_key="$(cat /etc/wireguard/mgmt.key)"
	uci add_list network.mgmt.addresses="$WG_ADDRESS"
	uci -q delete network.mgmt_server
	uci set network.mgmt_server=wireguard_mgmt
	uci set network.mgmt_server.description='Server di gestione'
	uci set network.mgmt_server.public_key="$WG_SERVER_PUBKEY"
	uci set network.mgmt_server.endpoint_host="$WG_ENDPOINT_HOST"
	uci set network.mgmt_server.endpoint_port="$WG_ENDPOINT_PORT"
	uci set network.mgmt_server.persistent_keepalive="$WG_KEEPALIVE"
	uci set network.mgmt_server.route_allowed_ips='1'
	for n in $WG_ALLOWED; do uci add_list network.mgmt_server.allowed_ips="$n"; done
	uci commit network

	say "Zona firewall 'mgmt': dal tunnel verso il box tutto permesso"
	uci -q delete firewall.mgmt
	uci set firewall.mgmt=zone
	uci set firewall.mgmt.name='mgmt'
	uci add_list firewall.mgmt.network='mgmt'
	uci set firewall.mgmt.input='ACCEPT'
	uci set firewall.mgmt.output='ACCEPT'
	uci set firewall.mgmt.forward='REJECT'
	uci -q delete firewall.mgmt_lan
	z=$(zone_of lan)
	uci -q delete "firewall.$z.masq"
	uci -q delete "firewall.$z.masq_src"
	if [ "$VPN_TO_LAN" = 1 ]; then
		say "Accesso dal tunnel alla LAN del cliente: attivo, con NAT verso la LAN"
		uci set firewall.mgmt_lan=forwarding
		uci set firewall.mgmt_lan.src='mgmt'
		uci set firewall.mgmt_lan.dest='lan'
		uci set "firewall.$z.masq=1"
		for n in $WG_ALLOWED; do uci add_list "firewall.$z.masq_src=$n"; done
	else
		say "Accesso dal tunnel alla LAN del cliente: spento (solo il box è raggiungibile)"
	fi
	uci commit firewall

	case "$MONITOR" in
		zabbix)
			say "Agente Zabbix: server $ZABBIX_SERVER, nome host $HOSTNAME_BOX"
			f=/etc/zabbix_agentd.conf
			for kv in "Server=$ZABBIX_SERVER" "ServerActive=$ZABBIX_SERVER" "Hostname=$HOSTNAME_BOX"; do
				k=${kv%%=*}
				if grep -q "^$k=" "$f"; then sed -i "s|^$k=.*|$kv|" "$f"; else echo "$kv" >> "$f"; fi
			done
			uci set zabbix_agentd.general.enabled='1'
			uci commit zabbix_agentd
			/etc/init.d/zabbix_agentd enable
			/etc/init.d/zabbix_agentd restart
			/etc/init.d/prometheus-node-exporter-lua stop 2>/dev/null
			/etc/init.d/prometheus-node-exporter-lua disable 2>/dev/null
			;;
		prometheus)
			say "Prometheus node exporter sulla porta 9100 (raggiungibile solo dal tunnel)"
			uci set prometheus-node-exporter-lua.main.listen_interface='*'
			uci set prometheus-node-exporter-lua.main.listen_port='9100'
			uci commit prometheus-node-exporter-lua
			/etc/init.d/prometheus-node-exporter-lua enable
			/etc/init.d/prometheus-node-exporter-lua restart
			/etc/init.d/zabbix_agentd stop 2>/dev/null
			/etc/init.d/zabbix_agentd disable 2>/dev/null
			;;
		*)
			say "Nessun agente di monitoraggio"
			for s in zabbix_agentd prometheus-node-exporter-lua; do
				/etc/init.d/$s stop 2>/dev/null
				/etc/init.d/$s disable 2>/dev/null
			done
			;;
	esac

	if [ -n "$LOG_IP" ]; then
		say "Log inviato a $LOG_IP:$LOG_PORT ($LOG_PROTO)"
		uci set system.@system[0].log_ip="$LOG_IP"
		uci set system.@system[0].log_port="$LOG_PORT"
		uci set system.@system[0].log_proto="$LOG_PROTO"
		uci set system.@system[0].log_hostname="$HOSTNAME_BOX"
		uci commit system
	fi

	echo
	echo '=========================================================='
	echo " Da aggiungere alla configurazione WireGuard del server:"
	echo '=========================================================='
	echo '[Peer]'
	echo "# $HOSTNAME_BOX"
	echo "PublicKey = $(wg pubkey < /etc/wireguard/mgmt.key)"
	echo "AllowedIPs = ${WG_ADDRESS%/*}/32"
	echo '=========================================================='
	return 0
}
