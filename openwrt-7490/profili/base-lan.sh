# Common part: the box becomes a plain client of the customer LAN.
# Variables set by the tool: HOSTNAME_BOX LAN_MODE LAN_IP LAN_PREFIX LAN_GW LAN_DNS MGMT_IPS
#                            ROOT_PW SSH_PUBKEY (one key per line) KEEP_LUCI NTP_SERVERS
# Defines base_prepare (writes and commits the settings) and base_apply (makes them active).

say() { printf '>>> %s\n' "$*"; }

zone_of() {
	i=0
	while uci -q get "firewall.@zone[$i]" >/dev/null; do
		if [ "$(uci -q get "firewall.@zone[$i].name")" = "$1" ]; then
			echo "@zone[$i]"
			return 0
		fi
		i=$((i + 1))
	done
	return 1
}

base_prepare() {
	[ -f /etc/openwrt_release ] || { echo "Questo non è un sistema OpenWrt" >&2; return 1; }

	say "Nome del box: $HOSTNAME_BOX, fuso orario Europe/Rome, NTP attivo"
	uci set system.@system[0].hostname="$HOSTNAME_BOX"
	uci set system.@system[0].zonename='Europe/Rome'
	uci set system.@system[0].timezone='CET-1CEST,M3.5.0,M10.5.0/3'
	uci set system.ntp.enabled='1'
	if [ -n "$NTP_SERVERS" ]; then
		uci -q delete system.ntp.server
		for s in $NTP_SERVERS; do uci add_list system.ntp.server="$s"; done
	fi

	if [ -n "$ROOT_PW" ]; then
		say "Password di root impostata"
		printf '%s\n%s\n' "$ROOT_PW" "$ROOT_PW" | passwd root >/dev/null 2>&1 || { echo "Impossibile impostare la password di root" >&2; return 1; }
	fi
	if [ -n "$SSH_PUBKEY" ]; then
		say "Chiavi SSH aggiunte: da ora l'accesso SSH è solo con chiave"
		mkdir -p /etc/dropbear
		touch /etc/dropbear/authorized_keys
		printf '%s\n' "$SSH_PUBKEY" | while IFS= read -r k; do
			[ -n "$k" ] || continue
			grep -qxF "$k" /etc/dropbear/authorized_keys || echo "$k" >> /etc/dropbear/authorized_keys
		done
		chmod 600 /etc/dropbear/authorized_keys
		uci set dropbear.main.PasswordAuth='off'
		uci set dropbear.main.RootPasswordAuth='off'
	fi

	uci -q delete network.lan.ip6assign
	uci -q delete network.lan.netmask
	uci -q delete network.lan.gateway
	uci -q delete network.lan.dns
	if [ "$LAN_MODE" = dhcp ]; then
		say "LAN: indirizzo dal DHCP della rete del cliente"
		uci set network.lan.proto='dhcp'
		uci -q delete network.lan.ipaddr
	else
		say "LAN: indirizzo fisso $LAN_IP/$LAN_PREFIX"
		uci set network.lan.proto='static'
		uci set network.lan.ipaddr="$LAN_IP/$LAN_PREFIX"
		[ -n "$LAN_GW" ] && uci set network.lan.gateway="$LAN_GW"
		for d in $LAN_DNS; do uci add_list network.lan.dns="$d"; done
	fi
	say "WAN e DSL spente"
	uci set network.wan.disabled='1'
	uci set network.wan6.disabled='1'

	say "Server DHCP e annunci IPv6 spenti, DNS solo per il box stesso"
	uci set dhcp.lan.ignore='1'
	uci set dhcp.lan.dhcpv4='disabled'
	uci set dhcp.lan.dhcpv6='disabled'
	uci set dhcp.lan.ra='disabled'
	uci -q delete dhcp.@dnsmasq[0].interface
	uci add_list dhcp.@dnsmasq[0].interface='loopback'

	z=$(zone_of lan) || { echo "Zona lan del firewall non trovata" >&2; return 1; }
	say "Firewall: dalla LAN verso il box solo SSH dagli IP di gestione, ping e risposte DHCP"
	uci set "firewall.$z.input=REJECT"
	uci set "firewall.$z.forward=REJECT"
	uci -q delete firewall.box_lan_ssh
	if [ -n "$MGMT_IPS" ]; then
		uci set firewall.box_lan_ssh=rule
		uci set firewall.box_lan_ssh.name='SSH di gestione dalla LAN'
		uci set firewall.box_lan_ssh.src='lan'
		uci set firewall.box_lan_ssh.proto='tcp'
		uci set firewall.box_lan_ssh.dest_port='22'
		for ip in $MGMT_IPS; do uci add_list firewall.box_lan_ssh.src_ip="$ip"; done
		uci set firewall.box_lan_ssh.target='ACCEPT'
	fi
	uci -q delete firewall.box_lan_ping
	uci set firewall.box_lan_ping=rule
	uci set firewall.box_lan_ping.name='Ping dalla LAN'
	uci set firewall.box_lan_ping.src='lan'
	uci set firewall.box_lan_ping.proto='icmp'
	uci set firewall.box_lan_ping.icmp_type='echo-request'
	uci set firewall.box_lan_ping.family='ipv4'
	uci set firewall.box_lan_ping.target='ACCEPT'
	uci -q delete firewall.box_lan_dhcp
	uci set firewall.box_lan_dhcp=rule
	uci set firewall.box_lan_dhcp.name='Risposte DHCP sulla LAN'
	uci set firewall.box_lan_dhcp.src='lan'
	uci set firewall.box_lan_dhcp.proto='udp'
	uci set firewall.box_lan_dhcp.dest_port='68'
	uci set firewall.box_lan_dhcp.family='ipv4'
	uci set firewall.box_lan_dhcp.target='ACCEPT'

	if [ "$KEEP_LUCI" = 1 ]; then
		say "LuCI resta attivo, raggiungibile solo dove il firewall lo permette"
		/etc/init.d/uhttpd enable 2>/dev/null
	else
		say "LuCI spento"
		/etc/init.d/uhttpd disable 2>/dev/null
	fi
	/etc/init.d/odhcpd disable 2>/dev/null

	uci commit || { echo "Salvataggio della configurazione non riuscito" >&2; return 1; }
	say "Configurazione salvata"
}

base_apply() {
	rootfs=$(ubus call system board 2>/dev/null | jsonfilter -e '@.rootfs_type' 2>/dev/null)
	if [ "$rootfs" = initramfs ]; then
		say "Sistema in RAM: riavvio i servizi tra 3 secondi (spegnendo il box si perde tutto)"
		( trap '' HUP
		  sleep 3
		  /etc/init.d/odhcpd stop
		  [ "$KEEP_LUCI" = 1 ] || /etc/init.d/uhttpd stop
		  /etc/init.d/system reload
		  /etc/init.d/sysntpd restart
		  /etc/init.d/dnsmasq restart
		  /etc/init.d/dropbear restart
		  /etc/init.d/network reload
		  fw4 reload
		) </dev/null >/dev/null 2>&1 &
	else
		say "Riavvio del box tra 5 secondi per applicare tutto"
		( trap '' HUP; sleep 5; reboot ) </dev/null >/dev/null 2>&1 &
	fi
}
