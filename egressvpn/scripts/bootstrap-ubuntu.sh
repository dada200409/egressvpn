#!/usr/bin/env bash
# Bootstrap server A (Ubuntu) for egressvpn: dependencies, a CA + server
# certificate, a starter config table, then render and install the result.
#
# Run it ON A as root. It stops before touching routing or the firewall and asks
# first, because apply.sh changes a live host.
set -euo pipefail

PUBLIC=${1:?usage: bootstrap-ubuntu.sh <public-ip-or-hostname> <vpn-username>}
VPN_USER=${2:?usage: bootstrap-ubuntu.sh <public-ip-or-hostname> <vpn-username>}
POOL=10.90.1.0/24
CONF=/etc/egressvpn/egress.yaml
CA_DIR=/etc/egressvpn/ca

command -v egressvpn >/dev/null || { echo "install the binary first: install -m0755 egressvpn /usr/local/bin/" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

apt-get update -qq
apt-get install -y -qq strongswan strongswan-swanctl libcharon-extauth-plugins wireguard-tools nftables iproute2

# the EAP plugin is the single most commonly missing piece, and its absence looks
# like a client problem rather than a server one
if [ ! -e /usr/lib/ipsec/plugins/libstrongswan-eap-mschapv2.so ]; then
	echo "eap-mschapv2 plugin missing; on older Ubuntu try: apt install libcharon-extra-plugins" >&2
	exit 1
fi

umask 077
mkdir -p "$CA_DIR" /etc/egressvpn/users /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private \
	/etc/swanctl/conf.d /etc/nftables.d

# CA + leaf. A public hostname can be served by a real CA, but a bare IP has to be
# pinned by shipping this CA inside the profile, which is what the client wants.
if [ -f "$CA_DIR/ca.pem" ]; then
	echo "keeping the existing CA at $CA_DIR/ca.pem"
else
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CA_DIR/ca-key.pem" -out "$CA_DIR/ca.pem" \
		-days 825 -subj "/CN=EgressVPN Root CA"
fi

case $PUBLIC in
*.*.*.*) SAN="IP:$PUBLIC" ;;
*:*) SAN="IP:$PUBLIC" ;; # IPv6 literal
*) SAN="DNS:$PUBLIC" ;;
esac

openssl req -newkey rsa:2048 -nodes -keyout "/etc/swanctl/private/$PUBLIC-key.pem" -out /tmp/egress.csr \
	-subj "/CN=$PUBLIC"
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
	"$SAN" >/tmp/egress-san.cnf
openssl x509 -req -in /tmp/egress.csr -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca-key.pem" \
	-days 825 -CAcreateserial -extfile /tmp/egress-san.cnf -out "/etc/swanctl/x509/$PUBLIC.pem"
rm -f /tmp/egress.csr /tmp/egress-san.cnf

IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1); exit}')
[ -n "$IF" ] || { echo "cannot work out the outgoing interface" >&2; exit 1; }

PASS=$(openssl rand -base64 15)
printf '%s\n' "$PASS" >"/etc/egressvpn/users/$VPN_USER"
chmod 600 "/etc/egressvpn/users/$VPN_USER"

cat >"$CONF" <<YAML
server:
  public-host: $PUBLIC
  cert-file: /etc/swanctl/x509/$PUBLIC.pem
  key-file: /etc/swanctl/private/$PUBLIC-key.pem
  ca-file: $CA_DIR/ca.pem
  dns:
    - 1.1.1.1
client:
  display-name: Corp VPN
  organization: Company
tuning:
  # macOS fixes its IKEv2 interface at 1280; the server device and the MSS
  # clamp (default: tunnel-mtu - 40) follow that, not the physical NIC.
  tunnel-mtu: 1280
faces:
  - name: local
    egress: local
    pool: $POOL
    out-interface: $IF
users:
  - name: $VPN_USER
    face: local
    password-ref: /etc/egressvpn/users/$VPN_USER
YAML

egressvpn validate -c "$CONF"
egressvpn render -c "$CONF" -o /etc/egressvpn/out

# install where apply.sh expects to find them
install -m600 /etc/egressvpn/out/egressvpn.conf /etc/swanctl/conf.d/egressvpn.conf
install -m644 /etc/egressvpn/out/charon-snippet.conf /etc/strongswan.d/egressvpn.conf
install -m644 /etc/egressvpn/out/egress.nft /etc/nftables.d/egress.nft
install -m644 /etc/egressvpn/out/sysctl.conf /etc/sysctl.d/99-egressvpn.conf
install -m755 /etc/egressvpn/out/routes.sh /usr/local/sbin/egressvpn-routes.sh
install -m644 /etc/egressvpn/out/egressvpn-routes.service /etc/systemd/system/egressvpn-routes.service
install -m644 /etc/egressvpn/out/egressvpn-routes.timer /etc/systemd/system/egressvpn-routes.timer
install -m755 /etc/egressvpn/out/apply.sh /usr/local/bin/egressvpn-apply.sh
install -m755 /etc/egressvpn/out/verify.sh /usr/local/bin/egressvpn-verify.sh

# Ubuntu has no strongswan.service; the starter unit is strongswan-starter.service
# (ipsec.service on older releases).
UNIT=
for unit in strongswan-starter ipsec strongswan; do
	if systemctl cat "$unit" >/dev/null 2>&1; then
		UNIT=$unit
		break
	fi
done
[ -n "$UNIT" ] || { echo "no strongswan systemd unit found" >&2; exit 1; }
systemctl enable "$UNIT" >/dev/null 2>&1 || true
# restart, not start: the charon we just installed config into may already be
# running, and plugin load options are only read at startup
systemctl restart "$UNIT"
echo "restarted $UNIT.service"

# Restarting the daemon does not read /etc/swanctl: the starter only launches
# charon, and on Ubuntu nothing calls --load-all for you. Skip this and the box
# comes up healthy with zero connections, refusing every client.
swanctl --load-all

# load_modular means a plugin needs charon.plugins.<name>.load = yes to be used,
# and the distro ships no snippet for eap-mschapv2. If our own snippet did not take
# effect the clients fail at IKE_AUTH, so check the running daemon rather than
# trusting that the file was included.
PID=$(pgrep -x charon | head -1)
[ -n "$PID" ] || { echo "charon is not running; check: journalctl -u $UNIT" >&2; exit 1; }
if grep -q libstrongswan-eap-mschapv2.so "/proc/$PID/maps"; then
	echo "eap-mschapv2 is loaded by charon (pid $PID)"
else
	echo "charon did NOT load eap-mschapv2 - is /etc/strongswan.d/egressvpn.conf included by /etc/strongswan.conf?" >&2
	exit 1
fi

echo
echo "rendered and installed. client profile: /etc/egressvpn/out/profiles/"
echo "password for $VPN_USER (shown once; also in /etc/egressvpn/users/$VPN_USER): $PASS"
echo
echo "review /etc/egressvpn/out/apply.sh, then run: egressvpn-apply.sh && egressvpn-verify.sh"
