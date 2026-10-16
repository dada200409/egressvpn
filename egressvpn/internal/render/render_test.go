package render

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dada200409/egressvpn/internal/config"
	"github.com/dada200409/egressvpn/internal/wgkey"
)

func TestGenKeyRoundTrip(t *testing.T) {
	priv, pub, err := wgkey.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	again, err := wgkey.PublicKeyOf(priv)
	if err != nil {
		t.Fatal(err)
	}
	if again != pub {
		t.Errorf("public key derivation is not stable: %q vs %q", again, pub)
	}
	if err := wgkey.ValidatePeerPublicKey(pub); err != nil {
		t.Errorf("a freshly generated key should validate: %v", err)
	}
}

func TestPeerKeyValidation(t *testing.T) {
	cases := map[string]string{
		"low-order all-zero": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"low-order one":      "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"not base64":         "not-base64!",
		"wrong length":       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	for name, key := range cases {
		if err := wgkey.ValidatePeerPublicKey(key); err == nil {
			t.Errorf("%s should be rejected: a peer key like this yields a tunnel with no secrecy", name)
		}
	}
}

const yamlTemplate = `server:
  public-host: vpn.example.com
  cert-file: %[5]s
  key-file: /etc/swanctl/private/vpn.example.com-key.pem
  ca-file: %[4]s
  ca-common-name: Test Root CA
  dns:
    - 1.1.1.1
  lan:
    - 192.168.10.0/24
faces:
  - name: local
    egress: local
    pool: 10.90.1.0/24
    out-interface: eth0
  - name: via-b
    egress: relay
    pool: 10.90.2.0/24
    upstream: b
upstreams:
  - name: b
    interface: wgb
    endpoint: 203.0.113.20:51820
    local-ip: 10.91.0.2/32
    remote-ip: 10.91.0.1/32
    remote-public-key: %[1]s
    private-key-file: %[2]s
    psk-file: %[3]s
users:
  - name: alice
    face: local
    password: pw-alice
  - name: bob
    face: via-b
    password-ref: env:EGRESSVPN_TEST_PW
`

// setup writes A's private key plus the YAML into a temp dir and loads it, so the
// tests exercise the real parse-and-render pipeline instead of a hand-built struct.
func setup(t *testing.T) (*config.Config, string, string, string) {
	t.Helper()
	aPriv, aPub, err := wgkey.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, bPub, err := wgkey.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := wgkey.GenPSK()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "wgb.key")
	pskPath := filepath.Join(dir, "wgb.psk")
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "vpn.example.com.pem")
	if err := os.WriteFile(keyPath, []byte(aPriv+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pskPath, []byte(psk+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte(selfSignedCert(t, "Test Root CA")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte(selfSignedCert(t, "vpn.example.com")), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EGRESSVPN_TEST_PW", "pw-from-env")

	yamlPath := filepath.Join(dir, "egress.yaml")
	body := fmt.Sprintf(yamlTemplate, bPub, keyPath, pskPath, caPath, certPath)
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(yamlPath)
	if err != nil {
		t.Fatalf("fixture rejected: %v", err)
	}
	return c, aPriv, aPub, bPub
}

func mustRender(t *testing.T, c *config.Config) *Files {
	t.Helper()
	f, err := Render(c)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return f
}

func TestSwanctlPerUserConnectionAndPoolBinding(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)

	for _, want := range []string{
		"   alice {",                // one connection per identity
		"pools = local",             // alice lands in the local-egress pool
		"   bob {", "pools = via-b", // bob lands in the chained pool
		"auth = eap-mschapv2",
		"certs = vpn.example.com.pem", // file name in x509/, extension included
		"addrs = 10.90.2.0/24",
		"reauth_time =",
	} {
		if !strings.Contains(f.Swanctl, want) {
			t.Errorf("swanctl.conf missing %q", want)
		}
	}
	// charon's parser rejects these outright ("unknown option", "invalid
	// section"), so a whole config can silently fail to load over one of them.
	for _, bogus := range []string{"reauth = yes", "children<1>"} {
		if strings.Contains(f.Swanctl, bogus) {
			t.Errorf("swanctl.conf contains %q, which strongSwan 5.9 does not accept", bogus)
		}
	}
	// `local<1>` is the documented form (swanctl.conf calls it local<suffix>);
	// only children is a plain dictionary of named sections.
	for _, want := range []string{"local<1> {", "remote<1> {", "children {\n         alice-tunnel {"} {
		if !strings.Contains(f.Swanctl, want) {
			t.Errorf("swanctl.conf missing %q", want)
		}
	}
	// The peer is matched by its EAP identity, never by the IKE ID. Apple clients
	// put their own local IP in IDi unless a profile sets a local identifier, and a
	// pinned remote.id then rejects them with "no matching peer config found" before
	// the password is looked at. Verified against a live macOS client.
	if !strings.Contains(f.Swanctl, "id = %any") {
		t.Error("swanctl.conf must match the peer with id = %any; the EAP identity does the authenticating")
	}
	// Line-anchored: "eap_id = alice" ends with "id = alice", so a substring search
	// for the pinned form would fire on the EAP identity we deliberately set.
	for _, line := range strings.Split(f.Swanctl, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "id = alice" || trimmed == "id = bob" {
			t.Errorf("swanctl.conf pins the peer IKE ID (%q), which breaks clients that send their own address as IDi", trimmed)
		}
	}
}

func TestSwanctlDeclaresFullTunnelSelectors(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// Leaving the selectors out is NOT a full tunnel: they default to "dynamic",
	// which resolves to the tunnel endpoint address and the peer's virtual IP. A live
	// macOS client then negotiated 10.0.1.2/32 === 10.90.1.1/32, connected happily,
	// and sent nothing through the tunnel.
	for _, want := range []string{"local_ts = 0.0.0.0/0", "remote_ts = 0.0.0.0/0"} {
		if !strings.Contains(f.Swanctl, want) {
			t.Errorf("swanctl.conf missing %q; without it the tunnel is host-to-host and the client keeps its own default route", want)
		}
	}
	// Value form, not the word: the generated comment quotes "dynamic" to explain
	// why the selectors are written out, and a substring search would fire on that.
	for _, bogus := range []string{"= dynamic", "dynamic,"} {
		if strings.Contains(f.Swanctl, bogus) {
			t.Errorf("swanctl.conf uses the dynamic traffic selector default (%q), which yields a host-to-host tunnel", bogus)
		}
	}
}

func TestSecretsResolveFromInlineAndEnv(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	if !strings.Contains(f.Swanctl, `secret = "pw-alice"`) {
		t.Error("inline password missing")
	}
	if !strings.Contains(f.Swanctl, `secret = "pw-from-env"`) {
		t.Error("password-ref env resolution failed")
	}
}

func TestNftKillSwitchAndAnonymisation(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)

	for _, want := range []string{
		`ip saddr 10.90.2.0/24 oifname "wgb" accept`,
		`ip saddr 10.90.2.0/24 drop`, // no leak via A when wgb is down
		`ip saddr 10.90.1.0/24 oifname "eth0" masquerade`,
		"snat to 10.91.0.2", // B sees only A, never a client IP
	} {
		if !strings.Contains(f.Nft, want) {
			t.Errorf("egress.nft missing %q", want)
		}
	}
	// A host-wide forward policy drop would also govern traffic this tool knows
	// nothing about, so containment must come from the per-pool drops only.
	if strings.Contains(f.Nft, "policy drop") {
		t.Error("the forward chain must not default-drop traffic outside the client pools")
	}
	if strings.Contains(f.Nft, "\n    meta l4proto tcp tcp flags") {
		t.Error("the MSS clamp must be scoped to a pool, not every forwarded SYN on the host")
	}
}

// A dropped `table inet egressvpn {` opener once produced a file whose braces still
// balanced pair-by-pair but which nft could not parse at all. nft -c -f is the real
// check and apply.sh runs it, but this catches the shape locally instead of at
// deploy time on someone's live host.
func TestNftFileIsWrappedInItsOwnTable(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	nft := f.Nft
	if !strings.HasPrefix(strings.TrimSpace(nft), "#!/usr/sbin/nft -f") {
		t.Error("egress.nft must start with the nft shebang")
	}
	if !strings.Contains(nft, "table inet egressvpn {\n\n  chain forward {") {
		t.Error("egress.nft must open its table before the first chain")
	}
	// `nft -f` merges into a live table, so without this a re-render leaves the old
	// pool's accept rule behind. Order matters: the empty declaration makes the table
	// exist so the flush is valid on a fresh host, where `nft -c -f` would otherwise
	// fail on flushing a table that isn't there.
	pre := nft[:strings.Index(nft, "table inet egressvpn {\n")]
	if !strings.Contains(pre, "table inet egressvpn { }") || !strings.Contains(pre, "flush table inet egressvpn") {
		t.Error("egress.nft must declare then flush its table before the rules, or re-applying accumulates rules")
	}
	if strings.Index(nft, "flush table") > strings.Index(nft, "chain forward") {
		t.Error("the flush must come before any rules are declared")
	}
	body := nft[strings.Index(nft, "table inet"):]
	opens, closes := strings.Count(body, "{"), strings.Count(body, "}")
	if opens != closes {
		t.Errorf("egress.nft unbalanced: %d { vs %d }", opens, closes)
	}
	if strings.Count(body, "hook ") != 3 {
		t.Errorf("egress.nft has %d hooked chains, expected 3 (forward, postrouting, mssclamp)", strings.Count(body, "hook "))
	}
}

func TestNftMssClampPresent(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// Verified against nft 1.0.9 / kernel 6.8: the option is "maxseg" and the
	// writable member is "size". "tcp option mss clamp value" does not parse.
	//
	// The range match is the whole point: "size set N" alone rewrites the
	// advertised MSS upward too, and on the live box a 1340 clamp against a
	// macOS client whose ipsec0 is 1280 dropped every large segment.
	for _, want := range []string{
		"tcp option maxseg size 1241-65535 tcp option maxseg size set 1240",
		"ip daddr 10.90.1.0/24 meta l4proto tcp tcp flags & (syn | ack) == syn | ack",
	} {
		if !strings.Contains(f.Nft, want) {
			t.Errorf("nft ruleset is missing %q", want)
		}
	}
	if strings.Contains(f.Nft, "syn tcp option maxseg size set") {
		t.Error("unconditional MSS clamp: it raises the client's MSS above the tunnel MTU and black-holes bulk traffic")
	}
	if !strings.Contains(f.Nft, "ip saddr 10.90.1.0/24 meta l4proto tcp tcp flags & (syn | ack) == syn tcp option maxseg size") {
		t.Error("chained egress without MSS clamping produces the classic 'connects but stalls on TLS' failure")
	}
}

func TestApplySetsTunnelMtuOnXfrmDevices(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// The xfrmi is the IKE tunnel's server half (the client's own 1280 is what
	// limits the path); the WireGuard hop is a separate link with its own MTU.
	if !strings.Contains(f.Routes, "ip link set xvlocal mtu 1280 up") {
		t.Errorf("the reconciler must bring xvlocal up at the tunnel MTU, got:\n%s", f.Routes)
	}
	if !strings.Contains(f.Routes, "ip link set wgb mtu 1380 up") {
		t.Errorf("the reconciler must keep the WireGuard hop on tuning.mtu, got:\n%s", f.Routes)
	}
}

func TestWireGuardPeerBlockPublishesAsPubKey(t *testing.T) {
	c, aPriv, aPub, bPub := setup(t)
	f := mustRender(t, c)

	aSide := f.WireGuard["b"]
	if !strings.Contains(aSide, "PublicKey = "+bPub) {
		t.Error("A-side config must peer with B's public key from the XML")
	}
	// wg(8) takes inline base64 only; a path here fails at `wg setconf` time
	if !strings.Contains(aSide, "PrivateKey = "+aPriv) {
		t.Error("A-side config must inline the private key, not reference a file path")
	}
	if strings.Contains(aSide, "PrivateKey = /") {
		t.Error("private key rendered as a path")
	}
	if !strings.Contains(aSide, "0.0.0.0/0") {
		t.Error("AllowedIPs must cover default for policy routing to have effect")
	}
	// apply.sh loads this file with `wg setconf`, which only knows the wg(8) keys.
	// Address/MTU are wg-quick-only and abort the deploy with
	// "Line unrecognized: Address=..." - and running this file through wg-quick
	// instead would turn the peer's 0.0.0.0/0 into A's real default route.
	for _, forbidden := range []string{"Address =", "MTU ="} {
		if strings.Contains(aSide, forbidden) {
			t.Errorf("A-side conf carries wg-quick-only key %q; wg setconf would reject it", forbidden)
		}
	}
	// the block handed to B must carry A's derived key, proving the stale-key guard
	if !strings.Contains(f.PeerSnippets["b"], "PublicKey = "+aPub) {
		t.Error("B peer block must contain the public key derived from A's private key file")
	}
}

func TestVerifyCountsLiveForwardRules(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// A hand-inserted `ip saddr <pool> drop` above the accept ate every forwarded
	// packet on the live host and looked like nothing at all: tunnel up, no errors,
	// no internet. The count of pool rules in the kernel is how that drift shows up.
	// one accept + one lan accept + one drop per face
	for _, want := range []string{
		`live=$(nft list chain inet egressvpn forward 2>/dev/null | grep -c "saddr 10.90.1.0/24")`,
		`if [ "$live" -eq 3 ]; then`,
		`saddr 10.90.2.0/24`,
	} {
		if !strings.Contains(f.Verify, want) {
			t.Errorf("verify.sh missing %q", want)
		}
	}
}

func TestGeneratedShellParses(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// verify.sh had three checks joined onto one line by a literal "\n" written
	// inside a backtick string, and nothing noticed until a live deploy: the
	// generated text is shell, so each check has to be its own command.
	for name, body := range map[string]string{"verify.sh": f.Verify, "apply.sh": f.Apply} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v\n%s", name, err, out)
		}
		if name != "verify.sh" {
			continue
		}
		for _, atLineStart := range []string{
			"wg show wgb >/dev/null",
			"wg show wgb latest-handshakes",
			"ip rule show | grep -q \"lookup 100\"",
			"if ip -br link show xvlocal",
		} {
			if !strings.Contains(body, "\n"+atLineStart) {
				t.Errorf("%s: %q is not the start of a line - the previous check swallowed it", name, atLineStart)
			}
		}
	}
}

func TestSwanctlBindsEachFaceToItsOwnXfrmInterface(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// A forwarding gateway cannot run a full tunnel off the policy database: a
	// wildcard child there becomes "src 0.0.0.0/0 dst 0.0.0.0/0 dir out", which
	// re-encrypts this host's own forwarded packets back into the same tunnel. On
	// the live server that was "connected, no network" for the client plus no
	// internet for the host itself. if_id is the only way to scope the SA.
	for _, want := range []string{"if_id_in = 1", "if_id_out = 1", "if_id_in = 2", "if_id_out = 2"} {
		if !strings.Contains(f.Swanctl, want) {
			t.Errorf("swanctl.conf missing %q; without it the child installs a wildcard out policy", want)
		}
	}
	// The ids must be distinct per face, or both pools' tunnels share one device
	// and a relay user exits through the local face.
	alice := f.Swanctl[strings.Index(f.Swanctl, "   alice {"):strings.Index(f.Swanctl, "   bob {")]
	bob := f.Swanctl[strings.Index(f.Swanctl, "   bob {"):]
	if !strings.Contains(alice, "if_id_in = 1") || !strings.Contains(bob, "if_id_in = 2") {
		t.Error("a user's child must carry the if_id of their own face's XFRM interface")
	}
}

func TestCharonOverrideIsASingleMergedFile(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// One file, both kinds of key. /etc/strongswan.d/egressvpn.conf is included at
	// top level, so an operator who "just adds install_routes" by rewriting it
	// silently drops the plugin loads and every client comes back EAP/FAIL - a
	// real outage caused by a real edit. The render therefore carries both.
	for _, want := range []string{"install_routes = no", "eap-mschapv2 {", "load = yes", "error-notify {"} {
		if !strings.Contains(f.CharonSnippet, want) {
			t.Errorf("charon override missing %q", want)
		}
	}
	if strings.Count(f.CharonSnippet, "load = yes") < 3 {
		t.Error("charon override must keep every plugin load directive in the same file as install_routes")
	}
}

func TestApplyScriptCreatesXfrmInterfaces(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// The routing lives in the reconciler so that a re-apply and the self-heal
	// cannot disagree about what the deployment needs; apply.sh runs it.
	for _, want := range []string{
		"modprobe xfrm_interface",
		"ip link add name xvlocal type xfrm dev eth0 if_id 1",
		"ip link add name xvvia-b type xfrm dev eth0 if_id 2",
		// decrypted client packets arrive with iif = the xfrm device, and the
		// kernel only forwards if that *input* interface has forwarding on
		"net.ipv4.conf.xvlocal.forwarding=1",
		"net.ipv4.conf.xvlocal.accept_local=1",
		// the pool route is what steering reduces to: routing, not a wildcard
		"ip route replace 10.90.1.0/24 dev xvlocal",
		"ip route replace 10.90.2.0/24 dev xvvia-b",
	} {
		if !strings.Contains(f.Routes, want) {
			t.Errorf("egressvpn-routes.sh missing %q", want)
		}
	}
	if !strings.Contains(f.Apply, "sh /usr/local/sbin/egressvpn-routes.sh") {
		t.Error("apply.sh must run the route reconciler")
	}
	// The links have to exist before charon resolves a child's if_id.
	if strings.Index(f.Apply, "egressvpn-routes.sh") > strings.Index(f.Apply, "swanctl --load-all") {
		t.Error("apply.sh brings up the XFRM interfaces after loading the connections")
	}
	if !strings.Contains(f.Sysctl, "net.ipv4.conf.default.send_redirects = 0") {
		t.Error("sysctl must disable redirects for interfaces created after boot, not only for all")
	}
}

// A route that names an interface is pruned when that interface flaps, and the
// pruning is silent: the client still authenticates, the ruleset still accepts, and
// every reply falls through to the default gateway. Measured on the live host -
// 10.90.1.0/24 dev xvlocal was gone for hours with a healthy CHILD_SA. So the
// deployment needs something that runs after the flap, and it has to stay quiet
// while nothing is wrong.
func TestRouteReconcilerHealsWithoutChurn(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	if !strings.Contains(f.Routes, `if ! ip -4 route get 10.90.1.1 2>/dev/null | grep -q "dev xvlocal"; then`) {
		t.Errorf("reconciler must ask the FIB whether a pool address is routable, got:\n%s", f.Routes)
	}
	for _, want := range []string{
		"systemctl enable egressvpn-routes.service egressvpn-routes.timer",
		"[ -x /usr/local/sbin/egressvpn-routes.sh ]",
	} {
		if !strings.Contains(f.Apply, want) {
			t.Errorf("apply.sh missing %q - the timer would not survive a reboot", want)
		}
	}
	for _, want := range []string{"/etc/systemd/system/egressvpn-routes.service", "/etc/systemd/system/egressvpn-routes.timer", "ExecStart=/usr/local/sbin/egressvpn-routes.sh", "WantedBy=timers.target", "OnUnitActiveSec="} {
		if !strings.Contains(f.RoutesUnit+f.RoutesTimer, want) {
			t.Errorf("route unit/timer missing %q", want)
		}
	}
	for _, want := range []string{"route reconciler installed", "egressvpn-routes.timer"} {
		if !strings.Contains(f.Verify, want) {
			t.Errorf("verify.sh must check the reconciler is installed and armed, missing %q", want)
		}
	}
}

// The probe address is what every repair decision keys off, so it has to be a real
// client address inside the pool - the network address itself is not routable by a
// pool route on every kernel, and a probe outside the pool reports the face broken
// while it is healthy.
func TestPoolProbeStaysInsideItsPool(t *testing.T) {
	for pool, want := range map[string]string{
		"10.90.1.0/24":  "10.90.1.1",
		"172.16.5.0/28": "172.16.5.1",
		"10.90.9.0/24":  "10.90.9.1",
	} {
		if got := poolProbe(pool); got != want {
			t.Errorf("poolProbe(%s) = %s, want %s", pool, got, want)
		}
	}
}

func TestApplyScriptWiresPolicyRouting(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	for _, want := range []string{
		"ip link add wgb type wireguard",
		"ip route replace default dev wgb table 100",
		"ip rule del priority 100 2>/dev/null || true",
		"ip rule add priority 100 from 10.90.2.0/24 lookup 100",
	} {
		if !strings.Contains(f.Routes, want) {
			t.Errorf("egressvpn-routes.sh missing %q", want)
		}
	}
	for _, want := range []string{
		"swanctl --load-all",
		"include /etc/swanctl/conf.d/*.conf",
		"pgrep -x charon",
		"strongswan-starter",
	} {
		if !strings.Contains(f.Apply, want) {
			t.Errorf("apply.sh missing %q", want)
		}
	}
	// Ubuntu/Debian have no strongswan.service, so a bare start of it always fails
	// and the deploy stops with a misleading "charon is not running".
	if strings.Contains(f.Apply, "start strongswan ") || strings.Contains(f.Apply, "quiet strongswan ") {
		t.Error("apply.sh must not name the non-existent strongswan.service")
	}
	// swanctl's -f means --flush-certs; there is no --file, so pointing it at our
	// own path would fail the deploy
	if strings.Contains(f.Apply, "--load-all --file") {
		t.Error("apply.sh must not pass --file to swanctl")
	}
	for _, body := range []string{f.Apply, f.Routes} {
		if strings.Contains(body, "local") && strings.Contains(body, "from 10.90.1.0/24 lookup 100") {
			t.Error("local face must not get policy routing; it uses the main table")
		}
		// `ip rule` has no replace subcommand, and both scripts run under set -e: a
		// deploy that reaches it stops there, before the nft load and
		// swanctl --load-all, so the server looks applied while it is half-applied.
		if strings.Contains(body, "ip rule replace") {
			t.Error("uses `ip rule replace`, which iproute2 does not implement")
		}
	}
}

func TestApplyScriptWarnsWhenPluginIsNotLoaded(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// charon reads charon.plugins.*.load only at startup, so a running daemon keeps
	// its old plugin set through a clean-looking deploy and every client then dies at
	// IKE_AUTH. apply.sh must surface that instead of leaving verify.sh as the only
	// place an operator would find out.
	if !strings.Contains(f.Apply, "libstrongswan-eap-mschapv2.so") {
		t.Error("apply.sh must check /proc/<charon>/maps for eap-mschapv2 after loading")
	}
	// it must not restart the IKE daemon on its own: that drops every live tunnel.
	// Only a literal command line counts - the warning text names the command on
	// purpose, and this deploy does restart its own units, which carry no sessions.
	for _, line := range strings.Split(f.Apply, "\n") {
		cmd := strings.TrimSpace(line)
		if !strings.HasPrefix(cmd, "systemctl restart") && !strings.HasPrefix(cmd, "systemctl stop") {
			continue
		}
		for _, daemon := range []string{"strongswan", "ipsec", "charon"} {
			if strings.Contains(cmd, daemon) {
				t.Errorf("apply.sh executes %q; it must warn and let the operator decide", cmd)
			}
		}
	}
}

func TestNftLanRulesUseRealPools(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	if strings.Contains(f.Nft, "10.0.0.0/8") {
		t.Error("LAN rules must key off the face pools, not a hardcoded supernet")
	}
	for _, want := range []string{
		"ip saddr 10.90.1.0/24 ip daddr 192.168.10.0/24 accept",
		"ip saddr 10.90.2.0/24 ip daddr 192.168.10.0/24 accept",
	} {
		if !strings.Contains(f.Nft, want) {
			t.Errorf("egress.nft missing %q", want)
		}
	}
}

func TestApplyScriptPreflightsNft(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	if !strings.Contains(f.Apply, "nft -c -f") {
		t.Error("apply.sh must compile the ruleset before loading it")
	}
}

// strongSwan silently ignores unknown charon keys, so a made-up option renders
// fine and then does nothing - "forwarding" came from a plausible-looking guess.
func TestCharonSnippetOnlyUsesRealKeys(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	for _, bogus := range []string{"forwarding", "fragmentation", "force_nat_kw", "retransmission_default"} {
		if strings.Contains(f.CharonSnippet, bogus) {
			t.Errorf("charon snippet mentions %q, which is not a charon key", bogus)
		}
	}
	for _, want := range []string{"eap-mschapv2", "load = yes"} {
		if !strings.Contains(f.CharonSnippet, want) {
			t.Errorf("charon snippet missing %q", want)
		}
	}
	// Debian's own strongswan.conf already sets it, and re-stating it from a
	// drop-in invites the question of who wins.
	if strings.Contains(f.CharonSnippet, "load_modular") {
		t.Error("charon snippet should not redeclare load_modular")
	}
	// A filelog section turns off charon's default logger, and the shipped
	// AppArmor profile denies the file creation, so adding one here silences the
	// daemon completely on Ubuntu.
	if strings.Contains(f.CharonSnippet, "filelog") {
		t.Error("charon snippet must not define a filelog target")
	}
}

// verify.sh runs on the server, where nobody re-reads these strings, so the checks
// it claims to make have to be the ones that can actually fail for the real reason.
func TestVerifyChecksPluginIsLoadedNotJustPresent(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// list-algs lists crypto algorithms; EAP methods never appear in it, so this
	// check would have reported "plugin not found" on a perfectly good server.
	if strings.Contains(f.Verify, "list-algs") {
		t.Error("verify.sh must not infer EAP support from list-algs")
	}
	for _, want := range []string{"libstrongswan-eap-mschapv2.so", "/maps", "pgrep -x charon"} {
		if !strings.Contains(f.Verify, want) {
			t.Errorf("verify.sh missing %q", want)
		}
	}
}

func TestMobileconfigStructure(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	prof := f.Profiles["alice"]
	for _, want := range []string{
		"<key>RemoteAddress</key><string>vpn.example.com</string>",
		"<key>RemoteIdentifier</key><string>vpn.example.com</string>",
		"<key>VPNType</key><string>IKEv2</string>",
		"<key>PayloadType</key><string>com.apple.vpn.managed</string>",
		"<key>ExtendedAuthEnabled</key><integer>1</integer>",
		"<key>AuthenticationMethod</key><string>Certificate</string>",
		"<key>PayloadType</key><string>com.apple.security.root</string>",
	} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile missing %q", want)
		}
	}
	// the CA must arrive as base64 DER inside <data>, never as PEM text
	if strings.Contains(prof, "BEGIN CERTIFICATE") {
		t.Error("CA embedded as PEM; Apple's <data> wants base64 DER")
	}
	if !strings.Contains(prof, "<key>PayloadContent</key><data>") {
		t.Error("CA payload content must be wrapped in <data>")
	}
}

func TestMobileconfigOmitsEmptyLocalIdentifier(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	// send-local-identifier is off in the fixture, so the key must be absent: an
	// empty <string> is read by some Apple releases as "send an empty IKE ID".
	if strings.Contains(f.Profiles["alice"], "<key>LocalIdentifier</key>") {
		t.Error("profile carries an empty LocalIdentifier; omit the key instead")
	}

	c.Client.SendLocalIdentifier = true
	f = mustRender(t, c)
	if !strings.Contains(f.Profiles["alice"], "<key>LocalIdentifier</key><string>alice</string>") {
		t.Error("send-local-identifier must put the account name in the profile")
	}
}

func TestMobileconfigDoesNotEmbedPasswordByDefault(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	if strings.Contains(f.Profiles["alice"], "AuthPassword") {
		t.Error("a profile file gets emailed and lands in Downloads; it must not carry the password unless asked")
	}
	if !strings.Contains(f.Profiles["alice"], "<key>AuthName</key><string>alice</string>") {
		t.Error("prefill-username should set AuthName so the user types only the password")
	}

	c.Client.EmbedPassword = true
	f, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Profiles["alice"], "<key>AuthPassword</key><string>pw-alice</string>") {
		t.Error("embed-password=true must actually embed it")
	}
}

func TestPrefillUsernameCanBeTurnedOff(t *testing.T) {
	c, _, _, _ := setup(t)
	off := false
	c.Client.PromptForUsername = &off
	f := mustRender(t, c)
	if strings.Contains(f.Profiles["alice"], "AuthName") {
		t.Error("prefill-username=false must omit AuthName so macOS asks for both")
	}
}

func TestMobileconfigTranslatesProposalsToAppleVocabulary(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	if !strings.Contains(f.Profiles["alice"], "<key>EncryptionAlgorithm</key><string>AES-256</string>") {
		t.Error("aes256 must map to Apple's AES-256")
	}
	if !strings.Contains(f.Profiles["alice"], "<key>IntegrityAlgorithm</key><string>SHA2-256</string>") {
		t.Error("sha256 must map to Apple's SHA2-256")
	}
	if !strings.Contains(f.Profiles["alice"], "<key>DiffieHellmanGroup</key><integer>14</integer>") {
		t.Error("modp2048 must map to group 14")
	}
}

func TestMobileconfigRejectsUnknownProposalVocabulary(t *testing.T) {
	c, _, _, _ := setup(t)
	c.Tuning.IkeProposals = "aes256gcm16-prfsha256-ecp256"
	if _, err := Render(c); err == nil {
		t.Fatal("an unmappable proposal must fail loudly, not emit a profile that installs and never connects")
	}
}

func TestMobileconfigStableAcrossRenders(t *testing.T) {
	c, _, _, _ := setup(t)
	first := mustRender(t, c).Profiles["alice"]
	second := mustRender(t, c).Profiles["alice"]
	if first != second {
		t.Error("profiles must be byte-stable so re-renders diff cleanly and reinstall replaces")
	}
}

func TestXMLProfileEscaping(t *testing.T) {
	if got := xmlEscape(`a<b>&"x`); got != "a&lt;b&gt;&amp;&quot;x" {
		t.Errorf("bad escaping: %s", got)
	}
}

func TestProfileIdentifierIsSlugified(t *testing.T) {
	c, _, _, _ := setup(t)
	c.Client.Organization = "Example Inc"
	f := mustRender(t, c)
	if !strings.Contains(f.Profiles["alice"], "<key>PayloadIdentifier</key><string>example-inc.alice.local</string>") {
		t.Error("identifier must be reverse-DNS safe: a space in PayloadIdentifier breaks MDM profile matching")
	}
}

func TestServerCertCNComesFromTheCertificate(t *testing.T) {
	c, _, _, _ := setup(t)
	// rename the file; the profile must still carry the certificate's own CN
	dir := t.TempDir()
	renamed := filepath.Join(dir, "unrelated-name.pem")
	raw, err := os.ReadFile(c.Server.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(renamed, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	c.Server.CertFile = renamed
	f := mustRender(t, c)
	if !strings.Contains(f.Profiles["alice"], "<key>ServerCertificateCommonName</key><string>vpn.example.com</string>") {
		t.Error("CN must be read from the certificate, not inferred from the filename")
	}
}

func TestIssuerCNComesFromConfigWhenSet(t *testing.T) {
	c, _, _, _ := setup(t)
	f := mustRender(t, c)
	if !strings.Contains(f.Profiles["alice"], "<key>ServerCertificateIssuerCommonName</key><string>Test Root CA</string>") {
		t.Error("an explicit ca-common-name must win over the derived one")
	}
}

func TestIssuerCNDefaultsToCACertificate(t *testing.T) {
	c, _, _, _ := setup(t)
	c.Server.CACommonName = ""
	f := mustRender(t, c)
	if !strings.Contains(f.Profiles["alice"], "<key>ServerCertificateIssuerCommonName</key><string>Test Root CA</string>") {
		t.Error("issuer CN should be read from the CA when not configured")
	}
}

func TestProfileFailsOnUnparsableCert(t *testing.T) {
	c, _, _, _ := setup(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.Server.CertFile = bad
	if _, err := Render(c); err == nil {
		t.Fatal("expected a garbage cert file to abort rendering")
	}
}

func TestRenderFailsOnMissingPrivateKeyFile(t *testing.T) {
	c, _, _, _ := setup(t)
	c.Upstreams[0].PrivateKeyFile = filepath.Join(t.TempDir(), "absent.key")
	if _, err := Render(c); err == nil {
		t.Fatal("expected missing key file to abort rendering")
	}
}

// The hop-2 link can be carried over TCP. Everything that makes the chain work
// must stay identical when it is - same device name, same routes, same NAT - so
// this asserts the generated link is a drop-in for the WireGuard one, and that
// each generated fragment actually parses as shell.
func TestHop2OverTCP(t *testing.T) {
	c, _, _, _ := setup(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "hop2_ed25519")
	if err := os.WriteFile(key, []byte("never embedded; A reads it at run time\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexampleexampleexampleexample egress-hop2"
	if err := os.WriteFile(key+".pub", []byte(pub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	u := &c.Upstreams[0]
	u.Transport = "tcp-ssh"
	u.Endpoint = "203.0.113.9:22"
	u.PrivateKeyFile = key
	u.RemotePubKey = ""
	u.PSKFile = ""

	f := mustRender(t, c)
	if len(f.WireGuard) != 0 {
		t.Error("transport tcp-ssh must not render a wg conf: wg setconf on the renamed tunnel device would abort apply.sh")
	}

	runner := f.Hop2Runner["b"]
	for _, want := range []string{
		"IDX=10",
		"ssh -F \"$CFG\" -w $IDX:$IDX hop2-b &",
		// the device keeps the configured name, so egress.nft's oifname and the
		// table-100 route need no separate version
		"ip link set tun$IDX name wgb",
		"ip -4 addr replace 10.91.0.2/32 dev wgb",
		"ip link set wgb mtu 1380 up",
		"ip route replace 10.91.0.1 dev wgb scope link",
		"ip route replace default dev wgb table 100",
	} {
		if !strings.Contains(runner, want) {
			t.Errorf("hop-2 runner missing %q", want)
		}
	}
	if strings.Contains(runner, "wg setconf") || strings.Contains(runner, "type wireguard") {
		t.Error("hop-2 runner must not touch WireGuard on a tcp link")
	}

	sshCfg := f.Hop2SshCfg["b"]
	for _, want := range []string{
		"Host hop2-b", "HostName 203.0.113.9", "Port 22", "User root",
		"IdentityFile " + key,
		// a key that is not accepted must not fall through to passwords: repeated
		// failures from A's address can get A banned on B while the link flaps
		"PreferredAuthentications publickey",
		"PasswordAuthentication no",
	} {
		if !strings.Contains(sshCfg, want) {
			t.Errorf("hop-2 ssh config missing %q", want)
		}
	}

	unit := f.Hop2Unit["b"]
	if !strings.Contains(unit, "ExecStart=/usr/local/sbin/egress-hop2-b.sh") {
		t.Errorf("unit must start the runner this render produced, got %q", unit)
	}
	if !strings.Contains(unit, "Restart=always") {
		t.Error("the link dies with the ssh channel, so the unit has to restart it")
	}

	peer := f.PeerSnippets["b"]
	for _, want := range []string{
		pub,
		`command="/usr/local/sbin/egress-hop2-b-peer.sh"`,
		`from="vpn.example.com"`,
		"PermitTunnel yes",
		// some images ship this off, and then the link fails as "Permission denied
		// (password)" which reads like a key problem
		"PubkeyAuthentication yes",
		"ip saddr 10.91.0.2 masquerade",
		"ip saddr 10.90.2.0/24 masquerade",
		"net.ipv4.ip_forward = 1",
		// start on an active oneshot unit is a no-op: a re-render would leave B
		// running the previous NAT table while the file said something else
		"systemctl restart egress-b-nft.service",
	} {
		if !strings.Contains(peer, want) {
			t.Errorf("block for B missing %q", want)
		}
	}
	// sshd answers with the FIRST authorized_keys line holding a key, so the stale
	// entry has to be removed by the key itself. Filtering on the script name left
	// an earlier render's line in place, and B kept running the old peer script -
	// which reads as "link never comes up" on A.
	blob := strings.Fields(pub)[1]
	if !strings.Contains(peer, "grep -vF '"+blob+"'") {
		t.Errorf("block for B must drop previous authorized_keys entries by key blob %q", blob)
	}
	if strings.Contains(peer, "grep -v 'egress-hop2-") {
		t.Error("authorized_keys dedupe by script name misses stale entries for the same key")
	}
	if strings.Contains(peer, "systemctl start egress-b-nft.service") {
		t.Error("the NAT unit must be restarted; start on an active oneshot unit is a no-op")
	}

	apply := f.Apply
	for _, want := range []string{
		"systemctl restart egressvpn-hop2-b.service",
		"tcp 22",
	} {
		if !strings.Contains(apply, want) {
			t.Errorf("apply.sh missing %q", want)
		}
	}
	if strings.Contains(apply, "wg setconf wgb") || strings.Contains(apply, "type wireguard") {
		t.Error("apply.sh must not configure WireGuard for a tcp-ssh link")
	}

	// The keeper is what runs unattended, so it must know the ssh link's own facts:
	// the ssh device carries no dynamic addressing, and a flap takes the table-100
	// default with it, which leaves the relay face egressing through A.
	for _, want := range []string{
		"ip -4 address replace 10.91.0.2/32 dev wgb",
		"ip route replace 10.91.0.1 dev wgb scope link",
		"ip route replace default dev wgb table 100",
	} {
		if !strings.Contains(f.Routes, want) {
			t.Errorf("egressvpn-routes.sh missing %q", want)
		}
	}
	if strings.Contains(f.Routes, "wg setconf wgb") || strings.Contains(f.Routes, "type wireguard") {
		t.Error("the reconciler must not configure WireGuard for a tcp-ssh link")
	}
	// after= so a reboot does not run the keeper against a link that has not been
	// created yet and note "wgb is missing" into the log every minute
	if !strings.Contains(f.RoutesUnit, "After=network-online.target egressvpn-hop2-b.service") {
		t.Errorf("route unit must order after the hop-2 unit, got:\n%s", f.RoutesUnit)
	}

	verify := f.Verify
	for _, want := range []string{
		"systemctl is-active --quiet egressvpn-hop2-b.service",
		"ping -c 1 -W 2 10.91.0.1",
	} {
		if !strings.Contains(verify, want) {
			t.Errorf("verify.sh missing %q", want)
		}
	}
	// `wg show` on a tunnel device fails, and a check that can only report failure
	// on a working deployment is worse than no check.
	if strings.Contains(verify, "wg show wgb") {
		t.Error("verify.sh must not ask wg(8) about a tcp-ssh link")
	}

	checkParses(t, "runner.sh", runner, "bash")
	checkParses(t, "apply.sh", apply, "sh")
	checkParses(t, "verify.sh", verify, "sh")
	checkParses(t, "B-peer.sh", peer, "bash")
}

// A missing .pub file is the one case where the block for B cannot be completed,
// and a half-written authorized_keys line is a long way to debug.
func TestHop2OverTCPNeedsPublicKey(t *testing.T) {
	c, _, _, _ := setup(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "hop2_ed25519")
	if err := os.WriteFile(key, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &c.Upstreams[0]
	u.Transport = "tcp-ssh"
	u.Endpoint = "203.0.113.9:22"
	u.PrivateKeyFile = key
	u.RemotePubKey = ""
	u.PSKFile = ""
	_, err := Render(c)
	if err == nil {
		t.Fatal("expected render to fail without hop2_ed25519.pub")
	}
	if !strings.Contains(err.Error(), "ssh-keygen") {
		t.Errorf("error should say how to make the key, got %v", err)
	}
}

func checkParses(t *testing.T, name, body, shell string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(shell, "-n", path).CombinedOutput(); err != nil {
		t.Errorf("%s does not parse as %s: %v\n%s", name, shell, err, out)
	}
}

// selfSignedCert emits a throwaway PEM certificate. Content is irrelevant; the
// profile renderer reads the subject CN out of it, so the CN is the parameter.
func selfSignedCert(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
