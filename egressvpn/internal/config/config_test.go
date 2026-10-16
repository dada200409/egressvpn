package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dada200409/egressvpn/internal/wgkey"
)

// fixture builds a valid config; tests then break exactly one rule each.
func fixture(t *testing.T) *Config {
	t.Helper()
	// real key material: validation rejects low-order or malformed peer keys
	_, peerPub, err := wgkey.GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`server:
  public-host: vpn.example.com
  cert-file: /etc/swanctl/x509/vpn.example.com.pem
  key-file: /etc/swanctl/private/vpn.example.com-key.pem
  ca-file: /etc/swanctl/x509ca/ca.pem
  dns:
    - 1.1.1.1
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
    endpoint: 203.0.113.20:51820
    local-ip: 10.91.0.2/32
    remote-ip: 10.91.0.1/32
    remote-public-key: %[1]s
    private-key-file: /tmp/wgb.key
users:
  - name: alice
    face: local
    password: pw-alice
  - name: bob
    face: via-b
    password: pw-bob
`, peerPub)

	dir := t.TempDir()
	path := filepath.Join(dir, "egress.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	return c
}

func TestLoadAppliesDefaults(t *testing.T) {
	c := fixture(t)
	if c.Server.Identity != c.Server.PublicHost {
		t.Errorf("identity should default to public-host, got %q", c.Server.Identity)
	}
	if c.Tuning.Mtu != 1380 || c.Tuning.TunnelMtu != 1280 || c.Tuning.MssClamp != 1240 {
		t.Errorf("tuning defaults wrong: mtu=%d tunnel-mtu=%d mss=%d", c.Tuning.Mtu, c.Tuning.TunnelMtu, c.Tuning.MssClamp)
	}
	if c.Upstreams[0].Interface != "wg-b" {
		t.Errorf("upstream interface should default to wg-<name>, got %q", c.Upstreams[0].Interface)
	}
}

func TestPoolOverlapRejected(t *testing.T) {
	c := fixture(t)
	c.Faces[1].Pool = "10.90.0.0/16"
	if err := c.Validate(); err == nil {
		t.Fatal("expected overlapping pool to be rejected")
	}
}

// An MSS clamp above the tunnel MTU is not inert: nftables rewrites the
// advertised value unconditionally, so it raises the peer's segment size and
// the client drops everything over its own tunnel MTU. This happened on the
// live box with mss-clamp 1340 against a 1280-byte macOS ipsec0.
func TestClampAboveTunnelMtuRejected(t *testing.T) {
	c := fixture(t)
	c.Tuning.MssClamp = 1340
	err := c.Validate()
	if err == nil {
		t.Fatal("expected a clamp above the tunnel MTU to be rejected")
	}
	if !strings.Contains(err.Error(), "tunnel-mtu") {
		t.Errorf("error should name the knob to fix, got %v", err)
	}
	c.Tuning.TunnelMtu = 1400
	if err := c.Validate(); err != nil {
		t.Errorf("1340 is a legal clamp for a 1400-byte tunnel: %v", err)
	}
}

// A hop-2 link can be carried over TCP instead of WireGuard, and the two
// transports need different things: ssh splits host and port, its key is a file
// that has to exist, and WireGuard's peer key would be decoration.
func TestTCPTransportRules(t *testing.T) {
	c := fixture(t)
	if c.Upstreams[0].Transport != "wireguard" {
		t.Fatalf("transport should default to wireguard, got %q", c.Upstreams[0].Transport)
	}
	u := &c.Upstreams[0]
	u.Transport = "tcp-ssh"
	u.Endpoint = "203.0.113.9:22"

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "WireGuard settings") {
		t.Errorf("tcp-ssh with remote-public-key set should be rejected, got %v", err)
	}
	u.RemotePubKey = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ssh private-key-file") {
		t.Errorf("tcp-ssh should demand a key that exists, got %v", err)
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "hop2_ed25519")
	if err := os.WriteFile(key, []byte("never read by the renderer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u.PrivateKeyFile = key
	if err := c.Validate(); err != nil {
		t.Fatalf("a tcp-ssh link with an existing key should be valid: %v", err)
	}
	if u.SSHUser != "root" || u.TunnelIndex != 10 {
		t.Errorf("tcp-ssh defaults: ssh-user %q tunnel-index %d", u.SSHUser, u.TunnelIndex)
	}
	// ssh needs the port explicitly: guessing 22 would send the link somewhere the
	// operator did not write.
	u.Endpoint = "203.0.113.9"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Errorf("tcp-ssh endpoint without a port should be rejected, got %v", err)
	}
	u.Endpoint = "203.0.113.9:22"
	u.Transport = "udp"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "transport must be") {
		t.Errorf("unknown transport should be rejected, got %v", err)
	}
}

func TestUnknownFaceRejected(t *testing.T) {
	c := fixture(t)
	c.Users[0].Face = "nope"
	if err := c.Validate(); err == nil {
		t.Fatal("expected unknown face to be rejected")
	}
}

func TestRelayFaceWithoutUpstreamRejected(t *testing.T) {
	c := fixture(t)
	c.Faces[1].Upstream = "missing"
	if err := c.Validate(); err == nil {
		t.Fatal("expected unknown upstream to be rejected")
	}
}

func TestUserWithoutCredentialRejected(t *testing.T) {
	c := fixture(t)
	c.Users[0].Password = ""
	if err := c.Validate(); err == nil {
		t.Fatal("user with no credential should be rejected")
	}
}

func TestDuplicateUserRejected(t *testing.T) {
	c := fixture(t)
	c.Users[1].Name = "alice"
	if err := c.Validate(); err == nil {
		t.Fatal("duplicate identity would make strongSwan connection selection ambiguous")
	}
}

func TestPasswordFromFileStripsTrailingNewline(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "alice")
	if err := os.WriteFile(secret, []byte("s3cr3t\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := User{Name: "alice", PasswordRef: secret}
	got, err := u.ResolvePassword()
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cr3t" {
		t.Errorf("want trailing newline stripped, got %q", got)
	}
}

func TestPasswordFromEnv(t *testing.T) {
	t.Setenv("EGRESSVPN_TEST_PW", "from-env")
	u := User{Name: "alice", PasswordRef: "env:EGRESSVPN_TEST_PW"}
	got, err := u.ResolvePassword()
	if err != nil || got != "from-env" {
		t.Errorf("env ref failed: %q err=%v", got, err)
	}
}

func TestEmptyEnvRefIsErrorNotBlankPassword(t *testing.T) {
	u := User{Name: "alice", PasswordRef: "env:EGRESSVPN_DEFINITELY_UNSET"}
	if _, err := u.ResolvePassword(); err == nil {
		t.Fatal("empty env var must error, not silently yield a blank password")
	}
}
