package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/dada200409/egressvpn/internal/wgkey"
	"github.com/dada200409/egressvpn/internal/yamlite"
)

type Config struct {
	Server    Server     `yaml:"server"`
	Client    Client     `yaml:"client"`
	Tuning    Tuning     `yaml:"tuning"`
	Faces     []Face     `yaml:"faces"`
	Upstreams []Upstream `yaml:"upstreams"`
	Users     []User     `yaml:"users"`
}

// Server is hop-1: the IKEv2 endpoint the Macs connect to.
type Server struct {
	PublicHost   string `yaml:"public-host"`
	Identity     string `yaml:"identity"`
	CertFile     string `yaml:"cert-file"`
	KeyFile      string `yaml:"key-file"`
	CAFile       string `yaml:"ca-file"`
	CACommonName string `yaml:"ca-common-name"`
	// InboundInterface is the NIC client ESP packets arrive on. Every egress face
	// hangs its XFRM interface off this one - it is where the tunnel endpoints
	// live, not where the traffic eventually leaves.
	InboundInterface string   `yaml:"inbound-interface"`
	DNS              []string `yaml:"dns"`
	LAN              []string `yaml:"lan"`
}

// Client controls the generated Apple profile.
type Client struct {
	DisplayName   string `yaml:"display-name"`
	Organization  string `yaml:"organization"`
	RemoteAddress string `yaml:"remote-address"`
	EmbedPassword bool   `yaml:"embed-password"`
	// pointer so "absent" differs from "false": prefilling the EAP identity is the
	// friendlier default and should only need opting out.
	PromptForUsername        *bool `yaml:"prefill-username"`
	SendLocalIdentifier      bool  `yaml:"send-local-identifier"`
	RequireSupervisedRemoval bool  `yaml:"removal-disallowed"`
}

// PrefillsUsername reports whether AuthName goes into the profile.
func (c *Client) PrefillsUsername() bool {
	return c.PromptForUsername == nil || *c.PromptForUsername
}

type Tuning struct {
	// Mtu is the hop-2 link (A<->B) MTU, a plain internet path, whichever
	// transport carries it.
	Mtu int `yaml:"mtu"`
	// TunnelMtu is the MTU of the IKE tunnel: the xfrmi device on A. macOS
	// sets its IKEv2 interface to 1280 by itself and asks for nothing larger,
	// so this - not the server's link MTU - is what the clamp comes from.
	TunnelMtu int `yaml:"tunnel-mtu"`
	// MssClamp must stay at or below TunnelMtu - 40. nftables rewrites the
	// advertised MSS unconditionally, so a clamp above the client's path MSS
	// *raises* it: the peer then sends segments bigger than the client's
	// tunnel MTU and the client drops every one of them.
	MssClamp       int    `yaml:"mss-clamp"`
	IkeProposals   string `yaml:"ike-proposals"`
	EspProposals   string `yaml:"esp-proposals"`
	DpdDelay       string `yaml:"dpd-delay"`
	RekeyTime      string `yaml:"rekey-time"`
	ChildRekeyTime string `yaml:"child-rekey-time"`
	WgPort         int    `yaml:"wg-port"`
	WgKeepalive    int    `yaml:"wg-keepalive"`
}

// Face is one egress route: either A's own uplink or a chained upstream.
type Face struct {
	Name         string `yaml:"name"`
	Egress       string `yaml:"egress"`
	Pool         string `yaml:"pool"`
	OutInterface string `yaml:"out-interface"`
	Upstream     string `yaml:"upstream"`
}

// Upstream is the hop-2 link to server B.
type Upstream struct {
	Name      string `yaml:"name"`
	Interface string `yaml:"interface"`
	Endpoint  string `yaml:"endpoint"`
	// Transport selects how the hop-2 link is carried: "wireguard" (default) or
	// "tcp-ssh". Between two hosting providers that filter UDP in one direction a
	// WireGuard handshake can never complete (measured here: TCP SYNs from B
	// arrived on every port tried, zero UDP packets did), and only the link
	// technology has to change - the device keeps the same name, so A's policy
	// routing, SNAT and kill switch are identical either way.
	Transport string `yaml:"transport"`
	// SSHUser and TunnelIndex apply to tcp-ssh only. The tunnel device is created
	// as tun<tunnel-index> and renamed to interface.
	SSHUser     string `yaml:"ssh-user"`
	TunnelIndex int    `yaml:"tunnel-index"`
	// For tcp-ssh this is the path to A's SSH private key for the link (generated
	// with ssh-keygen, never embedded in the render output).
	PrivateKeyFile string `yaml:"private-key-file"`
	LocalTunnelIP  string `yaml:"local-ip"`
	RemoteTunnelIP string `yaml:"remote-ip"`
	RemotePubKey   string `yaml:"remote-public-key"`
	PSKFile        string `yaml:"psk-file"`
}

// OverTCP reports whether this link rides an SSH tunnel device instead of UDP.
func (u *Upstream) OverTCP() bool { return u.Transport == "tcp-ssh" }

type User struct {
	Name        string `yaml:"name"`
	Face        string `yaml:"face"`
	Password    string `yaml:"password"`
	PasswordRef string `yaml:"password-ref"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yamlite.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// RekeyMinutes converts strongSwan's duration ("14400s") into the whole minutes
// Apple's LifeTimeInMinutes wants, floored so the client rekeys before the
// server ever has to.
func (t *Tuning) RekeyMinutes() int { return minutes(t.RekeyTime) }

func (t *Tuning) ChildRekeyMinutes() int { return minutes(t.ChildRekeyTime) }

func minutes(d string) int {
	seconds := 0
	switch {
	case strings.HasSuffix(d, "h"):
		n, _ := strconv.Atoi(strings.TrimSuffix(d, "h"))
		seconds = n * 3600
	case strings.HasSuffix(d, "m"):
		n, _ := strconv.Atoi(strings.TrimSuffix(d, "m"))
		seconds = n * 60
	case strings.HasSuffix(d, "s"):
		n, _ := strconv.Atoi(strings.TrimSuffix(d, "s"))
		seconds = n
	default:
		n, _ := strconv.Atoi(d)
		seconds = n
	}
	if m := seconds / 60; m > 0 {
		return m
	}
	return 1
}

func (c *Config) applyDefaults() {
	if c.Server.Identity == "" {
		c.Server.Identity = c.Server.PublicHost
	}
	t := &c.Tuning
	if t.Mtu == 0 {
		t.Mtu = 1380
	}
	if t.TunnelMtu == 0 {
		// Measured on the live macOS client: its ipsec0 comes up with MTU 1280
		// no matter what the server offers. Match it so A's device and the
		// client's agree on what fits in the tunnel.
		t.TunnelMtu = 1280
	}
	if t.MssClamp == 0 {
		// 40 bytes of headroom for inner IP+TCP and the outer ESP/UDP headers;
		// going above the client's tunnel MTU is worse than not clamping at all.
		t.MssClamp = t.TunnelMtu - 40
	}
	if t.IkeProposals == "" {
		t.IkeProposals = "aes256-sha256-modp2048"
	}
	if t.EspProposals == "" {
		t.EspProposals = "aes256-sha256-modp2048"
	}
	if t.DpdDelay == "" {
		t.DpdDelay = "30s"
	}
	if t.RekeyTime == "" {
		t.RekeyTime = "14400s"
	}
	if t.ChildRekeyTime == "" {
		t.ChildRekeyTime = "3600s"
	}
	if c.Client.DisplayName == "" {
		c.Client.DisplayName = "VPN"
	}
	if t.WgPort == 0 {
		t.WgPort = 51820
	}
	if t.WgKeepalive == 0 {
		t.WgKeepalive = 25
	}
	for i := range c.Faces {
		if c.Faces[i].Egress == "local" && c.Faces[i].OutInterface == "" {
			c.Faces[i].OutInterface = "eth0"
		}
	}
	// The XFRM interfaces ride the NIC the clients reach, which in the usual
	// single-NIC case is the same uplink the local face egresses through.
	if c.Server.InboundInterface == "" {
		for i := range c.Faces {
			if c.Faces[i].Egress == "local" {
				c.Server.InboundInterface = c.Faces[i].OutInterface
				break
			}
		}
	}
	for i := range c.Upstreams {
		if c.Upstreams[i].Interface == "" {
			c.Upstreams[i].Interface = "wg-" + c.Upstreams[i].Name
		}
		if c.Upstreams[i].Transport == "" {
			c.Upstreams[i].Transport = "wireguard"
		}
		if c.Upstreams[i].SSHUser == "" {
			c.Upstreams[i].SSHUser = "root"
		}
		// one tunnel device per link; index 0 would collide with existing tun0
		if c.Upstreams[i].TunnelIndex == 0 {
			c.Upstreams[i].TunnelIndex = 10 + i
		}
	}
}

func (c *Config) Validate() error {
	if c.Server.PublicHost == "" {
		return fmt.Errorf("server.public-host is required")
	}
	if c.Server.CertFile == "" || c.Server.KeyFile == "" {
		return fmt.Errorf("server.cert-file and server.key-file are required")
	}
	// client profiles embed this so the Mac can verify the server's identity
	if c.Server.CAFile == "" {
		return fmt.Errorf("server.ca-file is required to generate client profiles")
	}
	if len(c.Faces) == 0 {
		return fmt.Errorf("at least one face is required")
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("at least one user is required")
	}

	faces := map[string]*Face{}
	pools := []*net.IPNet{}
	for i := range c.Faces {
		f := &c.Faces[i]
		if f.Name == "" {
			return fmt.Errorf("face %d: name attribute is required", i)
		}
		if _, dup := faces[f.Name]; dup {
			return fmt.Errorf("duplicate face name %q", f.Name)
		}
		// each face gets an XFRM interface named xv<face>, and interface names are
		// capped at 15 characters (IFNAMSIZ) by the kernel - a silently truncated
		// name would point apply.sh's route at a device that does not exist.
		if len(f.Name) > 12 {
			return fmt.Errorf("face %q: name must be at most 12 characters (interface xv%s exceeds IFNAMSIZ)", f.Name, f.Name)
		}
		switch f.Egress {
		case "local":
			if f.OutInterface == "" {
				return fmt.Errorf("face %q: egress=local needs out-interface", f.Name)
			}
		case "relay":
			if f.Upstream == "" {
				return fmt.Errorf("face %q: egress=relay needs upstream", f.Name)
			}
			if c.upstream(f.Upstream) == nil {
				return fmt.Errorf("face %q: unknown upstream %q", f.Name, f.Upstream)
			}
		default:
			return fmt.Errorf("face %q: egress must be local or relay, got %q", f.Name, f.Egress)
		}
		_, netw, err := net.ParseCIDR(f.Pool)
		if err != nil {
			return fmt.Errorf("face %q: bad pool %q: %w", f.Name, f.Pool, err)
		}
		for _, other := range pools {
			if netw.Contains(other.IP) || other.Contains(netw.IP) {
				return fmt.Errorf("face %q: pool %s overlaps another face pool", f.Name, f.Pool)
			}
		}
		pools = append(pools, netw)
		faces[f.Name] = f
	}

	upstreams := map[string]bool{}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Name == "" {
			return fmt.Errorf("upstream %d: name attribute is required", i)
		}
		upstreams[u.Name] = true
		switch u.Transport {
		case "wireguard", "tcp-ssh":
		default:
			return fmt.Errorf("upstream %q: transport must be wireguard or tcp-ssh, got %q", u.Name, u.Transport)
		}
		if u.Endpoint == "" || u.PrivateKeyFile == "" {
			return fmt.Errorf("upstream %q: endpoint and private-key-file are required", u.Name)
		}
		if u.OverTCP() {
			// ssh(1) takes host and port separately, so an endpoint with no port is
			// ambiguous rather than defaulted behind the operator's back.
			_, port, err := net.SplitHostPort(u.Endpoint)
			if err != nil {
				return fmt.Errorf("upstream %q: transport tcp-ssh needs endpoint as host:port (the ssh port): %w", u.Name, err)
			}
			if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("upstream %q: bad ssh port %q in endpoint", u.Name, port)
			}
			if u.RemotePubKey != "" || u.PSKFile != "" {
				return fmt.Errorf("upstream %q: remote-public-key and psk-file are WireGuard settings; the tcp-ssh link is encrypted by ssh itself, so remove them", u.Name)
			}
			// A's key never appears in the output, but a missing file means the link
			// comes up dead and only verify.sh notices much later.
			if _, err := os.Stat(u.PrivateKeyFile); err != nil {
				return fmt.Errorf("upstream %q: ssh private-key-file: %w (ssh-keygen -t ed25519 -f %s -N '')", u.Name, err, u.PrivateKeyFile)
			}
			if u.TunnelIndex < 1 || u.TunnelIndex > 999 {
				return fmt.Errorf("upstream %q: tunnel-index %d out of range 1..999", u.Name, u.TunnelIndex)
			}
		} else {
			if u.RemotePubKey == "" {
				return fmt.Errorf("upstream %q: remote-public-key is required for transport wireguard", u.Name)
			}
			if _, err := net.ResolveUDPAddr("udp", u.Endpoint); err != nil {
				return fmt.Errorf("upstream %q: bad endpoint %q: %w", u.Name, u.Endpoint, err)
			}
			// a low-order peer key would build a tunnel with no real secrecy
			if err := wgkey.ValidatePeerPublicKey(u.RemotePubKey); err != nil {
				return fmt.Errorf("upstream %q: %w", u.Name, err)
			}
		}
		if net.ParseIP(cidrIP(u.LocalTunnelIP)) == nil || net.ParseIP(cidrIP(u.RemoteTunnelIP)) == nil {
			return fmt.Errorf("upstream %q: local-ip/remote-ip must be CIDRs or plain IPs", u.Name)
		}
		if u.LocalTunnelIP != "" && !strings.Contains(u.LocalTunnelIP, "/") {
			return fmt.Errorf("upstream %q: local-ip must be CIDR (e.g. 10.91.0.2/32)", u.Name)
		}
	}

	seen := map[string]bool{}
	for _, u := range c.Users {
		if u.Name == "" {
			return fmt.Errorf("user with empty <name>")
		}
		if seen[u.Name] {
			return fmt.Errorf("duplicate user %q", u.Name)
		}
		seen[u.Name] = true
		if faces[u.Face] == nil {
			return fmt.Errorf("user %q: unknown face %q", u.Name, u.Face)
		}
		if u.Password == "" && u.PasswordRef == "" {
			return fmt.Errorf("user %q: set password or password-ref", u.Name)
		}
	}

	if c.Tuning.MssClamp < 536 || c.Tuning.MssClamp > 1460 {
		return fmt.Errorf("tuning.mss-clamp %d out of the sane 536..1460 range", c.Tuning.MssClamp)
	}
	if c.Tuning.TunnelMtu < 576 || c.Tuning.TunnelMtu > 1500 {
		return fmt.Errorf("tuning.tunnel-mtu %d out of the sane 576..1500 range", c.Tuning.TunnelMtu)
	}
	// A clamp wider than the tunnel's MTU is not a no-op: the rewrite raises the
	// peer's segment size past what the client can receive, and the client drops
	// silently (measured: clamp 1340 against a 1280-byte ipsec0 lost every
	// packet over 1280 bytes, leaving ICMP-only throughput).
	if c.Tuning.MssClamp > c.Tuning.TunnelMtu-40 {
		return fmt.Errorf("tuning.mss-clamp %d exceeds tunnel-mtu %d minus 40: the clamp would raise "+
			"the client's MSS and black-hole large packets; use at most %d",
			c.Tuning.MssClamp, c.Tuning.TunnelMtu, c.Tuning.TunnelMtu-40)
	}
	return nil
}

func (c *Config) upstream(name string) *Upstream {
	for i := range c.Upstreams {
		if c.Upstreams[i].Name == name {
			return &c.Upstreams[i]
		}
	}
	return nil
}

// ResolvePassword keeps plaintext out of the config file: password-ref names a file
// (whole file, trailing newline stripped) or env:VARNAME.
func (u *User) ResolvePassword() (string, error) {
	if u.Password != "" {
		return u.Password, nil
	}
	ref := u.PasswordRef
	if v, ok := strings.CutPrefix(ref, "env:"); ok {
		val := os.Getenv(v)
		if val == "" {
			return "", fmt.Errorf("user %q: environment variable %s is empty", u.Name, v)
		}
		return val, nil
	}
	raw, err := os.ReadFile(ref)
	if err != nil {
		return "", fmt.Errorf("user %q: cannot read password-ref %q: %w", u.Name, ref, err)
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

func cidrIP(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}
