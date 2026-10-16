package render

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/dada200409/egressvpn/internal/config"
)

// Apple's IKEv2 payload uses its own algorithm vocabulary, so the strongSwan
// proposal string has to be translated rather than passed through.
const (
	apxAES128 = "AES-128"
	apxAES256 = "AES-256"
)

var dhToAppleGroup = map[string]int{
	"modp2048": 14,
	"modp3072": 15,
	"modp4096": 16,
	"ecp256":   19,
	"ecp384":   20,
	"ecp521":   21,
}

var integrityToApple = map[string]string{
	"sha1":    "SHA1-96",
	"sha256":  "SHA2-256",
	"sha384":  "SHA2-384",
	"sha512":  "SHA2-512",
	"sha1_96": "SHA1-96",
	"md5":     "MD5",
}

// splitProposal parses strongSwan's "cipher-integrity-dh" into the three Apple
// values. Unknown parts are an error: silently emitting a wrong algorithm name
// produces a profile that installs fine and then never connects.
func splitProposal(proposal string) (encryption, integrity string, group int, err error) {
	parts := strings.Split(proposal, "-")
	if len(parts) < 3 {
		return "", "", 0, fmt.Errorf("proposal %q is not cipher-integrity-dh", proposal)
	}
	cipher, dh := parts[0], parts[len(parts)-1]
	integrity = strings.Join(parts[1:len(parts)-1], "-")

	switch cipher {
	case "aes128":
		encryption = apxAES128
	case "aes256":
		encryption = apxAES256
	default:
		return "", "", 0, fmt.Errorf("proposal %q: Apple profile has no name for cipher %q; use aes128 or aes256", proposal, cipher)
	}
	g, ok := dhToAppleGroup[dh]
	if !ok {
		return "", "", 0, fmt.Errorf("proposal %q: unsupported DH group %q (know modp2048/3072/4096, ecp256/384/521)", proposal, dh)
	}
	// Apple wants the integrity algorithm omitted for AEAD; the cipher-integrity
	// forms we accept always name one explicitly.
	i, ok := integrityToApple[integrity]
	if !ok {
		return "", "", 0, fmt.Errorf("proposal %q: unsupported integrity algorithm %q", proposal, integrity)
	}
	return encryption, i, g, nil
}

// deterministicUUID keeps rendered profiles byte-stable so a re-render shows as
// a diff instead of churn, and so reinstalling replaces the old profile.
func deterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// caDER converts a PEM certificate to the base64 DER that Apple's <data> wants.
func caDER(path string) (string, error) {
	der, err := certDER(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func certDER(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s has no PEM block; Apple needs a PEM-encoded certificate", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s is a %s, expected CERTIFICATE", path, block.Type)
	}
	return block.Bytes, nil
}

// certCommonName reads the identity the client will actually match against.
// Deriving it from the certificate beats trusting a filename: renaming a PEM
// would otherwise silently produce a profile that fails server verification.
func certCommonName(path string) (string, error) {
	der, err := certDER(path)
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	if cn := cert.Subject.CommonName; cn != "" {
		return cn, nil
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0], nil
	}
	return "", fmt.Errorf("%s has neither a subject CN nor a DNS SAN, so the client cannot pin it", path)
}

// slug makes an Apple-conformant reverse-DNS identifier fragment out of a
// display string; a space in PayloadIdentifier breaks MDM profile matching.
func slug(s string) string {
	var b strings.Builder
	lastDash := true
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
			lastDash = r == '-'
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// Mobileconfig returns an Apple profile for one user. Keys follow the layout
// documented by strongSwan for Apple interoperability.
func Mobileconfig(c *config.Config, u *config.User) (filename, content string, err error) {
	face := faceOf(c, u.Face)
	org := c.Client.Organization
	if org == "" {
		org = "egressvpn"
	}
	profileID := slug(org) + "." + slug(u.Name) + "." + slug(u.Face)
	caID := slug(org) + ".ca"

	enc, integ, group, err := splitProposal(c.Tuning.IkeProposals)
	if err != nil {
		return "", "", err
	}
	childEnc, childInteg, childGroup, err := splitProposal(c.Tuning.EspProposals)
	if err != nil {
		return "", "", err
	}

	caPath := c.Server.CAFile
	if caPath == "" {
		return "", "", fmt.Errorf("server.ca-file is required: without it the client cannot verify the server identity")
	}
	caData, err := caDER(caPath)
	if err != nil {
		return "", "", err
	}
	// issuer CN comes from the CA itself unless overridden
	issuerCN := c.Server.CACommonName
	if issuerCN == "" {
		if issuerCN, err = certCommonName(caPath); err != nil {
			return "", "", fmt.Errorf("ca-common-name: %w", err)
		}
	}
	// the client matches the server cert's own CN, not our filename
	serverCN, err := certCommonName(c.Server.CertFile)
	if err != nil {
		return "", "", fmt.Errorf("server certificate: %w", err)
	}

	remoteAddr := c.Client.RemoteAddress
	if remoteAddr == "" {
		remoteAddr = c.Server.PublicHost
	}

	// The password is deliberately not embedded by default: a profile file gets
	// emailed and lands in Downloads, and this is an account credential.
	authPassword := ""
	if c.Client.EmbedPassword {
		pass, err := u.ResolvePassword()
		if err != nil {
			return "", "", err
		}
		authPassword = pass
	}

	localIdentifier := ""
	if c.Client.SendLocalIdentifier {
		localIdentifier = u.Name
	}

	vpnUUID := deterministicUUID(profileID + ".vpn")
	caUUID := deterministicUUID(caID)
	payloadUUID := deterministicUUID(profileID)

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key><string>` + xmlEscape(c.Client.DisplayName+" ("+face.Name+")") + `</string>
  <key>PayloadOrganization</key><string>` + xmlEscape(org) + `</string>
  <key>PayloadIdentifier</key><string>` + xmlEscape(profileID) + `</string>
  <key>PayloadUUID</key><string>` + payloadUUID + `</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadRemovalDisallowed</key>` + boolTag(c.Client.RequireSupervisedRemoval) + `
  <key>PayloadContent</key><array>
    <dict>
      <key>PayloadIdentifier</key><string>` + xmlEscape(profileID) + `.vpn</string>
      <key>PayloadUUID</key><string>` + vpnUUID + `</string>
      <key>PayloadType</key><string>com.apple.vpn.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadEnabled</key><true/>
      <key>PayloadDisplayName</key><string>` + xmlEscape(c.Client.DisplayName) + `</string>
      <key>UserDefinedName</key><string>` + xmlEscape(c.Client.DisplayName) + `</string>
      <key>VPNType</key><string>IKEv2</string>
      <key>IPv4</key><dict><key>ConfigMethod</key><string>Automatic</string></dict>
      <key>Proxies</key><dict/>
      <key>IKEv2</key>
      <dict>
        <key>RemoteAddress</key><string>` + xmlEscape(remoteAddr) + `</string>
        <key>RemoteIdentifier</key><string>` + xmlEscape(c.Server.Identity) + `</string>
        <key>AuthenticationMethod</key><string>Certificate</string>
        <key>ExtendedAuthEnabled</key><integer>1</integer>
`)
	// An empty LocalIdentifier is worse than no key at all: Apple reads the empty
	// string as "send an empty IKE ID" on some releases. The server matches on the
	// EAP identity, so omitting this is the safe default.
	if localIdentifier != "" {
		fmt.Fprintf(&b, "        <key>LocalIdentifier</key><string>%s</string>\n", xmlEscape(localIdentifier))
	}
	if issuerCN != "" {
		fmt.Fprintf(&b, "        <key>ServerCertificateIssuerCommonName</key><string>%s</string>\n", xmlEscape(issuerCN))
	}
	fmt.Fprintf(&b, "        <key>ServerCertificateCommonName</key><string>%s</string>\n", xmlEscape(serverCN))
	if authPassword != "" {
		fmt.Fprintf(&b, "        <key>AuthName</key><string>%s</string>\n", xmlEscape(u.Name))
		fmt.Fprintf(&b, "        <key>AuthPassword</key><string>%s</string>\n", xmlEscape(authPassword))
	} else if c.Client.PrefillsUsername() {
		// pre-fills the EAP identity so the user only types the password
		fmt.Fprintf(&b, "        <key>AuthName</key><string>%s</string>\n", xmlEscape(u.Name))
	}
	b.WriteString(`        <key>UseCertificateAsID</key><false/>
        <key>StrictFirstResponderCheck</key><true/>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key><string>` + enc + `</string>
          <key>IntegrityAlgorithm</key><string>` + integ + `</string>
          <key>DiffieHellmanGroup</key><integer>` + fmt.Sprint(group) + `</integer>
          <key>LifeTimeInMinutes</key><integer>` + fmt.Sprint(c.Tuning.RekeyMinutes()) + `</integer>
        </dict>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key><string>` + childEnc + `</string>
          <key>IntegrityAlgorithm</key><string>` + childInteg + `</string>
          <key>DiffieHellmanGroup</key><integer>` + fmt.Sprint(childGroup) + `</integer>
          <key>LifeTimeInMinutes</key><integer>` + fmt.Sprint(c.Tuning.ChildRekeyMinutes()) + `</integer>
        </dict>
      </dict>
    </dict>
    <dict>
      <key>PayloadIdentifier</key><string>` + xmlEscape(caID) + `</string>
      <key>PayloadUUID</key><string>` + caUUID + `</string>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>VPN CA</string>
      <key>PayloadContent</key><data>` + caData + `</data>
    </dict>
  </array>
</dict>
</plist>
`)
	return u.Name + "-" + u.Face + ".mobileconfig", b.String(), nil
}

func boolTag(v bool) string {
	if v {
		return "<true/>"
	}
	return "<false/>"
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
