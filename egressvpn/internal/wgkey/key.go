package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenKeyPair returns a WireGuard keypair. The private key is clamped the way
// `wg genkey` does, so the published key matches what wg-quick expects.
func GenKeyPair() (priv, pub string, err error) {
	var raw [32]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return "", "", fmt.Errorf("read random: %w", err)
	}
	clamp(raw[:])
	return encode(raw[:])
}

// PublicKeyOf derives the public key from a base64 private key, clamping the
// input first so a hand-edited unclamped key still yields wg's answer.
func PublicKeyOf(privateKey string) (string, error) {
	raw, err := decode(privateKey)
	if err != nil {
		return "", err
	}
	clamp(raw)
	_, pub, err := encode(raw)
	return pub, err
}

// ValidatePeerPublicKey rejects a peer key that would silently break the tunnel.
// A low-order point yields a predictable shared secret, i.e. encryption that
// looks configured but has no secrecy; crypto/ecdh refuses to ECDH against one,
// so probing the operation is the check.
func ValidatePeerPublicKey(publicKey string) error {
	raw, err := decode(publicKey)
	if err != nil {
		return fmt.Errorf("peer public key: %w", err)
	}
	probe, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("generate probe key: %w", err)
	}
	peer, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return fmt.Errorf("peer public key rejected: %w", err)
	}
	if _, err = probe.ECDH(peer); err != nil {
		return fmt.Errorf("peer public key rejected: %w", err)
	}
	return nil
}

func decode(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad base64: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

func encode(raw []byte) (priv, pub string, err error) {
	sk, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", "", fmt.Errorf("unusable private key, regenerate: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes()), nil
}

func GenPSK() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

func clamp(raw []byte) {
	raw[0] &= 248
	raw[31] &= 127
	raw[31] |= 64
}
