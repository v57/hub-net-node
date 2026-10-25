// Package linkgrant checks hub-signed peer link grants.
//
// A grant carries the signing hub's SPKI key, so a public node can check grants from self-hosted hubs without a hub
// registry. That check is only an abuse gate: the node forwards a grant to the device it names, and that device
// checks it again against the hub key it pinned and decides on its own whether to accept the link.
package linkgrant

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	network "github.com/v57/hub-net-node/models"
)

var ErrInvalid = errors.New("linkgrant: invalid peer link grant")

// Verifier checks grants against a clock; zero value uses time.Now.
type Verifier struct {
	Now func() time.Time
}

// Verify checks shape, lifetime and signature. It does not decide who may talk: a device does.
func (v Verifier) Verify(grant network.PeerLinkGrant) error {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if grant.Version != network.WireVersion || grant.GrantID == "" || grant.HubKey == "" || grant.HubNetworkID == "" {
		return ErrInvalid
	}
	switch grant.Purpose {
	case network.PeerLinkPurposeHub, network.PeerLinkPurposeGateway, network.PeerLinkPurposeShare:
	default:
		return fmt.Errorf("%w: unsupported purpose", ErrInvalid)
	}
	if grant.A.Key == "" || grant.B.Key == "" || grant.A.Key == grant.B.Key ||
		grant.A.WireGuardKey == "" || grant.B.WireGuardKey == "" || grant.A.WireGuardKey == grant.B.WireGuardKey {
		return fmt.Errorf("%w: sides", ErrInvalid)
	}
	if !network.HasValidLifetime(grant.IssuedAt, grant.ExpiresAt, network.PeerLinkGrantMaxLifetime, now) {
		return fmt.Errorf("%w: expired or invalid lifetime", ErrInvalid)
	}
	publicKey, err := parseHubKey(grant.HubKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	valid, err := network.VerifyEnvelope(network.PurposePeerLink, grant, publicKey, grant.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature: %v", ErrInvalid, err)
	}
	if !valid {
		return fmt.Errorf("%w: signature mismatch", ErrInvalid)
	}
	return nil
}

// Other returns the side of the grant that isn't key, and whether key is a side at all.
func Other(grant network.PeerLinkGrant, key string) (network.PeerLinkSide, bool) {
	switch key {
	case grant.A.Key:
		return grant.B, true
	case grant.B.Key:
		return grant.A, true
	default:
		return network.PeerLinkSide{}, false
	}
}

func parseHubKey(encoded string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid hub key encoding")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("invalid hub SPKI key")
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("hub key is not Ed25519")
	}
	return publicKey, nil
}
