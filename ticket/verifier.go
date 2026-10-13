// Package ticket validates Hub-signed rendezvous tickets.
//
// Tickets carry the signing Hub's SPKI public key. This lets a public node
// validate tickets from self-hosted Hubs without maintaining a Hub registry.
// Agents still decide which Hubs they trust; the node is only an abuse gate.
package ticket

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	network "github.com/v57/hub-net-node/models"
)

var ErrInvalid = errors.New("ticket: invalid rendezvous ticket")

// Verifier validates tickets for one node. Empty NodeID accepts any signed
// node binding, useful before an operator assigns a stable deployment ID.
type Verifier struct {
	NodeID string
	Now    func() time.Time
}

func (v Verifier) Verify(ticket network.RendezvousTicket) error {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if ticket.Version != network.WireVersion ||
		ticket.TicketID == "" ||
		ticket.HubKey == "" ||
		ticket.HubNetworkID == "" ||
		ticket.Key == "" ||
		ticket.NodeID == "" ||
		ticket.SessionPurpose != "peer-connect" {
		return ErrInvalid
	}
	if v.NodeID != "" && ticket.NodeID != v.NodeID {
		return fmt.Errorf("%w: node binding mismatch", ErrInvalid)
	}
	if len(ticket.Roles) != 1 || ticket.Roles[0] != "rendezvous" {
		return fmt.Errorf("%w: unsupported roles", ErrInvalid)
	}
	if !network.HasValidLifetime(
		ticket.IssuedAt,
		ticket.ExpiresAt,
		network.RendezvousTicketMaxLifetime,
		now,
	) {
		return fmt.Errorf("%w: expired or invalid lifetime", ErrInvalid)
	}
	publicKey, err := parseHubKey(ticket.HubKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	valid, err := network.VerifyEnvelope(
		network.PurposeRendezvousTicket,
		ticket,
		publicKey,
		ticket.Signature,
	)
	if err != nil {
		return fmt.Errorf("%w: signature: %v", ErrInvalid, err)
	}
	if !valid {
		return fmt.Errorf("%w: signature mismatch", ErrInvalid)
	}
	return nil
}

func parseHubKey(encoded string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid Hub key encoding")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("invalid Hub SPKI key")
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Hub key is not Ed25519")
	}
	return publicKey, nil
}
