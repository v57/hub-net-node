// Package testticket builds Hub-signed rendezvous tickets for tests across
// hub-net-node packages.
//
// It mirrors the signing flow in ticket/verifier_test.go but is importable by
// the server and session packages so their end-to-end tests can produce
// tickets the real ticket.Verifier accepts. Production code never imports this
// package — it lives under internal/ to enforce that.
package testticket

import (
	"testing"
	"time"

	"github.com/v57/hub-net-node/identity"
	network "github.com/v57/hub-net-node/models"
)

// Signed builds one valid ticket bound to nodeID, signed by a fresh Hub key.
// key/networkID identify the opener; distinct agents sharing a
// network id are how the node pairs two sessions.
func Signed(t *testing.T, now time.Time, nodeID, networkID, key string) network.RendezvousTicket {
	return SignedWithID(t, now, nodeID, networkID, key, "ticket-"+key)
}

// SignedWithID builds a valid ticket with an explicit identifier.
func SignedWithID(t *testing.T, now time.Time, nodeID, networkID, key, ticketID string) network.RendezvousTicket {
	t.Helper()
	hub, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := hub.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	ticket := network.RendezvousTicket{
		Version:        network.WireVersion,
		TicketID:       ticketID,
		HubKey:         hubKey,
		HubNetworkID:   networkID,
		Key:            key,
		NodeID:         nodeID,
		Roles:          []string{"rendezvous"},
		SessionPurpose: "peer-connect",
		IssuedAt:       now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt:      now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	ticket.Signature, err = network.SignEnvelope(
		network.PurposeRendezvousTicket,
		ticket,
		hub.PrivateKey(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}
