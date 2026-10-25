package linkgrant

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	network "github.com/v57/hub-net-node/models"
)

func signed(t *testing.T, mutate func(*network.PeerLinkGrant)) (network.PeerLinkGrant, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(public)
	now := time.Now().UTC()
	grant := network.PeerLinkGrant{
		Version: network.WireVersion, GrantID: "g", HubKey: base64.StdEncoding.EncodeToString(der), HubNetworkID: "n",
		Purpose: network.PeerLinkPurposeHub,
		A:       network.PeerLinkSide{Key: "a", WireGuardKey: "wa", Addresses: []string{"100.96.0.1"}},
		B:       network.PeerLinkSide{Key: "b", WireGuardKey: "wb", Addresses: []string{"100.96.0.2"}},
		AViaB:   []string{"100.96.0.2/32"}, BViaA: []string{"100.96.0.1/32"},
		AToB: []network.PeerLinkPort{{Protocol: "tcp", Port: 1997}}, BToA: []network.PeerLinkPort{},
		IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	if mutate != nil {
		mutate(&grant)
	}
	grant.Signature, err = network.SignEnvelope(network.PurposePeerLink, grant, private)
	if err != nil {
		t.Fatal(err)
	}
	return grant, private
}

func TestVerifyAcceptsASignedGrant(t *testing.T) {
	grant, _ := signed(t, nil)
	if err := (Verifier{}).Verify(grant); err != nil {
		t.Fatal(err)
	}
	if other, ok := Other(grant, "a"); !ok || other.Key != "b" {
		t.Fatalf("Other(a) = %+v, %v", other, ok)
	}
	if _, ok := Other(grant, "c"); ok {
		t.Fatal("a stranger is a side")
	}
}

func TestVerifyRejectsTamperingAndBadShapes(t *testing.T) {
	cases := map[string]func(*network.PeerLinkGrant){
		"same key both sides": func(g *network.PeerLinkGrant) { g.B.Key = g.A.Key },
		"same wireguard key":  func(g *network.PeerLinkGrant) { g.B.WireGuardKey = g.A.WireGuardKey },
		"unknown purpose":     func(g *network.PeerLinkGrant) { g.Purpose = "relay" },
		"over a month": func(g *network.PeerLinkGrant) {
			g.ExpiresAt = time.Now().Add(40 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
		},
		"expired": func(g *network.PeerLinkGrant) {
			g.IssuedAt = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
			g.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		},
	}
	for name, mutate := range cases {
		grant, _ := signed(t, mutate)
		if err := (Verifier{}).Verify(grant); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Verify = %v", name, err)
		}
	}
	grant, _ := signed(t, nil)
	grant.AViaB = []string{"0.0.0.0/0"}
	if err := (Verifier{}).Verify(grant); !errors.Is(err, ErrInvalid) {
		t.Errorf("routes changed after signing: Verify = %v", err)
	}
	other, _ := signed(t, nil)
	grant, _ = signed(t, nil)
	grant.HubKey = other.HubKey
	if err := (Verifier{}).Verify(grant); !errors.Is(err, ErrInvalid) {
		t.Errorf("hub key swapped: Verify = %v", err)
	}
}
