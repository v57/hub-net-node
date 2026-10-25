package protocol

import (
	"errors"
	"fmt"
	"time"

	network "github.com/v57/hub-net-node/models"
)

const (
	MajorVersion = 1
	MinorVersion = 0

	DefaultMaxSessionsPerAgent = 16
	DefaultMaxCandidates       = 16
	DefaultMaxMessageBytes     = 16 * 1024
	DefaultMessagesPerSecond   = 20
	DefaultSessionLifetime     = 2 * time.Minute
	DefaultCandidateLifetime   = 30 * time.Second
	// DefaultRegistrationLifetime bounds the online inviter registration lease.
	// An agent refreshes by re-running the challenge handshake before expiry;
	// the lease mirrors the session lifetime so a registered inviter that drops
	// is reclaimed on the same cadence as an abandoned session.
	DefaultRegistrationLifetime = 2 * time.Minute
)

type Role string

const RoleRendezvous Role = "rendezvous"

type Limits struct {
	MaxSessionsPerAgent int           `json:"maxSessionsPerAgent"`
	MaxCandidates       int           `json:"maxCandidates"`
	MaxMessageBytes     int           `json:"maxMessageBytes"`
	MessagesPerSecond   int           `json:"messagesPerSecond"`
	SessionLifetime     time.Duration `json:"-"`
	CandidateLifetime   time.Duration `json:"-"`
	SessionLifetimeMS   int64         `json:"sessionLifetimeMs"`
	CandidateLifetimeMS int64         `json:"candidateLifetimeMs"`
}

func DefaultLimits() Limits {
	return Limits{
		MaxSessionsPerAgent: DefaultMaxSessionsPerAgent,
		MaxCandidates:       DefaultMaxCandidates,
		MaxMessageBytes:     DefaultMaxMessageBytes,
		MessagesPerSecond:   DefaultMessagesPerSecond,
		SessionLifetime:     DefaultSessionLifetime,
		CandidateLifetime:   DefaultCandidateLifetime,
		SessionLifetimeMS:   DefaultSessionLifetime.Milliseconds(),
		CandidateLifetimeMS: DefaultCandidateLifetime.Milliseconds(),
	}
}

type Capabilities struct {
	MajorVersion int    `json:"majorVersion"`
	MinorVersion int    `json:"minorVersion"`
	Roles        []Role `json:"roles"`
	Limits       Limits `json:"limits"`
}

func ServerCapabilities(limits Limits) Capabilities {
	return Capabilities{
		MajorVersion: MajorVersion,
		MinorVersion: MinorVersion,
		Roles:        []Role{RoleRendezvous},
		Limits:       limits,
	}
}

type MessageType string

const (
	// Invitation bootstrap, the first-contact path for a device that has no grant yet
	MessageOpenSession      MessageType = "session.open"
	MessageSessionOpened    MessageType = "session.opened"
	MessageOfferCandidate   MessageType = "candidate.offer"
	MessageCandidates       MessageType = "candidate.list"
	MessageCloseSession     MessageType = "session.close"
	MessageBootstrapPending MessageType = "inviter.bootstrap"
	MessageError            MessageType = "error"

	// Presence: a device that wants to be reachable proves its service key and keeps the lease
	MessagePresenceRegister     MessageType = "presence.register"
	MessagePresenceChallenge    MessageType = "presence.challenge"
	MessagePresenceRegistered   MessageType = "presence.registered"
	MessagePresenceUnregistered MessageType = "presence.unregistered"

	// Peer links between two present devices of a hub, named by a hub-signed grant
	MessageLinkOpen     MessageType = "link.open"
	MessageLinkOpened   MessageType = "link.opened"
	MessageLinkIncoming MessageType = "link.incoming"
	MessageLinkAccept   MessageType = "link.accept"
	MessageLinkReject   MessageType = "link.reject"
	MessageLinkOffer    MessageType = "link.offer"
	MessageLinkReady    MessageType = "link.ready"
	MessageLinkClose    MessageType = "link.close"
	MessageLinkClosed   MessageType = "link.closed"
)

// ObservedEndpoint is node-measured transport metadata, kept separate from
// client-declared candidates. Shape matches shared Hub Network v1 model.
type ObservedEndpoint struct {
	Version   int    `json:"version"`
	Key       string `json:"key"`
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Port      uint16 `json:"port"`
}

// LinkUDPProbe is the datagram a device sends to the node from its WireGuard socket so the node can see the NAT
// mapping the peer has to aim at. The probe token is the side's own secret from link.opened or link.incoming.
type LinkUDPProbe struct {
	Version    int    `json:"version"`
	LinkID     string `json:"linkId"`
	ProbeToken string `json:"probeToken"`
}

// LinkUDPProbeResponse confirms the observation without echoing the endpoint.
type LinkUDPProbeResponse struct {
	Version int    `json:"version"`
	LinkID  string `json:"linkId"`
}

// UDPProbeResponse confirms an invitation probe. It deliberately does not echo
// the observed endpoint; that endpoint is released only to the matched peer.
type UDPProbeResponse struct {
	Version  int    `json:"version"`
	TicketID string `json:"ticketId"`
}

// InvitationUDPProbe authenticates endpoint observation for invitation
// bootstrap from the same UDP socket that will carry WireGuard.
type InvitationUDPProbe struct {
	Version          int    `json:"version"`
	InvitationCode   string `json:"invitationCode"`
	Key              string `json:"key"`
	TokenDigest      string `json:"tokenDigest"`
	TransactionID    string `json:"transactionId"`
	TunnelInstanceID string `json:"tunnelInstanceId,omitempty"`
	Generation       uint64 `json:"generation,omitempty"`
}

// Envelope deliberately has no payload or data field. The rendezvous protocol
// accepts only the bounded coordination fields associated with its message type.
type Envelope struct {
	MajorVersion   int                   `json:"majorVersion"`
	MinorVersion   int                   `json:"minorVersion"`
	Type           MessageType           `json:"type"`
	RequestID      string                `json:"requestId,omitempty"`
	SessionID      string                `json:"sessionId,omitempty"`
	Candidate      *network.Candidate    `json:"candidate,omitempty"`
	Candidates     []network.Candidate   `json:"candidates,omitempty"`
	Observed       *ObservedEndpoint     `json:"observedEndpoint,omitempty"`
	Error          *network.NetworkError `json:"error,omitempty"`
	InvitationCode string                `json:"invitationCode,omitempty"`
	Key            string                `json:"key,omitempty"`
	TokenDigest    string                `json:"tokenDigest,omitempty"`
	TransactionID  string                `json:"transactionId,omitempty"`
	TunnelInstance string                `json:"tunnelInstanceId,omitempty"`
	Generation     uint64                `json:"generation,omitempty"`
	// ServiceKey is the base64 SPKI service public key a device registers presence with.
	ServiceKey string `json:"serviceKey,omitempty"`
	// ChallengeNonce is the base64url random nonce the node issues for the presence challenge.
	ChallengeNonce string `json:"challengeNonce,omitempty"`
	// ChallengeSignature is the base64 Ed25519 signature over the nonce under the presence domain.
	ChallengeSignature string `json:"challengeSignature,omitempty"`
	// RegistrationExpiresAt is the RFC3339 end of the presence lease; returned in presence.registered.
	RegistrationExpiresAt string `json:"registrationExpiresAt,omitempty"`
	// Grant is the hub-signed peer link grant, in link.open and link.incoming only.
	Grant *network.PeerLinkGrant `json:"grant,omitempty"`
	// LinkID names one link the node is introducing.
	LinkID string `json:"linkId,omitempty"`
	// ProbeToken is the receiving side's own secret for its UDP probe.
	ProbeToken string `json:"probeToken,omitempty"`
	// PeerKey is the other side's service key.
	PeerKey string `json:"peerKey,omitempty"`
	// Endpoints are a side's declared candidates (link.offer) or the peer's (link.ready).
	Endpoints []network.LinkEndpoint `json:"endpoints,omitempty"`
	// PunchAt is the RFC3339 time both sides start their handshakes toward each other.
	PunchAt string `json:"punchAt,omitempty"`
}

// allowedFields lists, per message type, the optional fields it may carry; anything else is rejected, so no message
// can smuggle data in a field meant for another.
var allowedFields = map[MessageType][]string{
	MessageOpenSession:          {"requestId", "invitationCode", "key", "tokenDigest", "transactionId", "tunnelInstanceId", "generation"},
	MessageSessionOpened:        {"requestId", "sessionId"},
	MessageOfferCandidate:       {"requestId", "sessionId", "candidate"},
	MessageCandidates:           {"sessionId", "candidates", "observedEndpoint"},
	MessageCloseSession:         {"requestId", "sessionId"},
	MessageBootstrapPending:     {"invitationCode", "key", "tokenDigest", "transactionId", "tunnelInstanceId", "generation"},
	MessageError:                {"requestId", "error", "linkId", "sessionId"},
	MessagePresenceRegister:     {"requestId", "serviceKey", "challengeNonce", "challengeSignature"},
	MessagePresenceChallenge:    {"requestId", "serviceKey", "challengeNonce"},
	MessagePresenceRegistered:   {"requestId", "serviceKey", "registrationExpiresAt"},
	MessagePresenceUnregistered: {"serviceKey"},
	MessageLinkOpen:             {"requestId", "grant"},
	MessageLinkOpened:           {"requestId", "linkId", "probeToken", "peerKey"},
	MessageLinkIncoming:         {"linkId", "grant", "probeToken", "peerKey"},
	MessageLinkAccept:           {"requestId", "linkId"},
	MessageLinkReject:           {"requestId", "linkId", "error"},
	MessageLinkOffer:            {"requestId", "linkId", "endpoints"},
	MessageLinkReady:            {"linkId", "peerKey", "observedEndpoint", "endpoints", "punchAt"},
	MessageLinkClose:            {"requestId", "linkId"},
	MessageLinkClosed:           {"linkId", "error"},
}

// presentFields names the optional fields that are set.
func (message Envelope) presentFields() []string {
	var present []string
	add := func(name string, set bool) {
		if set {
			present = append(present, name)
		}
	}
	add("requestId", message.RequestID != "")
	add("sessionId", message.SessionID != "")
	add("candidate", message.Candidate != nil)
	add("candidates", len(message.Candidates) != 0)
	add("observedEndpoint", message.Observed != nil)
	add("error", message.Error != nil)
	add("invitationCode", message.InvitationCode != "")
	add("key", message.Key != "")
	add("tokenDigest", message.TokenDigest != "")
	add("transactionId", message.TransactionID != "")
	add("tunnelInstanceId", message.TunnelInstance != "")
	add("generation", message.Generation != 0)
	add("serviceKey", message.ServiceKey != "")
	add("challengeNonce", message.ChallengeNonce != "")
	add("challengeSignature", message.ChallengeSignature != "")
	add("registrationExpiresAt", message.RegistrationExpiresAt != "")
	add("grant", message.Grant != nil)
	add("linkId", message.LinkID != "")
	add("probeToken", message.ProbeToken != "")
	add("peerKey", message.PeerKey != "")
	add("endpoints", len(message.Endpoints) != 0)
	add("punchAt", message.PunchAt != "")
	return present
}

func (message Envelope) Validate(now time.Time, limits Limits) error {
	if message.MajorVersion != MajorVersion {
		return fmt.Errorf("unsupported major version %d", message.MajorVersion)
	}
	if message.MinorVersion > MinorVersion {
		return fmt.Errorf("unsupported minor version %d", message.MinorVersion)
	}
	if message.Type == "" {
		return errors.New("missing message type")
	}
	allowed, known := allowedFields[message.Type]
	if !known {
		return fmt.Errorf("unsupported message type %q", message.Type)
	}
	for _, field := range message.presentFields() {
		if !contains(allowed, field) {
			return fmt.Errorf("%s contains invalid field %s", message.Type, field)
		}
	}
	if len(message.Candidates) > limits.MaxCandidates || len(message.Endpoints) > limits.MaxCandidates {
		return errors.New("candidate limit exceeded")
	}
	switch message.Type {
	case MessageOpenSession:
		if message.InvitationCode == "" || message.Key == "" || message.TokenDigest == "" || message.TransactionID == "" {
			return errors.New("invitation bootstrap requires code, key, token digest and transaction")
		}
	case MessageSessionOpened, MessageCloseSession:
		if message.SessionID == "" {
			return fmt.Errorf("%s requires a session id", message.Type)
		}
	case MessageOfferCandidate:
		if message.SessionID == "" || message.Candidate == nil {
			return errors.New("candidate.offer requires a session and candidate")
		}
		if message.Candidate.SessionID != message.SessionID {
			return errors.New("candidate session mismatch")
		}
	case MessageCandidates:
		if message.SessionID == "" {
			return errors.New("candidate.list requires a session")
		}
		if !validObserved(message.Observed) {
			return errors.New("candidate.list requires a valid observed endpoint")
		}
		for _, candidate := range message.Candidates {
			if candidate.SessionID != message.SessionID {
				return errors.New("candidate session mismatch")
			}
			if candidate.Key != message.Observed.Key {
				return errors.New("candidate and observed endpoint agent mismatch")
			}
		}
	case MessageBootstrapPending:
		if message.InvitationCode == "" || message.Key == "" || message.TokenDigest == "" || message.TransactionID == "" {
			return errors.New("inviter.bootstrap requires code, key, digest, and transaction")
		}
	case MessageError:
		if message.Error == nil {
			return errors.New("error message requires an error")
		}
	case MessagePresenceRegister:
		if message.ServiceKey == "" {
			return errors.New("presence.register requires a service key")
		}
		if (message.ChallengeNonce == "") != (message.ChallengeSignature == "") {
			return errors.New("presence.register requires both nonce and signature or neither")
		}
	case MessagePresenceChallenge:
		if message.ServiceKey == "" || message.ChallengeNonce == "" {
			return errors.New("presence.challenge requires a service key and a nonce")
		}
	case MessagePresenceRegistered:
		if message.ServiceKey == "" || message.RegistrationExpiresAt == "" {
			return errors.New("presence.registered requires a service key and an expiry")
		}
	case MessagePresenceUnregistered:
		if message.ServiceKey == "" {
			return errors.New("presence.unregistered requires a service key")
		}
	case MessageLinkOpen:
		if message.Grant == nil {
			return errors.New("link.open requires a grant")
		}
	case MessageLinkOpened:
		if message.LinkID == "" || message.ProbeToken == "" || message.PeerKey == "" {
			return errors.New("link.opened requires a link, probe token and peer")
		}
	case MessageLinkIncoming:
		if message.LinkID == "" || message.Grant == nil || message.ProbeToken == "" || message.PeerKey == "" {
			return errors.New("link.incoming requires a link, grant, probe token and peer")
		}
	case MessageLinkAccept, MessageLinkReject, MessageLinkOffer, MessageLinkClose, MessageLinkClosed:
		if message.LinkID == "" {
			return fmt.Errorf("%s requires a link id", message.Type)
		}
	case MessageLinkReady:
		if message.LinkID == "" || message.PeerKey == "" || message.PunchAt == "" || !validObserved(message.Observed) {
			return errors.New("link.ready requires a link, peer, observed endpoint and punch time")
		}
	}
	return nil
}

func validObserved(observed *ObservedEndpoint) bool {
	return observed != nil && observed.Version == network.WireVersion && observed.Key != "" &&
		observed.Transport == "udp" && observed.Address != "" && observed.Port != 0
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
