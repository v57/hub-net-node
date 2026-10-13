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
	MessageOpenSession         MessageType = "session.open"
	MessageSessionOpened       MessageType = "session.opened"
	MessageOfferCandidate      MessageType = "candidate.offer"
	MessageCandidates          MessageType = "candidate.list"
	MessageCloseSession        MessageType = "session.close"
	MessageError               MessageType = "error"
	MessageRegisterInviter     MessageType = "inviter.register"
	MessageInviterChallenge    MessageType = "inviter.challenge"
	MessageInviterRegistered   MessageType = "inviter.registered"
	MessageInviterUnregistered MessageType = "inviter.unregistered"
	// MessageBootstrapPending is pushed by the node to a registered inviter
	// when a joiner opens a session with one of its invitations. It carries
	// the transaction identity and the invitation code so the inviter can
	// probe and open its own side of the paired session on the same
	// registration connection.
	MessageBootstrapPending MessageType = "inviter.bootstrap"
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

// UDPProbe is a bounded authenticated datagram sent to the node before
// session.open. The ticket binds the observation to one Hub, network, profile,
// agent, and node without trusting any client-declared address or port.
type UDPProbe struct {
	Version int                      `json:"version"`
	Ticket  network.RendezvousTicket `json:"ticket"`
}

// UDPProbeResponse confirms that the node recorded the datagram source. It
// deliberately does not echo the observed endpoint; that endpoint is released
// only to the authenticated matched peer through candidate.list.
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
	MajorVersion   int                       `json:"majorVersion"`
	MinorVersion   int                       `json:"minorVersion"`
	Type           MessageType               `json:"type"`
	RequestID      string                    `json:"requestId,omitempty"`
	Ticket         *network.RendezvousTicket `json:"ticket,omitempty"`
	SessionID      string                    `json:"sessionId,omitempty"`
	Candidate      *network.Candidate        `json:"candidate,omitempty"`
	Candidates     []network.Candidate       `json:"candidates,omitempty"`
	Observed       *ObservedEndpoint         `json:"observedEndpoint,omitempty"`
	Error          *network.NetworkError     `json:"error,omitempty"`
	InvitationCode string                    `json:"invitationCode,omitempty"`
	Key            string                    `json:"key,omitempty"`
	TokenDigest    string                    `json:"tokenDigest,omitempty"`
	TransactionID  string                    `json:"transactionId,omitempty"`
	TunnelInstance string                    `json:"tunnelInstanceId,omitempty"`
	Generation     uint64                    `json:"generation,omitempty"`
	// ServiceKey is the base64 SPKI service public key of a registering inviter.
	// It is the same key that signs the inviter's compact invitations.
	ServiceKey string `json:"serviceKey,omitempty"`
	// ChallengeNonce is the base64url random nonce the node issues for the
	// online-inviter registration challenge.
	ChallengeNonce string `json:"challengeNonce,omitempty"`
	// ChallengeSignature is the base64 Ed25519 signature over the nonce under
	// the inviter-registration domain, proving possession of the service key.
	ChallengeSignature string `json:"challengeSignature,omitempty"`
	// RegistrationExpiresAt is the RFC3339 time at which the registration lease
	// expires; returned in inviter.registered.
	RegistrationExpiresAt string `json:"registrationExpiresAt,omitempty"`
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
	if len(message.Candidates) > limits.MaxCandidates {
		return errors.New("candidate limit exceeded")
	}
	switch message.Type {
	case MessageOpenSession:
		if (message.Ticket == nil) == (message.InvitationCode == "") {
			return errors.New("session.open requires exactly one ticket or invitation")
		}
		if message.SessionID != "" || message.Candidate != nil || len(message.Candidates) != 0 || message.Observed != nil {
			return errors.New("session.open contains invalid fields")
		}
		if message.Ticket != nil && message.Key != "" {
			return errors.New("ticket session contains bootstrap fields")
		}
		if message.Ticket != nil {
			if expiresAt, err := time.Parse(time.RFC3339Nano, message.Ticket.ExpiresAt); err != nil || !expiresAt.After(now) {
				return errors.New("ticket is expired or invalid")
			}
		}
		if message.InvitationCode != "" && message.Key == "" {
			return errors.New("invitation bootstrap requires key")
		}
		if message.InvitationCode != "" && (message.TokenDigest == "" || message.TransactionID == "") {
			return errors.New("invitation bootstrap requires token digest and transaction")
		}
	case MessageSessionOpened:
		if message.InvitationCode != "" || message.Key != "" || message.TokenDigest != "" || message.TransactionID != "" || message.TunnelInstance != "" || message.Generation != 0 {
			return errors.New("session.opened contains bootstrap fields")
		}
		if message.SessionID == "" {
			return errors.New("session.opened requires a session id")
		}
	case MessageOfferCandidate:
		if message.InvitationCode != "" || message.Key != "" || message.TokenDigest != "" || message.TransactionID != "" || message.TunnelInstance != "" || message.Generation != 0 {
			return errors.New("candidate.offer contains bootstrap fields")
		}
		if message.SessionID == "" || message.Candidate == nil {
			return errors.New("candidate.offer requires a session and candidate")
		}
		if message.Candidate.SessionID != message.SessionID {
			return errors.New("candidate session mismatch")
		}
	case MessageCandidates:
		if message.InvitationCode != "" || message.Key != "" || message.TokenDigest != "" || message.TransactionID != "" || message.TunnelInstance != "" || message.Generation != 0 {
			return errors.New("candidate.list contains bootstrap fields")
		}
		if message.SessionID == "" {
			return errors.New("candidate.list requires a session")
		}
		if message.Observed == nil || message.Observed.Version != network.WireVersion ||
			message.Observed.Key == "" || message.Observed.Transport != "udp" ||
			message.Observed.Address == "" || message.Observed.Port == 0 {
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
	case MessageCloseSession:
		if message.InvitationCode != "" || message.Key != "" || message.TokenDigest != "" || message.TransactionID != "" || message.TunnelInstance != "" || message.Generation != 0 {
			return errors.New("session.close contains bootstrap fields")
		}
		if message.SessionID == "" {
			return errors.New("session.close requires a session")
		}
	case MessageError:
		if message.Error == nil {
			return errors.New("error message requires an error")
		}
	case MessageRegisterInviter:
		// A register request either requests a challenge (serviceKey only) or
		// answers one (serviceKey + challengeNonce + challengeSignature).
		if message.ServiceKey == "" {
			return errors.New("inviter.register requires a service key")
		}
		if message.hasSessionOrBootstrapFields() || message.Error != nil ||
			message.Ticket != nil || message.Candidate != nil || len(message.Candidates) != 0 ||
			message.SessionID != "" || message.Observed != nil || message.RegistrationExpiresAt != "" {
			return errors.New("inviter.register contains invalid fields")
		}
		if (message.ChallengeNonce == "") != (message.ChallengeSignature == "") {
			return errors.New("inviter.register requires both nonce and signature or neither")
		}
	case MessageInviterChallenge, MessageInviterRegistered, MessageInviterUnregistered:
		if message.ServiceKey == "" {
			return errors.New("inviter message requires a service key")
		}
		if message.hasSessionOrBootstrapFields() || message.Error != nil ||
			message.Ticket != nil || message.Candidate != nil || len(message.Candidates) != 0 ||
			message.SessionID != "" || message.Observed != nil || message.ChallengeSignature != "" {
			return errors.New("inviter message contains invalid fields")
		}
		if message.Type == MessageInviterChallenge && message.ChallengeNonce == "" {
			return errors.New("inviter.challenge requires a nonce")
		}
		if message.Type == MessageInviterChallenge && message.RegistrationExpiresAt != "" {
			return errors.New("inviter.challenge contains invalid fields")
		}
		if message.Type == MessageInviterRegistered && message.RegistrationExpiresAt == "" {
			return errors.New("inviter.registered requires an expiry")
		}
		if message.Type == MessageInviterRegistered && message.ChallengeNonce != "" {
			return errors.New("inviter.registered contains invalid fields")
		}
		if message.Type == MessageInviterUnregistered &&
			(message.ChallengeNonce != "" || message.RegistrationExpiresAt != "") {
			return errors.New("inviter.unregistered contains invalid fields")
		}
	case MessageBootstrapPending:
		// inviter.bootstrap is a node-to-agent push. A client sending it is
		// rejected unless the envelope carries exactly the bootstrap fields
		// the node includes; no session, ticket, candidate, registration, or
		// error fields may accompany it.
		if message.InvitationCode == "" || message.Key == "" ||
			message.TokenDigest == "" || message.TransactionID == "" {
			return errors.New("inviter.bootstrap requires code, key, digest, and transaction")
		}
		if message.SessionID != "" || message.Ticket != nil || message.Candidate != nil ||
			len(message.Candidates) != 0 || message.Observed != nil || message.Error != nil ||
			message.ServiceKey != "" || message.ChallengeNonce != "" ||
			message.ChallengeSignature != "" || message.RegistrationExpiresAt != "" {
			return errors.New("inviter.bootstrap contains invalid fields")
		}
	default:
		return fmt.Errorf("unsupported message type %q", message.Type)
	}
	return nil
}

// hasSessionOrBootstrapFields reports whether the envelope carries any of the
// invitation-bootstrap or transaction fields that are invalid for inviter
// registration messages.
func (message Envelope) hasSessionOrBootstrapFields() bool {
	return message.InvitationCode != "" || message.Key != "" || message.TokenDigest != "" ||
		message.TransactionID != "" || message.TunnelInstance != "" || message.Generation != 0
}
