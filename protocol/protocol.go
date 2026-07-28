package protocol

import (
	"errors"
	"fmt"
	"time"

	network "github.com/v57/hub-service-go/protocol"
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
	MessageOpenSession    MessageType = "session.open"
	MessageSessionOpened  MessageType = "session.opened"
	MessageOfferCandidate MessageType = "candidate.offer"
	MessageCandidates     MessageType = "candidate.list"
	MessageCloseSession   MessageType = "session.close"
	MessageError          MessageType = "error"
)

// ObservedEndpoint is node-measured transport metadata, kept separate from
// client-declared candidates. Shape matches shared Hub Network v1 model.
type ObservedEndpoint struct {
	Version   int    `json:"version"`
	AgentKey  string `json:"agentKey"`
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

// Envelope deliberately has no payload or data field. The rendezvous protocol
// accepts only the bounded coordination fields associated with its message type.
type Envelope struct {
	MajorVersion int                       `json:"majorVersion"`
	MinorVersion int                       `json:"minorVersion"`
	Type         MessageType               `json:"type"`
	RequestID    string                    `json:"requestId,omitempty"`
	Ticket       *network.RendezvousTicket `json:"ticket,omitempty"`
	SessionID    string                    `json:"sessionId,omitempty"`
	Candidate    *network.Candidate        `json:"candidate,omitempty"`
	Candidates   []network.Candidate       `json:"candidates,omitempty"`
	Observed     *ObservedEndpoint         `json:"observedEndpoint,omitempty"`
	Error        *network.NetworkError     `json:"error,omitempty"`
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
		if message.Ticket == nil {
			return errors.New("session.open requires a ticket")
		}
		if message.SessionID != "" || message.Candidate != nil || len(message.Candidates) != 0 || message.Observed != nil {
			return errors.New("session.open contains invalid fields")
		}
		if expiresAt, err := time.Parse(time.RFC3339Nano, message.Ticket.ExpiresAt); err != nil || !expiresAt.After(now) {
			return errors.New("ticket is expired or invalid")
		}
	case MessageSessionOpened:
		if message.SessionID == "" {
			return errors.New("session.opened requires a session id")
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
		if message.Observed == nil || message.Observed.Version != network.WireVersion ||
			message.Observed.AgentKey == "" || message.Observed.Transport != "udp" ||
			message.Observed.Address == "" || message.Observed.Port == 0 {
			return errors.New("candidate.list requires a valid observed endpoint")
		}
		for _, candidate := range message.Candidates {
			if candidate.SessionID != message.SessionID {
				return errors.New("candidate session mismatch")
			}
			if candidate.AgentKey != message.Observed.AgentKey {
				return errors.New("candidate and observed endpoint agent mismatch")
			}
		}
	case MessageCloseSession:
		if message.SessionID == "" {
			return errors.New("session.close requires a session")
		}
	case MessageError:
		if message.Error == nil {
			return errors.New("error message requires an error")
		}
	default:
		return fmt.Errorf("unsupported message type %q", message.Type)
	}
	return nil
}
