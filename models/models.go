package models

const WireVersion = 1

type Versioned struct {
	Version int `json:"version"`
}

type HubHeader struct {
	Name string `json:"name"`
}

type InvitationBootstrapScope struct {
	Audience string   `json:"audience"`
	Actions  []string `json:"actions"`
}

type NetworkInvitation struct {
	Version              int                        `json:"version"`
	SignatureDomain      string                     `json:"signatureDomain"`
	TokenID              string                     `json:"tokenId"`
	IssuedAt             string                     `json:"issuedAt"`
	ExpiresAt            string                     `json:"expiresAt"`
	HubKey               string                     `json:"hubKey"`
	InvitingKey          string                     `json:"invitingKey"`
	InvitingAgentAddress string                     `json:"invitingAgentAddress"`
	HubProHost           string                     `json:"hubProHost"`
	Node                 string                     `json:"node,omitempty"`
	Scopes               []InvitationBootstrapScope `json:"scopes"`
	Signature            string                     `json:"signature"`
}

type LocalTarget struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

type NetworkPolicy struct {
	Mode  string   `json:"mode"`
	Group string   `json:"group,omitempty"`
	Keys  []string `json:"keys,omitempty"`
}

type AgentAttestation struct {
	Version       int         `json:"version"`
	AttestationID string      `json:"attestationId"`
	ServiceKey    string      `json:"serviceKey"`
	Key           string      `json:"key"`
	ShareName     string      `json:"shareName"`
	Protocol      string      `json:"protocol"`
	Target        LocalTarget `json:"target"`
	IssuedAt      string      `json:"issuedAt"`
	ExpiresAt     string      `json:"expiresAt"`
	Signature     string      `json:"signature"`
}

type NetworkShare struct {
	Version     int              `json:"version"`
	Name        string           `json:"name"`
	Protocol    string           `json:"protocol"`
	Target      LocalTarget      `json:"target"`
	Policy      *NetworkPolicy   `json:"policy,omitempty"`
	Attestation AgentAttestation `json:"attestation"`
}

type NetworkSharePublication struct {
	Version        int    `json:"version"`
	ResourceID     string `json:"resourceId"`
	Authority      string `json:"authority"`
	ProviderID     string `json:"providerId"`
	Protocol       string `json:"protocol"`
	OverlayAddress string `json:"overlayAddress"`
	Port           uint16 `json:"port"`
}

type AgentProfile struct {
	Version          int      `json:"version"`
	Key              string   `json:"key"`
	WireGuardKey     string   `json:"wireGuardKey"`
	Name             string   `json:"name,omitempty"`
	Platform         string   `json:"platform,omitempty"`
	OverlayAddresses []string `json:"overlayAddresses"`
	ConnectedAt      string   `json:"connectedAt"`
	// Online is set in member lists (network/agents/list for the owner and
	// the hub host's agent): false for a known member that is not connected.
	Online bool `json:"online,omitempty"`
}

// AgentProfileRegistration omits Key because hub-server derives it from the
// authenticated Channel sender.
type AgentProfileRegistration struct {
	Version          int      `json:"version"`
	WireGuardKey     string   `json:"wireGuardKey"`
	Name             string   `json:"name,omitempty"`
	Platform         string   `json:"platform,omitempty"`
	OverlayAddresses []string `json:"overlayAddresses"`
	ConnectedAt      string   `json:"connectedAt"`
}

type AgentBindRequest struct {
	AgentProfileRegistration
	BindingKind LocalAgentBindingKind `json:"bindingKind"`
	// Admission is required on a key's first join bind: the inviter-signed
	// direct bootstrap response naming this joiner. hub-server admits the key if
	// the signer is currently bound to the network.
	Admission *DirectBootstrapResponse `json:"admission,omitempty"`
}

type LocalAgentBindingKind string

const (
	LocalAgentBindingMachine  LocalAgentBindingKind = "machine"
	LocalAgentBindingAppleApp LocalAgentBindingKind = "apple-app"
	// LocalAgentBindingJoin registers an invitation joiner that arrived
	// through the inviter's direct bootstrap tunnel. The joiner authenticates
	// with its own service key (the same key it signed the direct bootstrap
	// request with) and has no local hub-net agent proof.
	LocalAgentBindingJoin LocalAgentBindingKind = "join"
)

const AppleAppAgentCapabilityInvitationBootstrap = "invitation-bootstrap-v1"

// AppleAppAgentReadinessAssertion is extension-signed proof that one active
// Apple packet tunnel can serve invitation bootstrap for a bounded lease.
type AppleAppAgentReadinessAssertion struct {
	Version          int      `json:"version"`
	SignatureDomain  string   `json:"signatureDomain"`
	HubNetworkID     string   `json:"hubNetworkId"`
	WireGuardKey     string   `json:"wireGuardKey"`
	TunnelInstanceID string   `json:"tunnelInstanceId"`
	Capabilities     []string `json:"capabilities"`
	Generation       uint64   `json:"generation"`
	IssuedAt         string   `json:"issuedAt"`
	ExpiresAt        string   `json:"expiresAt"`
	Signature        string   `json:"signature"`
}

type AppleAppAgentBindRequest struct {
	Version   int                             `json:"version"`
	Assertion AppleAppAgentReadinessAssertion `json:"assertion"`
}

type AppleAppAgentRenewRequest struct {
	Version   int                             `json:"version"`
	Assertion AppleAppAgentReadinessAssertion `json:"assertion"`
}

type AppleAppAgentUnbindRequest struct {
	Version          int    `json:"version"`
	HubNetworkID     string `json:"hubNetworkId"`
	TunnelInstanceID string `json:"tunnelInstanceId"`
	Generation       uint64 `json:"generation"`
}

type AppleBootstrapAssignment struct {
	Version                  int      `json:"version"`
	AssignmentID             string   `json:"assignmentId"`
	TokenDigest              string   `json:"tokenDigest"`
	TransactionID            string   `json:"transactionId"`
	HubNetworkID             string   `json:"hubNetworkId"`
	InvitingKey              string   `json:"invitingKey"`
	JoinerKey                string   `json:"joinerKey"`
	JoinerWireGuardKey       string   `json:"joinerWireGuardKey"`
	JoinerOverlayAddresses   []string `json:"joinerOverlayAddresses"`
	HubProBootstrapAddresses []string `json:"hubProBootstrapAddresses"`
	InvitationCode           string   `json:"invitationCode"`
	Node                     string   `json:"node"`
	TunnelInstanceID         string   `json:"tunnelInstanceId"`
	Generation               uint64   `json:"generation"`
	ExpiresAt                string   `json:"expiresAt"`
}

type AppleBootstrapStatus struct {
	Version          int           `json:"version"`
	AssignmentID     string        `json:"assignmentId"`
	TokenDigest      string        `json:"tokenDigest"`
	TransactionID    string        `json:"transactionId"`
	TunnelInstanceID string        `json:"tunnelInstanceId"`
	Generation       uint64        `json:"generation"`
	State            string        `json:"state"`
	UpdatedAt        string        `json:"updatedAt"`
	Error            *NetworkError `json:"error,omitempty"`
}

type AppleBootstrapCancel struct {
	Version          int    `json:"version"`
	AssignmentID     string `json:"assignmentId"`
	TokenDigest      string `json:"tokenDigest"`
	TransactionID    string `json:"transactionId"`
	TunnelInstanceID string `json:"tunnelInstanceId"`
	Generation       uint64 `json:"generation"`
	Reason           string `json:"reason"`
	CancelledAt      string `json:"cancelledAt"`
}

type LocalAgentBindingStatus struct {
	Version          int                   `json:"version"`
	State            string                `json:"state"`
	BindingKind      LocalAgentBindingKind `json:"bindingKind,omitempty"`
	Key              string                `json:"key,omitempty"`
	TunnelInstanceID string                `json:"tunnelInstanceId,omitempty"`
	Generation       uint64                `json:"generation,omitempty"`
	ExpiresAt        string                `json:"expiresAt,omitempty"`
	Capabilities     []string              `json:"capabilities"`
	Connected        bool                  `json:"connected"`
	BootstrapCapable bool                  `json:"bootstrapCapable"`
	UpdatedAt        string                `json:"updatedAt"`
	Error            *NetworkError         `json:"error,omitempty"`
}

type ProfileBinding struct {
	Version          int      `json:"version"`
	BindingID        string   `json:"bindingId"`
	HubNetworkID     string   `json:"hubNetworkId"`
	Key              string   `json:"key"`
	WireGuardKey     string   `json:"wireGuardKey"`
	OverlayAddresses []string `json:"overlayAddresses"`
	IssuedAt         string   `json:"issuedAt"`
	ExpiresAt        string   `json:"expiresAt"`
	Signature        string   `json:"signature"`
}

type ConnectionGrant struct {
	Version            int    `json:"version"`
	GrantID            string `json:"grantId"`
	HubKey             string `json:"hubKey"`
	HubNetworkID       string `json:"hubNetworkId"`
	CallerKey          string `json:"callerKey"`
	CallerWireGuardKey string `json:"callerWireGuardKey"`
	CallerAddress      string `json:"callerAddress"`
	TargetKey          string `json:"targetKey"`
	TargetWireGuardKey string `json:"targetWireGuardKey"`
	ResourceID         string `json:"resourceId"`
	ProviderID         string `json:"providerId"`
	Protocol           string `json:"protocol"`
	DestinationAddress string `json:"destinationAddress"`
	DestinationPort    uint16 `json:"destinationPort"`
	Generation         uint64 `json:"generation"`
	IssuedAt           string `json:"issuedAt"`
	ExpiresAt          string `json:"expiresAt"`
	Signature          string `json:"signature"`
}

type RendezvousTicket struct {
	Version        int      `json:"version"`
	TicketID       string   `json:"ticketId"`
	HubKey         string   `json:"hubKey"`
	HubNetworkID   string   `json:"hubNetworkId"`
	Key            string   `json:"key"`
	NodeID         string   `json:"nodeId"`
	Roles          []string `json:"roles"`
	SessionPurpose string   `json:"sessionPurpose"`
	IssuedAt       string   `json:"issuedAt"`
	ExpiresAt      string   `json:"expiresAt"`
	Signature      string   `json:"signature"`
}

// PeerLinkSide is one device of a peer link: its service key, the WireGuard key its tunnel uses, its member and its
// overlay addresses.
type PeerLinkSide struct {
	Key          string   `json:"key"`
	WireGuardKey string   `json:"wireGuardKey"`
	Member       string   `json:"member"`
	Addresses    []string `json:"addresses"`
}

// PeerLinkPort is a protocol and port one side of a link may open on the other.
type PeerLinkPort struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// PeerLinkGrant is the hub-signed authorization for one direct WireGuard path between two devices of a hub: the
// routes each side sends through the other and the ports each may open on the other. The node checks only its
// signature and lifetime, as an abuse gate; each device checks it against the hub key it pinned when it joined.
type PeerLinkGrant struct {
	Version      int            `json:"version"`
	GrantID      string         `json:"grantId"`
	HubKey       string         `json:"hubKey"`
	HubNetworkID string         `json:"hubNetworkId"`
	Purpose      string         `json:"purpose"`
	A            PeerLinkSide   `json:"a"`
	B            PeerLinkSide   `json:"b"`
	AViaB        []string       `json:"aViaB"`
	BViaA        []string       `json:"bViaA"`
	AToB         []PeerLinkPort `json:"aToB"`
	BToA         []PeerLinkPort `json:"bToA"`
	IssuedAt     string         `json:"issuedAt"`
	ExpiresAt    string         `json:"expiresAt"`
	Signature    string         `json:"signature"`
}

// LinkEndpoint is an address and UDP port a device declares it can be reached at (LAN, global IPv6).
type LinkEndpoint struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// Peer link purposes: a member and the hub's machine, a client and a device sharing its internet, two devices of a
// shared service.
const (
	PeerLinkPurposeHub     = "hub"
	PeerLinkPurposeGateway = "gateway"
	PeerLinkPurposeShare   = "share"
)

type Candidate struct {
	Version     int    `json:"version"`
	CandidateID string `json:"candidateId"`
	SessionID   string `json:"sessionId"`
	Key         string `json:"key"`
	Kind        string `json:"kind"`
	Transport   string `json:"transport"`
	Address     string `json:"address"`
	Port        uint16 `json:"port"`
	Priority    uint32 `json:"priority"`
	Foundation  string `json:"foundation,omitempty"`
	ExpiresAt   string `json:"expiresAt"`
}

// ObservedEndpoint is transport metadata measured by a rendezvous node. It is
// kept separate from client-declared candidates so callers can distinguish
// node observation from agent claims.
type ObservedEndpoint struct {
	Version   int    `json:"version"`
	Key       string `json:"key"`
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Port      uint16 `json:"port"`
}

type NetworkResource struct {
	Version    int           `json:"version"`
	ResourceID string        `json:"resourceId"`
	OwnerKey   string        `json:"ownerKey"`
	ShareName  string        `json:"shareName"`
	Authority  string        `json:"authority"`
	Policy     NetworkPolicy `json:"policy"`
	Generation uint64        `json:"generation"`
}

type LiveProvider struct {
	Version        int    `json:"version"`
	ProviderID     string `json:"providerId"`
	ResourceID     string `json:"resourceId"`
	ServiceKey     string `json:"serviceKey"`
	Key            string `json:"key"`
	Protocol       string `json:"protocol"`
	OverlayAddress string `json:"overlayAddress"`
	Port           uint16 `json:"port"`
	ConnectedAt    string `json:"connectedAt"`
}

type NetworkError struct {
	Version   int            `json:"version"`
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

type ConnectionStatus struct {
	Version    int           `json:"version"`
	ResourceID string        `json:"resourceId"`
	ProviderID string        `json:"providerId,omitempty"`
	Phase      string        `json:"phase"`
	Direct     bool          `json:"direct"`
	UpdatedAt  string        `json:"updatedAt"`
	Error      *NetworkError `json:"error,omitempty"`
}

type AgentStatus struct {
	Version   int           `json:"version"`
	Key       string        `json:"key"`
	Available bool          `json:"available"`
	Addresses []string      `json:"addresses"`
	Peers     int           `json:"peers"`
	Shares    int           `json:"shares"`
	UpdatedAt string        `json:"updatedAt"`
	Error     *NetworkError `json:"error,omitempty"`
}

// GatewayCapability is explicitly advertised only after its provider enables
// internet-gateway-v1 for this Hub.
type GatewayCapability struct {
	Version    int    `json:"version"`
	Capability string `json:"capability"`
	IPv4       bool   `json:"ipv4"`
	IPv6       bool   `json:"ipv6"`
	DNS        bool   `json:"dns"`
	Metered    bool   `json:"metered"`
	UpdatedAt  string `json:"updatedAt"`
}

type GatewayStatus struct {
	Version      int               `json:"version"`
	HubNetworkID string            `json:"hubNetworkId"`
	Key          string            `json:"key"`
	WireGuardKey string            `json:"wireGuardKey"`
	Endpoint     string            `json:"endpoint"`
	Capability   GatewayCapability `json:"capability"`
	State        string            `json:"state"`
	UpdatedAt    string            `json:"updatedAt"`
	Error        *NetworkError     `json:"error,omitempty"`
}

type GatewayGrant struct {
	Version             int    `json:"version"`
	GrantID             string `json:"grantId"`
	HubKey              string `json:"hubKey"`
	HubNetworkID        string `json:"hubNetworkId"`
	ClientKey           string `json:"clientKey"`
	ClientWireGuardKey  string `json:"clientWireGuardKey"`
	GatewayKey          string `json:"gatewayKey"`
	GatewayWireGuardKey string `json:"gatewayWireGuardKey"`
	IPv4                bool   `json:"ipv4"`
	IPv6                bool   `json:"ipv6"`
	DNS                 bool   `json:"dns"`
	Generation          uint64 `json:"generation"`
	IssuedAt            string `json:"issuedAt"`
	ExpiresAt           string `json:"expiresAt"`
	Signature           string `json:"signature"`
}

type GatewayRevocation struct {
	Version      int    `json:"version"`
	HubNetworkID string `json:"hubNetworkId"`
	GatewayKey   string `json:"gatewayKey"`
	Generation   uint64 `json:"generation"`
	RevokedAt    string `json:"revokedAt"`
	Reason       string `json:"reason"`
}

type GatewayDiagnostic struct {
	Version      int            `json:"version"`
	HubNetworkID string         `json:"hubNetworkId"`
	GatewayKey   string         `json:"gatewayKey"`
	Code         string         `json:"code"`
	Message      string         `json:"message"`
	Retryable    bool           `json:"retryable"`
	UpdatedAt    string         `json:"updatedAt"`
	Details      map[string]any `json:"details,omitempty"`
}

// BootstrapEndpoint is a direct WireGuard endpoint advertised by an inviter
// for the temporary bootstrap link. The joiner uses one of these as the UDP
// handshake endpoint for the inviter peer.
type BootstrapEndpoint struct {
	Address   string `json:"address"`
	Port      uint16 `json:"port"`
	Transport string `json:"transport"`
}

// BootstrapAddress is a temporary point-to-point address pair assigned for the
// bootstrap link. These are distinct from the permanent overlay addresses
// hub-server assigns after bind.
type BootstrapAddress struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

// DirectBootstrapRequest is signed by the joiner's service key and proves the
// joiner controls that identity. The replayId binds the request to a specific
// compact invitation (it is the SHA-256 of the invitation payload); the nonce
// and issuedAt make the request itself single-use against the inviter.
type DirectBootstrapRequest struct {
	Version            int    `json:"version"`
	SignatureDomain    string `json:"signatureDomain"`
	ReplayID           string `json:"replayId"`
	JoinerServiceKey   string `json:"joinerServiceKey"`
	JoinerWireGuardKey string `json:"joinerWireGuardKey"`
	Nonce              string `json:"nonce"`
	IssuedAt           string `json:"issuedAt"`
	Signature          string `json:"signature"`
}

// DirectBootstrapResponse is signed by the inviter's invitation service key
// (the same key that signed the compact invitation). It is bound to the request
// by replayId and joiner identities, and supplies the temporary point-to-point
// configuration the joiner needs to reach hub-server through the inviter. Once the
// joiner completes hub/net/bind it receives permanent overlay addresses and
// must drop this temporary tunnel.
type DirectBootstrapResponse struct {
	Version             int                 `json:"version"`
	SignatureDomain     string              `json:"signatureDomain"`
	ReplayID            string              `json:"replayId"`
	InviterServiceKey   string              `json:"inviterServiceKey"`
	JoinerServiceKey    string              `json:"joinerServiceKey"`
	JoinerWireGuardKey  string              `json:"joinerWireGuardKey"`
	InviterWireGuardKey string              `json:"inviterWireGuardKey"`
	Endpoints           []BootstrapEndpoint `json:"endpoints"`
	JoinerAddress       BootstrapAddress    `json:"joinerAddress"`
	InviterAddress      BootstrapAddress    `json:"inviterAddress"`
	HubProHost          string              `json:"hubProHost"`
	IssuedAt            string              `json:"issuedAt"`
	ExpiresAt           string              `json:"expiresAt"`
	Signature           string              `json:"signature"`
}

type SharesReplacePayload struct {
	Shares []NetworkShare `json:"shares"`
}

type SharesReplaceMessage struct {
	Version   int                  `json:"version"`
	Type      string               `json:"type"`
	RequestID string               `json:"requestId,omitempty"`
	Payload   SharesReplacePayload `json:"payload"`
}
