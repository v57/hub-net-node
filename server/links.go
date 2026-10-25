package server

import (
	"errors"
	"time"

	"github.com/v57/hub-net-node/link"
	"github.com/v57/hub-net-node/linkgrant"
	network "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
)

// punchLead is how far ahead link.ready schedules both sides' first handshake, so they start within the same moment.
const punchLead = time.Second

// processLink handles one link message from a present device. Every reply and push goes through presence
// connections: a device's links live and die with its presence.
func (s *Server) processLink(state *connState, envelope protocol.Envelope) {
	if state.serviceKey == "" {
		s.writeError(state, "unauthorized", "register presence before linking", false)
		return
	}
	switch envelope.Type {
	case protocol.MessageLinkOpen:
		s.openLink(state, envelope)
	case protocol.MessageLinkAccept:
		accepted, err := s.links.Accept(envelope.LinkID, state.serviceKey)
		if err != nil {
			s.writeLinkError(state, envelope, err)
			return
		}
		s.logger.Info("link accepted", "link", short(accepted.ID), "target", keyTag(state.serviceKey))
		s.pushReadyIfReady(accepted)
	case protocol.MessageLinkReject:
		current, err := s.links.Close(envelope.LinkID, state.serviceKey)
		if err == nil && current.Target.Key != state.serviceKey {
			err = link.ErrNotTarget
		}
		if err != nil {
			s.writeLinkError(state, envelope, err)
			return
		}
		s.logger.Info("link rejected", "link", short(current.ID), "target", keyTag(state.serviceKey))
		s.pushLinkClosed(current, state.serviceKey, "link_rejected", "the other device rejected the link")
	case protocol.MessageLinkOffer:
		offered, err := s.links.Offer(envelope.LinkID, state.serviceKey, envelope.Endpoints)
		if err != nil {
			s.writeLinkError(state, envelope, err)
			return
		}
		s.pushReadyIfReady(offered)
	case protocol.MessageLinkClose:
		current, err := s.links.Close(envelope.LinkID, state.serviceKey)
		if err != nil {
			s.writeLinkError(state, envelope, err)
			return
		}
		s.pushLinkClosed(current, state.serviceKey, "link_closed", "the other device closed the link")
	}
}

// openLink checks the grant as an abuse gate (the target checks it for real), creates the link, tells the target and
// answers the opener.
func (s *Server) openLink(state *connState, envelope protocol.Envelope) {
	grant := *envelope.Grant
	if err := s.grants.Verify(grant); err != nil {
		s.logger.Info("link grant rejected", "from", state.source, "key", keyTag(state.serviceKey), "reason", err.Error())
		s.writeError(state, "unauthorized", "grant rejected", false)
		return
	}
	peer, ok := linkgrant.Other(grant, state.serviceKey)
	if !ok {
		s.writeError(state, "unauthorized", "not a side of the grant", false)
		return
	}
	if !s.registry.Online(peer.Key) {
		s.writeError(state, "peer_offline", "the other device is not present", true)
		return
	}
	created, replaced, err := s.links.Open(grant, state.serviceKey)
	if replaced != nil {
		s.pushLinkClosed(*replaced, "", "link_replaced", "the link was opened again")
	}
	if err != nil {
		s.writeError(state, errorCode(err), err.Error(), errors.Is(err, link.ErrRateLimited))
		return
	}
	if !s.registry.Push(peer.Key, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: protocol.MessageLinkIncoming, LinkID: created.ID, Grant: &grant,
		ProbeToken: created.Target.ProbeToken, PeerKey: state.serviceKey,
	}) {
		_, _ = s.links.Close(created.ID, state.serviceKey)
		s.writeError(state, "peer_offline", "the other device is not present", true)
		return
	}
	s.logger.Info("link opened", "link", short(created.ID), "purpose", grant.Purpose,
		"opener", keyTag(state.serviceKey), "target", keyTag(peer.Key))
	s.writeEnvelope(state, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: protocol.MessageLinkOpened, RequestID: envelope.RequestID, LinkID: created.ID,
		ProbeToken: created.Opener.ProbeToken, PeerKey: peer.Key,
	})
}

// pushReadyIfReady tells both sides where to find each other once the target accepted and both were observed; a
// later offer sends it again with the new candidates.
func (s *Server) pushReadyIfReady(current link.Link) {
	if !current.Ready() {
		return
	}
	punchAt := time.Now().Add(punchLead).UTC().Format(time.RFC3339Nano)
	for _, key := range []string{current.Opener.Key, current.Target.Key} {
		_, other, _ := current.SideOf(key)
		observed := protocol.ObservedEndpoint(*other.Observed)
		s.registry.Push(key, protocol.Envelope{
			MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
			Type: protocol.MessageLinkReady, LinkID: current.ID, PeerKey: other.Key,
			Observed: &observed, Endpoints: other.Candidates, PunchAt: punchAt,
		})
	}
	s.logger.Info("link ready", "link", short(current.ID),
		"opener", current.Opener.Observed.Address, "target", current.Target.Observed.Address)
}

// pushLinkClosed tells the sides of a removed link, except the one that asked for it.
func (s *Server) pushLinkClosed(current link.Link, except, code, message string) {
	for _, key := range []string{current.Opener.Key, current.Target.Key} {
		if key == "" || key == except {
			continue
		}
		s.registry.Push(key, protocol.Envelope{
			MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
			Type: protocol.MessageLinkClosed, LinkID: current.ID,
			Error: &network.NetworkError{Version: protocol.MajorVersion, Code: code, Message: message, Retryable: true},
		})
	}
}

// closeLinksOf ends every link of a device whose presence ended.
func (s *Server) closeLinksOf(key string) {
	for _, removed := range s.links.CloseForKey(key) {
		s.pushLinkClosed(removed, key, "peer_offline", "the other device is no longer present")
	}
}

func (s *Server) writeLinkError(state *connState, envelope protocol.Envelope, err error) {
	s.writeEnvelope(state, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: protocol.MessageError, RequestID: envelope.RequestID, LinkID: envelope.LinkID,
		Error: &network.NetworkError{Version: protocol.MajorVersion, Code: errorCode(err), Message: err.Error()},
	})
}
