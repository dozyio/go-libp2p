package libp2pwebrtc

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	tpt "github.com/libp2p/go-libp2p/core/transport"
	"github.com/libp2p/go-libp2p/p2p/transport/webrtc/udpmux"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"github.com/pion/webrtc/v3"
)

type connMultiaddrs struct {
	local, remote ma.Multiaddr
}

var _ network.ConnMultiaddrs = &connMultiaddrs{}

func (c *connMultiaddrs) LocalMultiaddr() ma.Multiaddr  { return c.local }
func (c *connMultiaddrs) RemoteMultiaddr() ma.Multiaddr { return c.remote }

const (
	candidateSetupTimeout         = 20 * time.Second
	DefaultMaxInFlightConnections = 10
)

type listener struct {
	localAddr                 net.Addr
	localMultiaddr            ma.Multiaddr
	ctx                       context.Context
	transport                 *WebRTCTransport
	mux                       *udpmux.UDPMux
	acceptQueue               chan tpt.CapableConn
	cancel                    context.CancelFunc
	localFingerprint          webrtc.DTLSFingerprint
	localFingerprintMultibase string
	config                    webrtc.Configuration
	wg                        sync.WaitGroup
}

var _ tpt.Listener = &listener{}

func newListener(transport *WebRTCTransport, laddr ma.Multiaddr, socket net.PacketConn, config webrtc.Configuration) (*listener, error) {
	localFingerprints, err := config.Certificates[0].GetFingerprints()
	if err != nil {
		return nil, err
	}

	localMh, err := hex.DecodeString(strings.ReplaceAll(localFingerprints[0].Value, ":", ""))
	if err != nil {
		return nil, err
	}
	localMhBuf, err := multihash.Encode(localMh, multihash.SHA2_256)
	if err != nil {
		return nil, err
	}
	localFpMultibase, err := multibase.Encode(multibase.Base64url, localMhBuf)
	if err != nil {
		return nil, err
	}

	l := &listener{
		transport:                 transport,
		config:                    config,
		localFingerprint:          localFingerprints[0],
		localFingerprintMultibase: localFpMultibase,
		localMultiaddr:            laddr,
		localAddr:                 socket.LocalAddr(),
		acceptQueue:               make(chan tpt.CapableConn),
	}

	l.ctx, l.cancel = context.WithCancel(context.Background())
	l.mux = udpmux.NewUDPMux(socket)
	l.mux.Start()

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.listen()
	}()

	return l, err
}

func (l *listener) listen() {
	// Accepting a connection requires instantiating a peerconnection and a noise connection
	// which is expensive. We therefore limit the number of in-flight connection requests. A
	// connection is considered to be in flight from the instant it is handled until it is
	// dequeued by a call to Accept, or errors out in some way.
	inFlightSemaphore := make(chan struct{}, l.transport.maxInFlightConnections)
	for {
		select {
		case inFlightSemaphore <- struct{}{}:
		case <-l.ctx.Done():
			return
		}

		candidate, err := l.mux.Accept(l.ctx)
		if err != nil {
			if l.ctx.Err() == nil {
				log.Debugf("accepting candidate failed: %s", err)
			}
			return
		}

		go func() {
			defer func() { <-inFlightSemaphore }()

			ctx, cancel := context.WithTimeout(l.ctx, candidateSetupTimeout)
			defer cancel()

			conn, err := l.handleCandidate(ctx, candidate)
			if err != nil {
				l.mux.RemoveConnByUfrag(candidate.Ufrag)
				log.Debugf("could not accept connection: %s: %v", candidate.Ufrag, err)
				return
			}

			select {
			case <-ctx.Done():
				log.Warn("could not push connection: ctx done")
				conn.Close()
			case l.acceptQueue <- conn:
				// acceptQueue is an unbuffered channel, so this blocks until the connection is accepted.
			}
		}()
	}
}

func (l *listener) handleCandidate(ctx context.Context, candidate udpmux.Candidate) (tpt.CapableConn, error) {
	remoteMultiaddr, err := manet.FromNetAddr(candidate.Addr)
	if err != nil {
		return nil, err
	}
	if l.transport.gater != nil {
		localAddr, _ := ma.SplitFunc(l.localMultiaddr, func(c ma.Component) bool { return c.Protocol().Code == ma.P_CERTHASH })
		if !l.transport.gater.InterceptAccept(&connMultiaddrs{local: localAddr, remote: remoteMultiaddr}) {
			// The connection attempt is rejected before we can send the client an error.
			// This means that the connection attempt will time out.
			return nil, errors.New("connection gated")
		}
	}
	scope, err := l.transport.rcmgr.OpenConnection(network.DirInbound, false, remoteMultiaddr)
	if err != nil {
		return nil, err
	}
	conn, err := l.setupConnection(ctx, scope, remoteMultiaddr, candidate)
	if err != nil {
		scope.Done()
		return nil, err
	}
	if l.transport.gater != nil && !l.transport.gater.InterceptSecured(network.DirInbound, conn.RemotePeer(), conn) {
		conn.Close()
		return nil, errors.New("connection gated")
	}
	return conn, nil
}

func (l *listener) setupConnection(
	ctx context.Context, scope network.ConnManagementScope,
	remoteMultiaddr ma.Multiaddr, candidate udpmux.Candidate,
) (tConn tpt.CapableConn, err error) {
	var w webRTCConnection
	defer func() {
		if err != nil {
			if w.PeerConnection != nil {
				_ = w.PeerConnection.Close()
			}
			if tConn != nil {
				_ = tConn.Close()
			}
		}
	}()

	settingEngine := webrtc.SettingEngine{LoggerFactory: pionLoggerFactory}
	settingEngine.SetAnsweringDTLSRole(webrtc.DTLSRoleServer)
	settingEngine.SetICECredentials(candidate.Ufrag, candidate.Ufrag)
	settingEngine.SetLite(true)
	settingEngine.SetICEUDPMux(l.mux)
	settingEngine.SetIncludeLoopbackCandidate(true)
	settingEngine.DisableCertificateFingerprintVerification(true)
	settingEngine.SetICETimeouts(
		l.transport.peerConnectionTimeouts.Disconnect,
		l.transport.peerConnectionTimeouts.Failed,
		l.transport.peerConnectionTimeouts.Keepalive,
	)
	// This is higher than the path MTU due to a bug in the sctp chunking logic.
	// Remove this after https://github.com/pion/sctp/pull/301 is included
	// in a release.
	settingEngine.SetReceiveMTU(udpmux.ReceiveBufSize)
	settingEngine.DetachDataChannels()
	settingEngine.SetSCTPMaxReceiveBufferSize(sctpReceiveBufferSize)
	if err := scope.ReserveMemory(sctpReceiveBufferSize, network.ReservationPriorityMedium); err != nil {
		return nil, err
	}

	w, err = newWebRTCConnection(settingEngine, l.config)
	if err != nil {
		return nil, fmt.Errorf("instantiating peer connection failed: %w", err)
	}

	errC := addOnConnectionStateChangeCallback(w.PeerConnection)
	// Infer the client SDP from the incoming STUN message by setting the ice-ufrag.
	if err := w.PeerConnection.SetRemoteDescription(webrtc.SessionDescription{
		SDP:  createClientSDP(candidate.Addr, candidate.Ufrag),
		Type: webrtc.SDPTypeOffer,
	}); err != nil {
		return nil, err
	}
	answer, err := w.PeerConnection.CreateAnswer(nil)
	if err != nil {
		return nil, err
	}
	if err := w.PeerConnection.SetLocalDescription(answer); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errC:
		if err != nil {
			return nil, fmt.Errorf("peer connection failed for ufrag: %s", candidate.Ufrag)
		}
	}

	// Run the noise handshake.
	rwc, err := detachHandshakeDataChannel(ctx, w.HandshakeDataChannel)
	if err != nil {
		return nil, err
	}
	handshakeChannel := newStream(w.HandshakeDataChannel, rwc, func() {})
	// we do not yet know A's peer ID so accept any inbound
	remotePubKey, err := l.transport.noiseHandshake(ctx, w.PeerConnection, handshakeChannel, "", crypto.SHA256, true)
	if err != nil {
		return nil, err
	}
	remotePeer, err := peer.IDFromPublicKey(remotePubKey)
	if err != nil {
		return nil, err
	}
	// earliest point where we know the remote's peerID
	if err := scope.SetPeer(remotePeer); err != nil {
		return nil, err
	}

	localMultiaddrWithoutCerthash, _ := ma.SplitFunc(l.localMultiaddr, func(c ma.Component) bool { return c.Protocol().Code == ma.P_CERTHASH })
	conn, err := newConnection(
		network.DirInbound,
		w.PeerConnection,
		l.transport,
		scope,
		l.transport.localPeerId,
		localMultiaddrWithoutCerthash,
		remotePeer,
		remotePubKey,
		remoteMultiaddr,
		w.IncomingDataChannels,
	)
	if err != nil {
		return nil, err
	}

	return conn, err
}

func (l *listener) Accept() (tpt.CapableConn, error) {
	select {
	case <-l.ctx.Done():
		return nil, tpt.ErrListenerClosed
	case conn := <-l.acceptQueue:
		return conn, nil
	}
}

func (l *listener) Close() error {
	select {
	case <-l.ctx.Done():
	default:
	}
	l.cancel()
	l.mux.Close()
	l.wg.Wait()
loop:
	for {
		select {
		case conn := <-l.acceptQueue:
			conn.Close()
		default:
			break loop
		}
	}
	return nil
}

func (l *listener) Addr() net.Addr {
	return l.localAddr
}

func (l *listener) Multiaddr() ma.Multiaddr {
	return l.localMultiaddr
}

// addOnConnectionStateChangeCallback adds the OnConnectionStateChange to the PeerConnection.
// The channel returned here:
// * is closed when the state changes to Connection
// * receives an error when the state changes to Failed
// * doesn't receive anything (nor is closed) when the state changes to Disconnected
func addOnConnectionStateChangeCallback(pc *webrtc.PeerConnection) <-chan error {
	errC := make(chan error, 1)
	var once sync.Once
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateConnected:
			once.Do(func() { close(errC) })
		case webrtc.PeerConnectionStateFailed:
			once.Do(func() {
				errC <- errors.New("peerconnection failed")
				close(errC)
			})
		case webrtc.PeerConnectionStateDisconnected:
			// the connection can move to a disconnected state and back to a connected state without ICE renegotiation.
			// This could happen when underlying UDP packets are lost, and therefore the connection moves to the disconnected state.
			// If the connection then receives packets on the connection, it can move back to the connected state.
			// If no packets are received until the failed timeout is triggered, the connection moves to the failed state.
			log.Warn("peerconnection disconnected")
		}
	})
	return errC
}
