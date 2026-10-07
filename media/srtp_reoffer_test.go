// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2024, Emir Aganovic

package media

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/emiago/diago/media/sdp"
	"github.com/emiago/sipgo/fakes"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Public RFC 4568 example material, not a live key.
const sdesTestKey = "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"

func sdesTestOffer(key string) []byte {
	return []byte(fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=test\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 1234 RTP/SAVP 8\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 %s\r\na=sendrecv\r\n", key))
}

// sdesReadRTP encrypts one RTP packet with sender and reads it through m.
func sdesReadRTP(t *testing.T, m *MediaSession, sender *srtp.Context, seq uint16) error {
	t.Helper()
	pkt := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 8, SequenceNumber: seq, SSRC: 42}, Payload: []byte("audio")}
	plain, err := pkt.Marshal()
	require.NoError(t, err)
	encrypted, err := sender.EncryptRTP(nil, plain, nil)
	require.NoError(t, err)
	m.rtpConn = &fakes.UDPConn{Reader: bytes.NewReader(encrypted)}
	read := rtp.Packet{}
	_, err = m.ReadRTP(make([]byte, RTPBufSize), &read)
	return err
}

func TestRemoteSDPSameKeyKeepsROC(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString(sdesTestKey)
	require.NoError(t, err)
	sender, err := srtp.CreateContext(key[:16], key[16:], srtp.ProtectionProfileAes128CmHmacSha1_80)
	require.NoError(t, err)

	offer := sdesTestOffer("inline:" + sdesTestKey)
	m := &MediaSession{Codecs: []Codec{CodecAudioAlaw}, SecureRTP: 1, SRTPAlg: SRTPProfileAes128CmHmacSha1_80}
	require.NoError(t, m.RemoteSDP(offer))

	// Cross the sequence wrap so both sides move to ROC 1.
	for _, seq := range []uint16{65534, 65535, 0, 1} {
		require.NoError(t, sdesReadRTP(t, m, sender, seq))
	}

	// A session refresh re-offers the same key, twice.
	for range 2 {
		m = m.Fork()
		require.NoError(t, m.RemoteSDP(offer))
	}
	require.NoError(t, sdesReadRTP(t, m, sender, 2), "same-key re-offer must keep the rollover counter")
}

func TestRemoteSDPNewKeyResetsContext(t *testing.T) {
	m := &MediaSession{Codecs: []Codec{CodecAudioAlaw}, SecureRTP: 1, SRTPAlg: SRTPProfileAes128CmHmacSha1_80}
	require.NoError(t, m.RemoteSDP(sdesTestOffer("inline:"+sdesTestKey)))
	oldCtx := m.remoteCtxSRTP

	key, err := base64.StdEncoding.DecodeString(sdesTestKey)
	require.NoError(t, err)
	key[0] ^= 1
	fork := m.Fork()
	require.NoError(t, fork.RemoteSDP(sdesTestOffer("inline:"+base64.StdEncoding.EncodeToString(key))))
	require.NotSame(t, oldCtx, fork.remoteCtxSRTP)

	// A fresh context for the new key starts at ROC 0.
	sender, err := srtp.CreateContext(key[:16], key[16:], srtp.ProtectionProfileAes128CmHmacSha1_80)
	require.NoError(t, err)
	require.NoError(t, sdesReadRTP(t, fork, sender, 100))
}

func TestMediaSessionForkSRTPReoffer(t *testing.T) {
	m := &MediaSession{
		Laddr:     net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		Codecs:    []Codec{CodecAudioAlaw},
		Mode:      sdp.ModeSendrecv,
		SecureRTP: 1,
		SRTPAlg:   SRTPProfileAes128CmHmacSha1_80,
	}
	offer := sdesTestOffer("inline:" + sdesTestKey)
	require.NoError(t, m.RemoteSDP(offer))

	fork := m.Fork()
	require.NoError(t, fork.RemoteSDP(offer), "a fork must accept an RTP/SAVP re-offer")
	assert.Equal(t, "RTP/SAVP", fork.remoteProto)

	answer := sdp.SessionDescription{}
	require.NoError(t, sdp.Unmarshal(fork.LocalSDP(), &answer))
	md, err := answer.MediaDescription("audio")
	require.NoError(t, err)
	assert.Equal(t, "RTP/SAVP", md.Proto)
	assert.Contains(t, strings.Join(answer.Values("a"), "\n"), "crypto:1 AES_CM_128_HMAC_SHA1_80 inline:")
}

func TestMediaSessionOriginStableAcrossAnswer(t *testing.T) {
	newSession := func() *MediaSession {
		return &MediaSession{
			Laddr:  net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
			Codecs: []Codec{CodecAudioAlaw},
			Mode:   sdp.ModeSendrecv,
		}
	}
	origin := func(b []byte) (uint64, uint64) {
		t.Helper()
		sd := sdp.SessionDescription{}
		require.NoError(t, sdp.Unmarshal(b, &sd))
		si, err := sd.SessionInformation()
		require.NoError(t, err)
		return si.SessionID, si.SessionVersion
	}

	peerSDP := func(id int) []byte {
		return []byte(fmt.Sprintf("v=0\r\no=- %d %d IN IP4 127.0.0.2\r\ns=peer\r\nc=IN IP4 127.0.0.2\r\nt=0 0\r\nm=audio 4000 RTP/AVP 8\r\na=sendrecv\r\n", id, id))
	}

	answerer := newSession()
	require.NoError(t, answerer.RemoteSDP(peerSDP(100)))
	answerID, _ := origin(answerer.LocalSDP())
	assert.NotEqual(t, uint64(100), answerID, "the answerer must not adopt the offerer's session id")

	offerer := newSession()
	offerID, offerVersion := origin(offerer.LocalSDP())
	require.NoError(t, offerer.RemoteSDP(peerSDP(200)))
	reofferID, reofferVersion := origin(offerer.Fork().LocalSDP())
	assert.Equal(t, offerID, reofferID, "the offerer's session id must survive the answer")
	assert.Equal(t, offerVersion+1, reofferVersion)
}

// A late-offer re-INVITE: our live session re-offers (new local key) and the
// peer's answer, carried in the ACK, is applied on a fork. The fork must keep
// encrypting with the key we offered.
func TestMediaSessionForkLateOfferAnswerKeepsLocalSRTP(t *testing.T) {
	newSession := func() *MediaSession {
		m := &MediaSession{
			Laddr:     net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
			Codecs:    []Codec{CodecAudioAlaw},
			SecureRTP: 1,
			SRTPAlg:   SRTPProfileAes128CmHmacSha1_80,
			Mode:      sdp.ModeSendrecv,
		}
		require.NoError(t, m.Init())
		t.Cleanup(func() { m.Close() })
		return m
	}
	us, peer := newSession(), newSession()
	require.NoError(t, peer.RemoteSDP(us.LocalSDP()))
	require.NoError(t, us.RemoteSDP(peer.LocalSDP()))

	reoffer := us.LocalSDP()
	peerFork := peer.Fork()
	require.NoError(t, peerFork.RemoteSDP(reoffer))
	ackAnswer := peerFork.LocalSDP()

	usFork := us.Fork()
	require.NoError(t, usFork.RemoteSDP(ackAnswer))

	pkt := &rtp.Packet{
		Header:  rtp.Header{Version: 2, PayloadType: 8, SequenceNumber: 1, Timestamp: 160, SSRC: 0xdeadbeef},
		Payload: []byte("srtp after late offer"),
	}
	require.NoError(t, usFork.WriteRTP(pkt))
	got := rtp.Packet{}
	_, err := peerFork.ReadRTP(make([]byte, RTPBufSize), &got)
	require.NoError(t, err, "fork must encrypt with the key from our re-offer")
	assert.Equal(t, pkt.Payload, got.Payload)
}
