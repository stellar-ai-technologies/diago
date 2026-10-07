package media

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/emiago/sipgo/fakes"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
	"github.com/stretchr/testify/require"
)

// Public RFC 4568 example material, not a live key.
const sdesTestKey = "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"

func sdesTestOffer(key string) []byte {
	return []byte(fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=test\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 1234 RTP/SAVP 8\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 %s\r\na=sendrecv\r\n", key))
}

func TestRemoteSDP_SDESLifetime(t *testing.T) {
	for _, suffix := range []string{"", "|2^31", "|2147483648", "|1", "|2^0", "|2^48", "|281474976710656"} {
		t.Run("valid"+suffix, func(t *testing.T) {
			m := MediaSession{Codecs: []Codec{CodecAudioAlaw}, SRTPAlg: SRTPProfileAes128CmHmacSha1_80}
			require.NoError(t, m.RemoteSDP(sdesTestOffer("inline:"+sdesTestKey+suffix)))
			require.NotNil(t, m.remoteCtxSRTP)
		})
	}
	for _, key := range []string{
		"inline:" + sdesTestKey + "|", "inline:" + sdesTestKey + "|0",
		"inline:" + sdesTestKey + "|01", "inline:" + sdesTestKey + "|+1",
		"inline:" + sdesTestKey + "|-1", "inline:" + sdesTestKey + "|2^",
		"inline:" + sdesTestKey + "|2^031", "inline:" + sdesTestKey + "|2^49",
		"inline:" + sdesTestKey + "|281474976710657", "inline:" + sdesTestKey + "|18446744073709551616",
		"inline:" + sdesTestKey + "|1:4", "inline:" + sdesTestKey + "|2^31|1:4",
		"inline:" + sdesTestKey + ";inline:" + sdesTestKey,
		"inline:bad-key|2^31", "inline:YWJj|2^31", "other:" + sdesTestKey,
	} {
		t.Run("invalid/"+strings.TrimPrefix(key, "inline:"+sdesTestKey), func(t *testing.T) {
			m := MediaSession{Codecs: []Codec{CodecAudioAlaw}, SRTPAlg: SRTPProfileAes128CmHmacSha1_80}
			require.Error(t, m.RemoteSDP(sdesTestOffer(key)))
			require.Nil(t, m.remoteCtxSRTP)
		})
	}
}

func TestMediaSDESLifetime(t *testing.T) {
	for _, exhaustRTCP := range []bool{false, true} {
		t.Run(fmt.Sprintf("exhaustRTCP=%t", exhaustRTCP), func(t *testing.T) {
			m := &MediaSession{Codecs: []Codec{CodecAudioAlaw}, SRTPAlg: SRTPProfileAes128CmHmacSha1_80}
			offer := sdesTestOffer("inline:" + sdesTestKey + "|2")
			require.NoError(t, m.RemoteSDP(offer))
			key, err := base64.StdEncoding.DecodeString(sdesTestKey)
			require.NoError(t, err)
			sender, err := srtp.CreateContext(key[:16], key[16:], srtp.ProtectionProfileAes128CmHmacSha1_80)
			require.NoError(t, err)
			seq := uint16(1234)
			read := func(rtcpPacket, corrupt bool) error {
				var encrypted []byte
				if rtcpPacket {
					plain, err := (&rtcp.ReceiverReport{SSRC: 42}).Marshal()
					require.NoError(t, err)
					encrypted, err = sender.EncryptRTCP(nil, plain, nil)
					require.NoError(t, err)
				} else {
					pkt := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 8, SequenceNumber: seq, SSRC: 42}, Payload: []byte("audio")}
					seq++
					plain, err := pkt.Marshal()
					require.NoError(t, err)
					encrypted, err = sender.EncryptRTP(nil, plain, nil)
					require.NoError(t, err)
				}
				if corrupt {
					encrypted[len(encrypted)-1] ^= 1
				}
				conn := &fakes.UDPConn{Reader: bytes.NewReader(encrypted)}
				if rtcpPacket {
					m.rtcpConn = conn
					_, err := m.ReadRTCP(make([]byte, RTPBufSize), make([]rtcp.Packet, 4))
					return err
				}
				m.rtpConn = conn
				pkt := rtp.Packet{}
				_, err := m.ReadRTP(make([]byte, RTPBufSize), &pkt)
				if err == nil {
					require.Equal(t, []byte("audio"), pkt.Payload)
				}
				return err
			}
			// Authentication failures must not consume the negotiated lifetime.
			require.Error(t, read(exhaustRTCP, true))
			require.NoError(t, read(exhaustRTCP, false))
			require.NoError(t, read(!exhaustRTCP, false))
			require.NoError(t, read(exhaustRTCP, false))
			require.ErrorContains(t, read(false, false), "SDES key lifetime exhausted")
			require.ErrorContains(t, read(true, false), "SDES key lifetime exhausted")
			// A larger lifetime on the same session cannot extend an exhausted key.
			require.NoError(t, m.RemoteSDP(sdesTestOffer("inline:"+sdesTestKey+"|4")))
			require.ErrorContains(t, read(exhaustRTCP, false), "SDES key lifetime exhausted")
			// Re-offering the same key on a fork must not replenish its budget.
			m = m.Fork()
			require.NoError(t, m.RemoteSDP(offer))
			require.ErrorContains(t, read(exhaustRTCP, false), "SDES key lifetime exhausted")
			// A different master key has its own packet budget.
			key[0] ^= 1
			require.NoError(t, m.RemoteSDP(sdesTestOffer("inline:"+base64.StdEncoding.EncodeToString(key)+"|2")))
			sender, err = srtp.CreateContext(key[:16], key[16:], srtp.ProtectionProfileAes128CmHmacSha1_80)
			require.NoError(t, err)
			require.NoError(t, read(exhaustRTCP, false))
			require.NoError(t, read(exhaustRTCP, false))
			require.ErrorContains(t, read(exhaustRTCP, false), "SDES key lifetime exhausted")
		})
	}
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
