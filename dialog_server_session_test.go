// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2024, Emir Aganovic

package diago

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrationDialogServerEarlyMedia(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dialer *Diago
	{
		ua, _ := sipgo.NewUA(sipgo.WithUserAgent("server"))
		defer ua.Close()

		dg := NewDiago(ua, WithTransport(
			Transport{
				Transport: "udp",
				BindHost:  "127.0.0.1",
				BindPort:  15020,
			},
		))

		// Run listener to accepte reinvites, but it should not receive any request
		err := dg.ServeBackground(ctx, nil)
		require.NoError(t, err)

		dialer = dg
	}

	ua, _ := sipgo.NewUA()
	defer ua.Close()

	dg := NewDiago(ua, WithTransport(
		Transport{
			Transport: "udp",
			BindHost:  "127.0.0.1",
			BindPort:  15010,
		},
	))

	waitDialog := make(chan *DialogServerSession)
	err := dg.ServeBackground(ctx, func(d *DialogServerSession) {
		t.Log("Call received")
		waitDialog <- d
		<-d.Context().Done()
	})
	require.NoError(t, err)

	allResponses := []sip.Response{}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		dialog, err := dialer.Invite(ctx, sip.Uri{User: "dialer", Host: "127.0.0.1", Port: 15010}, InviteOptions{
			OnResponse: func(res *sip.Response) error {
				t.Log("Received resp", res.StatusCode)
				allResponses = append(allResponses, *res.Clone())
				return nil
			},
		})
		if err != nil {
			t.Log("Failed to dial", err)
			return
		}
		defer dialog.Close()
		<-dialog.Context().Done()
		t.Log("Dialog done")
	}()

	d := <-waitDialog

	err = d.ProgressMedia()
	require.NoError(t, err)

	// It is valid to also send 180
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, d.Ringing())

	// We can play some file ringtone
	playback, err := d.PlaybackCreate()
	require.NoError(t, err)
	_, err = playback.PlayFile("testdata/files/demo-echodone.wav")
	require.NoError(t, err)

	// We can now answer
	err = d.Answer()
	require.NoError(t, err)

	// New playback is needed to follow new media session
	playback, err = d.PlaybackCreate()
	require.NoError(t, err)
	_, err = playback.PlayFile("testdata/files/demo-echodone.wav")
	require.NoError(t, err)
	d.Hangup(context.TODO())

	wg.Wait()
	require.Len(t, allResponses, 3)
	assert.Equal(t, 183, allResponses[0].StatusCode)
	assert.Equal(t, 180, allResponses[1].StatusCode)
	assert.Equal(t, 200, allResponses[2].StatusCode)
}

func TestIntegrationDialogServerReinvite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	{
		ua, _ := sipgo.NewUA(sipgo.WithUserAgent("server"))
		defer ua.Close()

		dg := NewDiago(ua, WithTransport(
			Transport{
				Transport: "udp",
				BindHost:  "127.0.0.1",
				BindPort:  15070,
			},
		))

		// Run listener to accepte reinvites, but it should not receive any request
		err := dg.ServeBackground(ctx, nil)
		require.NoError(t, err)

		go func() {
			dialog, err := dg.Invite(ctx, sip.Uri{User: "dialer", Host: "127.0.0.1", Port: 15060}, InviteOptions{})
			require.NoError(t, err)
			<-dialog.Context().Done()
			t.Log("Dialog done")
		}()
	}

	ua, _ := sipgo.NewUA()
	defer ua.Close()

	dg := NewDiago(ua, WithTransport(
		Transport{
			Transport: "udp",
			BindHost:  "127.0.0.1",
			BindPort:  15060,
		},
	))

	waitDialog := make(chan *DialogServerSession)
	err := dg.ServeBackground(ctx, func(d *DialogServerSession) {
		t.Log("Call received")
		waitDialog <- d
		<-d.Context().Done()
	})
	require.NoError(t, err)
	d := <-waitDialog

	err = d.Answer()
	require.NoError(t, err)
	err = d.ReInvite(d.Context())
	require.NoError(t, err)

	d.Hangup(context.TODO())
}

// A re-INVITE that carries an RTP/SAVP offer on an established SDES-SRTP call
// must be answered 200 and keep media flowing.
func TestIntegrationDialogServerReinviteSRTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srtpTransport := func(port int) DiagoOption {
		return WithTransport(Transport{
			ID:        "tcp",
			Transport: "tcp",
			BindHost:  "127.0.0.1",
			BindPort:  port,
			MediaSRTP: 1,
		})
	}
	codecs := WithMediaConfig(MediaConfig{Codecs: []media.Codec{media.CodecAudioUlaw}})

	mediaUpdated := make(chan struct{}, 1)
	callerDialog := make(chan *DialogClientSession, 1)
	{
		ua, _ := sipgo.NewUA(sipgo.WithUserAgent("caller"))
		defer ua.Close()

		dg := NewDiago(ua, srtpTransport(15446), codecs)
		// The caller must serve to receive the in-dialog re-INVITE.
		require.NoError(t, dg.ServeBackground(ctx, nil))

		go func() {
			dialog, err := dg.NewDialog(sip.Uri{User: "callee", Host: "127.0.0.1", Port: 15445}, NewDialogOptions{Transport: "tcp"})
			if err != nil {
				t.Error(err)
				return
			}
			defer dialog.Close()
			err = dialog.Invite(ctx, InviteClientOptions{
				OnMediaUpdate: func(d *DialogMedia) {
					mediaUpdated <- struct{}{}
				},
			})
			if err == nil {
				err = dialog.Ack(ctx)
			}
			if err != nil {
				t.Error(err)
				return
			}
			callerDialog <- dialog
			<-dialog.Context().Done()
		}()
	}

	ua, _ := sipgo.NewUA(sipgo.WithUserAgent("callee"))
	defer ua.Close()

	dg := NewDiago(ua, srtpTransport(15445), codecs)
	waitDialog := make(chan *DialogServerSession)
	err := dg.ServeBackground(ctx, func(d *DialogServerSession) {
		waitDialog <- d
		<-d.Context().Done()
	})
	require.NoError(t, err)
	d := <-waitDialog
	require.NoError(t, d.Answer())
	caller := <-callerDialog

	// The caller keeps sending while it answers the re-offer, so -race sees any
	// SRTP state the answer touches after the fork carries live media.
	callerWriter, err := caller.AudioWriter()
	require.NoError(t, err)
	stopSending := make(chan struct{})
	sending := make(chan struct{})
	go func() {
		defer close(sending)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopSending:
				return
			case <-ticker.C:
				if _, err := callerWriter.Write(make([]byte, 160)); err != nil {
					return
				}
			}
		}
	}()

	require.NoError(t, d.ReInvite(d.Context()))
	select {
	case <-mediaUpdated:
	case <-time.After(time.Second):
		t.Fatal("caller did not apply the SRTP re-offer")
	}
	time.Sleep(100 * time.Millisecond)
	close(stopSending)
	<-sending

	// Media sent with the re-offered key reaches the caller.
	r, err := caller.AudioReader()
	require.NoError(t, err)
	w, err := d.AudioWriter()
	require.NoError(t, err)
	frame := make([]byte, 160)
	_, err = w.Write(frame)
	require.NoError(t, err)

	read := make(chan error, 1)
	go func() {
		_, err := r.Read(make([]byte, 160))
		read <- err
	}()
	select {
	case err := <-read:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("no media after SRTP re-INVITE")
	}

	d.Hangup(context.TODO())
}

func TestIntegrationDialogServerPeerCodecPruneReinvite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ua, _ := sipgo.NewUA(sipgo.WithUserAgent("uas"))
	defer ua.Close()

	uas := NewDiago(ua, WithTransport(Transport{
		Transport:       "udp",
		BindHost:        "127.0.0.1",
		BindPort:        15080,
		MediaExternalIP: net.IPv4(203, 0, 113, 10),
	}))
	err := uas.ServeBackground(ctx, func(d *DialogServerSession) {
		// This is the reported role: the peer sends the initial INVITE and
		// Diago answers it as the UAS. RTP NAT must not change the SIP flow.
		err := d.AnswerOptions(AnswerOptions{
			RTPNAT:        media.RTPNATSymetric,
			OnMediaUpdate: func(*DialogMedia) {},
		})
		require.NoError(t, err)
		reader, err := d.AudioReader()
		require.NoError(t, err)
		go func() {
			_, _ = reader.Read(make([]byte, 160))
		}()
		<-d.Context().Done()
	})
	require.NoError(t, err)

	peerUA, _ := sipgo.NewUA(sipgo.WithUserAgent("peer"))
	defer peerUA.Close()
	peer := newDialer(peerUA)
	err = peer.ServeBackground(ctx, func(*DialogServerSession) {})
	require.NoError(t, err)

	dialog, err := peer.Invite(ctx, sip.Uri{User: "service", Host: "127.0.0.1", Port: 15080}, InviteOptions{})
	require.NoError(t, err)
	defer dialog.Close()
	require.Contains(t, string(dialog.InviteRequest.Body()), " 0 8 101")

	// The initial peer offer contains PCMU, PCMA and telephone-event. The
	// post-answer offer intentionally prunes PCMA, matching the SBC behavior.
	prunedMedia := dialog.MediaSession().Fork()
	prunedMedia.Codecs = []media.Codec{
		media.CodecAudioUlaw,
		media.CodecTelephoneEvent8000,
	}
	prunedOffer := prunedMedia.LocalSDP()
	require.Contains(t, string(prunedOffer), " 0 101")
	require.NotContains(t, string(prunedOffer), " 0 8 101")
	reinvite := sip.NewRequest(sip.INVITE, dialog.RemoteContact().Address)
	reinvite.AppendHeader(dialog.InviteRequest.Contact())
	reinvite.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	reinvite.SetBody(prunedOffer)

	reinviteCtx, cancelReinvite := context.WithTimeout(ctx, 3*time.Second)
	defer cancelReinvite()
	res, err := dialog.Do(reinviteCtx, reinvite)
	require.NoError(t, err)
	require.Equal(t, sip.StatusOK, res.StatusCode)
	require.NotNil(t, res.Contact())
	contentType := res.ContentType()
	require.NotNil(t, contentType)
	require.Equal(t, "application/sdp", contentType.Value())
	require.NotEmpty(t, res.Body())
	require.Contains(t, string(res.Body()), "c=IN IP4 203.0.113.10")
	require.NotContains(t, string(res.Body()), "c=IN IP4 127.0.0.1")

	// Complete the re-INVITE transaction from the peer/UAC side.
	ack := sip.NewRequest(sip.ACK, res.Contact().Address)
	require.NoError(t, dialog.WriteRequest(ack))
	dialog.Hangup(ctx)
}

func TestIntegrationDialogServerRefer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dialer *Diago
	{
		ua, _ := sipgo.NewUA(sipgo.WithUserAgent("dialer"))
		defer ua.Close()

		dg := NewDiago(ua, WithTransport(
			Transport{
				Transport: "udp",
				BindHost:  "127.0.0.1",
				BindPort:  15071,
				ID:        "udp",
			},
		))

		// Run listener to accepte reinvites, but it should not receive any request
		err := dg.ServeBackground(ctx, nil)
		require.NoError(t, err)
		dialer = dg
	}

	dialCall := func() {
		dialog, err := dialer.NewDialog(sip.Uri{User: "dialer", Host: "127.0.0.1", Port: 15070}, NewDialogOptions{})
		require.NoError(t, err)

		go func() {
			err := dialog.Invite(ctx, InviteClientOptions{
				OnRefer: func(referDialog *DialogClientSession) error {
					// referDialog.
					if err := referDialog.Invite(ctx, InviteClientOptions{}); err != nil {
						return err
					}
					if err := referDialog.Ack(ctx); err != nil {
						return err
					}

					return referDialog.Hangup(ctx)
				},
			})
			require.NoError(t, err)

			dialog.Ack(ctx)
			<-dialog.Context().Done()
			t.Log("Dialog done")
		}()
	}

	// UAS that accepts REFER
	// waitReferDialog := make(chan *DialogServerSession)
	{
		ua, _ := sipgo.NewUA()
		defer ua.Close()

		dg := NewDiago(ua, WithTransport(
			Transport{
				Transport: "udp",
				BindHost:  "127.0.0.1",
				BindPort:  15072,
			},
		))

		err := dg.ServeBackground(ctx, func(d *DialogServerSession) {
			t.Log("Call INVITE due to REFER received")
			// waitReferDialog <- d
			switch d.ToUser() {
			case "busy":
				d.Respond(sip.StatusBusyHere, "Busy Here", nil)
				return
			case "noanswer":
				d.Ringing()
				return
			default:
				d.Answer()
			}

			<-d.Context().Done()
		})
		require.NoError(t, err)
	}

	ua, _ := sipgo.NewUA()
	defer ua.Close()

	dg := NewDiago(ua, WithTransport(
		Transport{
			Transport: "udp",
			BindHost:  "127.0.0.1",
			BindPort:  15070,
		},
	))

	waitDialog := make(chan *DialogServerSession)
	err := dg.ServeBackground(ctx, func(d *DialogServerSession) {
		t.Log("Call received")
		waitDialog <- d
		<-d.Context().Done()
	})
	require.NoError(t, err)

	t.Run("Successfull", func(t *testing.T) {
		dialCall()
		d := <-waitDialog
		defer d.Hangup(ctx)

		err = d.Answer()
		require.NoError(t, err)

		referState := make(chan int)
		err = d.ReferOptions(d.Context(), sip.Uri{Host: "127.0.0.1", Port: 15072}, ReferServerOptions{
			OnNotify: func(statusCode int) {
				referState <- statusCode
			},
		})
		require.NoError(t, err)

		assert.Equal(t, 100, <-referState)
		assert.Equal(t, 200, <-referState)
	})

	t.Run("UnreachableRefer", func(t *testing.T) {
		dialCall()
		d := <-waitDialog
		defer d.Hangup(ctx)

		err = d.Answer()
		require.NoError(t, err)

		referState := make(chan int)
		err = d.ReferOptions(d.Context(), sip.Uri{User: "noanswer", Host: "127.0.0.1", Port: 15072}, ReferServerOptions{
			OnNotify: func(statusCode int) {
				referState <- statusCode
			},
		})
		require.NoError(t, err)

		assert.Equal(t, 100, <-referState)
		assert.Equal(t, sip.StatusTemporarilyUnavailable, <-referState)
	})

	t.Run("BusyRefer", func(t *testing.T) {
		dialCall()
		d := <-waitDialog
		defer d.Hangup(ctx)

		err = d.Answer()
		require.NoError(t, err)

		referState := make(chan int)
		err = d.ReferOptions(d.Context(), sip.Uri{User: "busy", Host: "127.0.0.1", Port: 15072}, ReferServerOptions{
			OnNotify: func(statusCode int) {
				referState <- statusCode
			},
		})
		require.NoError(t, err)

		assert.Equal(t, 100, <-referState)
		assert.Equal(t, sip.StatusBusyHere, <-referState)
	})
}

func TestIntegrationDialogServerPlayback(t *testing.T) {
	rtpBuf := newRTPWriterBuffer()
	dialog := &DialogServerSession{
		DialogMedia: DialogMedia{
			mediaSession:    &media.MediaSession{Codecs: []media.Codec{media.CodecAudioUlaw}},
			RTPPacketWriter: media.NewRTPPacketWriter(rtpBuf, media.CodecAudioUlaw),
		},
	}

	playback, err := dialog.PlaybackCreate()
	require.NoError(t, err)

	initTS := dialog.RTPPacketWriter.InitTimestamp()
	_, err = playback.PlayFile("testdata/files/demo-echodone.wav")
	require.NoError(t, err)
	diffTS := dialog.RTPPacketWriter.PacketHeader.Timestamp - initTS
	assert.Greater(t, diffTS, uint32(1000))

	time.Sleep(100 * time.Millisecond) // 4 frames
	initTS = dialog.RTPPacketWriter.InitTimestamp()
	_, err = playback.PlayFile("testdata/files/demo-echodone.wav")
	require.NoError(t, err)
	diffTS2 := dialog.RTPPacketWriter.PacketHeader.Timestamp - initTS
	t.Log(initTS, diffTS2)

	// Timestamp should be offset more than previous diff by Sleep
	assert.Greater(t, diffTS2, diffTS+5*media.CodecAudioUlaw.SampleTimestamp())
}
