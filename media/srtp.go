// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2024, Emir Aganovic

package media

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/pion/srtp/v3"
)

// RFC 4568 section 6.2.1: either packet limit exhausts the master key.
const (
	sdesMaxRTPPackets  uint64 = 1 << 48
	sdesMaxRTCPPackets uint64 = 1 << 31
)

var errSDESLifetimeExhausted = errors.New("SDES key lifetime exhausted")

// RFC 4568 section 6.1 caps the MKI length at 128 bytes.
const sdesMaxMKILength = 128

// When the peer's key carries an MKI, ours does too, in the form Microsoft-style
// peers use: a 2^31 lifetime and a 1-byte MKI of 1. Some of them reject a key
// without an MKI once they have offered one.
const sdesLocalMKIParams = "|2^31|1:1"

var sdesLocalMKI = []byte{1}

// parseSDESInline parses inline:<key||salt>["|" lifetime]["|" MKI ":" length].
// The MKI is returned as length big-endian bytes, or nil when absent.
func parseSDESInline(value string) (key []byte, lifetime uint64, mki []byte, err error) {
	inline, ok := strings.CutPrefix(value, "inline:")
	if !ok {
		return nil, 0, nil, errors.New("unsupported SDES key method")
	}
	if strings.Contains(inline, ";") {
		return nil, 0, nil, errors.New("multiple SDES keys are not supported")
	}
	params := strings.Split(inline, "|")
	encoded, params := params[0], params[1:]
	if n := len(params); n > 0 && strings.Contains(params[n-1], ":") {
		mki, err = parseSDESMKI(params[n-1])
		if err != nil {
			return nil, 0, nil, err
		}
		params = params[:n-1]
	}
	if len(params) > 1 {
		return nil, 0, nil, errors.New("invalid SDES key parameters")
	}
	lifetime = sdesMaxRTPPackets
	if len(params) == 1 {
		digits, powerOfTwo := strings.CutPrefix(params[0], "2^")
		// RFC 4568 section 6.1 forbids leading zeroes despite the broader ABNF.
		if len(digits) > 1 && digits[0] == '0' {
			return nil, 0, nil, errors.New("invalid SDES key lifetime")
		}
		lifetime, err = strconv.ParseUint(digits, 10, 64)
		if err != nil {
			return nil, 0, nil, errors.New("invalid SDES key lifetime")
		}
		if powerOfTwo {
			if lifetime > 48 {
				return nil, 0, nil, errors.New("SDES key lifetime exceeds crypto-suite limit")
			}
			lifetime = uint64(1) << lifetime
		}
		if lifetime == 0 || lifetime > sdesMaxRTPPackets {
			return nil, 0, nil, errors.New("invalid SDES key lifetime")
		}
	}
	key, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to decode SDES key: %w", err)
	}
	return key, lifetime, mki, nil
}

// parseSDESMKI parses the decimal "<value>:<length>" MKI parameter.
func parseSDESMKI(param string) ([]byte, error) {
	valueStr, lengthStr, _ := strings.Cut(param, ":")
	value, err := strconv.ParseUint(valueStr, 10, 64)
	if err != nil {
		return nil, errors.New("invalid SDES MKI value")
	}
	length, err := strconv.ParseUint(lengthStr, 10, 8)
	if err != nil || length == 0 || length > sdesMaxMKILength {
		return nil, errors.New("invalid SDES MKI length")
	}
	mki := make([]byte, length)
	for i := len(mki) - 1; i >= 0 && value > 0; i-- {
		mki[i] = byte(value)
		value >>= 8
	}
	if value > 0 {
		return nil, errors.New("SDES MKI value exceeds its length")
	}
	return mki, nil
}

// Shared across session forks when the peer re-offers the same key. RTP and
// RTCP have separate readers, but exhaustion of either retires the key for both.
type sdesKeyLifetime struct {
	key []byte
	mki []byte
	// ctx is the remote context for key, reused by forks so ROC and replay
	// state survive a same-key re-offer. pion contexts are not goroutine safe;
	// see DialogMedia.replaceRTPSessionUnsafe for the single-reader invariant.
	ctx         *srtp.Context
	mu          sync.Mutex
	limit       uint64
	rtpPackets  uint64
	rtcpPackets uint64
}

func (s *sdesKeyLifetime) accept(rtcp bool) error {
	if s == nil {
		return nil // DTLS keys do not carry an SDES lifetime.
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rtpPackets >= s.limit || s.rtcpPackets >= min(s.limit, sdesMaxRTCPPackets) {
		return errSDESLifetimeExhausted
	}
	if rtcp {
		s.rtcpPackets++
	} else {
		s.rtpPackets++
	}
	return nil
}

const (
	SRTPProfileAes128CmHmacSha1_80 uint16 = uint16(srtp.ProtectionProfileAes128CmHmacSha1_80)
	SRTPProfileAes256CmHmacSha1_80 uint16 = uint16(srtp.ProtectionProfileAes256CmHmacSha1_80)
	SRTPProfileAeadAes128Gcm       uint16 = uint16(srtp.ProtectionProfileAeadAes128Gcm)
	SRTPProfileAeadAes256Gcm       uint16 = uint16(srtp.ProtectionProfileAeadAes256Gcm)
	SRTPProfileNullHmacSha1_80     uint16 = uint16(srtp.ProtectionProfileNullHmacSha1_80)
)

func srtpProfileString(p srtp.ProtectionProfile) string {
	switch p {
	case srtp.ProtectionProfileAes128CmHmacSha1_80:
		return "AES_CM_128_HMAC_SHA1_80"
	case srtp.ProtectionProfileAes256CmHmacSha1_80:
		return "AES_CM_256_HMAC_SHA1_80"
	case srtp.ProtectionProfileAeadAes128Gcm:
		return "AEAD_AES_128_GCM"
	case srtp.ProtectionProfileAeadAes256Gcm:
		return "AEAD_AES_256_GCM"
	case srtp.ProtectionProfileNullHmacSha1_80:
		return "NULL_HMAC_SHA1_80"
	}
	// TODO: this is still wrong
	return strings.TrimPrefix("SRTP_", p.String())
}

func srtpProfileParse(alg string) srtp.ProtectionProfile {
	var profile srtp.ProtectionProfile
	switch alg {
	case "AES_CM_128_HMAC_SHA1_80":
		profile = srtp.ProtectionProfileAes128CmHmacSha1_80
	case "AES_CM_256_HMAC_SHA1_80":
		profile = srtp.ProtectionProfileAes256CmHmacSha1_80
	case "AEAD_AES_128_GCM":
		profile = srtp.ProtectionProfileAeadAes128Gcm
	case "AEAD_AES_256_GCM":
		profile = srtp.ProtectionProfileAeadAes256Gcm
	case "NULL_HMAC_SHA1_80":
		profile = srtp.ProtectionProfileNullHmacSha1_80
	}
	return profile
}
