package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// RFC 6238 TOTP: HMAC-SHA-1, 6 digits, 30 s steps, +/- one step tolerance.
const (
	totpStep   = 30
	totpDigits = 6
)

func NewTOTPSecret() []byte {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func TOTPBase32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

func TOTPURI(secret []byte, account string) string {
	v := url.Values{}
	v.Set("secret", TOTPBase32(secret))
	v.Set("issuer", "Yunmen")
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/Yunmen:" + url.PathEscape(account) + "?" + v.Encode()
}

func totpAt(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, code%1_000_000)
}

// TOTPCode returns the code for time t (used by tests and the init flow).
func TOTPCode(secret []byte, t time.Time) string { return totpAt(secret, t.Unix()/totpStep) }

// MatchTOTP returns the matching time step, or false. The caller must still
// record the step atomically to prevent replay.
func MatchTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / totpStep
	for _, step := range []int64{cur, cur - 1, cur + 1} {
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
