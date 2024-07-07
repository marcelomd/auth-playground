package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

// Some function that receives a user ID and returns an encryption key.
// Could be a DB lookup, or just ignore the ID and return a global key.
type KeyGetter func(id string) ([]byte, error)

const (
	AuthTimeWindow = 1 * time.Hour
	NonceSize      = 32
	TimeFormat     = "20060102T150405Z"
)

// Datetime receives a timestamp string and converts it to a time.Time
func Datetime(s string) (time.Time, error) {
	return time.Parse(TimeFormat, s)
}

// Digest returns the SHA256 hash of some bytes encoded in a base64 string.
func Digest(data []byte) string {
	return Encode64(Hash256(data))
}

// Encode64 encodes some bytes into a base64 string.
func Encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Decode64 decodes a base64 string into bytes
func Decode64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Hash256 returns the SHA256 hash of some bytes.
func Hash256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// Hmac256 returns the HMAC-SHA256 of some bytes.
func Hmac256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// NonceBytes generates a nonce and returns it's bytes.
func NonceBytes() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("could not generate nonce")
	}
	return nonce, nil
}

// NonceString generates a nonce and returns it as a base64 string.
func NonceString() (string, error) {
	nonce, err := NonceBytes()
	return Encode64(nonce), err
}

// NonceUint64 generates a nonce and returns it as an uint64.
func NonceUint64() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return uint64(binary.LittleEndian.Uint64(b[:])), nil
}

// Timestamp formats a time.Time into timestamp string format.
func Timestamp(t time.Time) string {
	return t.Format(TimeFormat)
}

// TimestampIsValid checks if the given timestamp is within the allowed window.
func TimestampIsValid(s string) bool {
	datetime, err := Datetime(s)
	if err != nil {
		return false
	}
	if time.Now().UTC().After(datetime.Add(AuthTimeWindow)) {
		return false
	}
	return true
}
