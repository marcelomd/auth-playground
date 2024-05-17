package authv3

import (
	"auth-playground/crypto"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNonce   = fmt.Errorf("can't generate nonce")
	ErrInvalid = fmt.Errorf("invalid token")
)

func makeStringToSign(id string, timestamp string, nonce string, digest string) string {
	return strings.Join([]string{id, timestamp, nonce, digest}, ":")
}

func makeSigningKey(id string, timestamp string, nonce string, key []byte) []byte {
	k := crypto.Hmac256(key, []byte(id))
	k = crypto.Hmac256(k, []byte(timestamp))
	k = crypto.Hmac256(k, []byte(nonce))
	return k
}

func makeSignature(stringToSign string, signingKey []byte) string {
	return crypto.Encode64(crypto.Hmac256(signingKey, []byte(stringToSign)))
}

func sign(id string, timestamp string, nonce string, digest string, key []byte) (string, string) {
	stringToSign := makeStringToSign(id, timestamp, nonce, digest)
	signingKey := makeSigningKey(id, timestamp, nonce, key)
	signature := makeSignature(stringToSign, signingKey)
	return stringToSign, signature
}

func Tokenize(id string, datetime time.Time, data []byte, key []byte) (string, error) {
	timestamp := crypto.Timestamp(datetime)
	nonce, err := crypto.NonceString()
	if err != nil {
		return "", ErrNonce
	}
	digest := crypto.Digest(data)
	prefix, signature := sign(id, timestamp, nonce, digest, key)
	return strings.Join([]string{prefix, signature}, ":"), nil
}

func Validate(token string, getKey crypto.KeyGetter, data []byte) (bool, error) {
	parts := strings.Split(token, ":")

	tId := parts[0]
	tTimestamp := parts[1]
	tNonce := parts[2]
	tDigest := parts[3]
	tSignature := parts[4]

	if !crypto.TimestampIsValid(tTimestamp) {
		return false, ErrInvalid
	}

	if tDigest != crypto.Digest(data) {
		return false, ErrInvalid
	}

	key, err := getKey(tId)
	if err != nil {
		return false, err
	}

	_, expected := sign(tId, tTimestamp, tNonce, tDigest, key)
	if tSignature != expected {
		return false, ErrInvalid
	}

	return true, nil
}
