package authv1

import (
	"auth-playground/crypto"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalid = fmt.Errorf("invalid token")
)

func makeStringToSign(id, datetime, action, resource, digest string) string {
	return strings.Join([]string{id, datetime, action, resource, digest}, ":")
}

func makeSigningKey(id string, timestamp string, action string, resource string, key []byte) []byte {
	k := crypto.Hmac256(key, []byte(id))
	k = crypto.Hmac256(k, []byte(timestamp))
	k = crypto.Hmac256(k, []byte(action))
	k = crypto.Hmac256(k, []byte(resource))
	return k
}

func makeSignature(stringToSign string, signingKey []byte) string {
	return crypto.Encode64(crypto.Hmac256(signingKey, []byte(stringToSign)))
}

func sign(id string, timestamp string, action string, resource string, digest string, key []byte) (string, string) {
	stringToSign := makeStringToSign(id, timestamp, action, resource, digest)
	signingKey := makeSigningKey(id, timestamp, action, resource, key)
	signature := makeSignature(stringToSign, signingKey)
	return stringToSign, signature
}

func Tokenize(id string, datetime time.Time, action string, resource string, data []byte, key []byte) string {
	timestamp := crypto.Timestamp(datetime)
	digest := crypto.Digest(data)
	prefix, signature := sign(id, timestamp, action, resource, digest, key)
	return strings.Join([]string{prefix, signature}, ":")
}

func Validate(token string, getKey crypto.KeyGetter, action string, resource string, data []byte) (bool, error) {
	parts := strings.Split(token, ":")
	if len(parts) != 6 {
		return false, ErrInvalid
	}

	tId := parts[0]
	tTimestamp := parts[1]
	tAction := parts[2]
	tResource := parts[3]
	tDigest := parts[4]
	tSignature := parts[5]

	if !crypto.TimestampIsValid(tTimestamp) {
		return false, ErrInvalid
	}

	if tAction != action {
		return false, ErrInvalid
	}

	if tResource != resource {
		return false, ErrInvalid
	}

	if tDigest != crypto.Digest(data) {
		return false, ErrInvalid
	}

	key, err := getKey(tId)
	if err != nil {
		return false, err
	}

	_, expected := sign(tId, tTimestamp, tAction, tResource, tDigest, key)
	if tSignature != expected {
		return false, ErrInvalid
	}

	return true, nil
}
