package authv2

import (
	"auth-playground/crypto"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	ErrInvalid = fmt.Errorf("invalid token")
)

func makeStringToSign(id string, timestamp string, entropy []string) string {
	s := []string{id, timestamp}
	s = append(s, entropy...)
	return strings.Join(s, ":")
}

func makeSigningKey(id string, timestamp string, entropy []string, key []byte) []byte {
	k := crypto.Hmac256(key, []byte(id))
	k = crypto.Hmac256(k, []byte(timestamp))
	for _, e := range entropy {
		k = crypto.Hmac256(k, []byte(e))
	}
	return k
}

func makeSignature(stringToSign string, signingKey []byte) string {
	return crypto.Encode64(crypto.Hmac256(signingKey, []byte(stringToSign)))
}

func sign(id string, timestamp string, entropy []string, key []byte) (string, string) {
	stringToSign := makeStringToSign(id, timestamp, entropy)
	signingKey := makeSigningKey(id, timestamp, entropy, key)
	signature := makeSignature(stringToSign, signingKey)
	return stringToSign, signature
}

func Tokenize(id string, datetime time.Time, entropy []string, key []byte) string {
	timestamp := crypto.Timestamp(datetime)
	prefix, signature := sign(id, timestamp, entropy, key)
	return strings.Join([]string{prefix, signature}, ":")
}

func Validate(token string, getKey crypto.KeyGetter, entropy []string) (bool, error) {
	parts := strings.Split(token, ":")
	partsLen := len(parts)

	tId := parts[0]
	tTimestamp := parts[1]
	tEntropy := parts[2 : partsLen-1]
	tSignature := parts[partsLen-1]

	if !crypto.TimestampIsValid(tTimestamp) {
		return false, ErrInvalid
	}

	if !slices.Equal(tEntropy, entropy) {
		return false, ErrInvalid
	}

	key, err := getKey(tId)
	if err != nil {
		return false, err
	}

	_, expected := sign(tId, tTimestamp, tEntropy, key)
	if tSignature != expected {
		return false, ErrInvalid
	}

	return true, nil
}
