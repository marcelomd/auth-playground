package authv4

import (
	"auth-playground/crypto"
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

type tokenVersion byte

const (
	TokenV1 = iota
)

type tokenType byte

const (
	AccessTokenType tokenType = iota
	RefreshTokenType
)

type AuthData struct {
	Version   tokenVersion `msgpack:"a"`
	TokenType tokenType    `msgpack:"b"`
	Nonce     uint64       `msgpack:"c"`
	Expires   int64        `msgpack:"d"`
	Id        string       `msgpack:"e"`
	Role      string       `msgpack:"f"`
}

var (
	ErrNonce   = fmt.Errorf("can't generate nonce")
	ErrMarshal = fmt.Errorf("can't marshal token")
	ErrInvalid = fmt.Errorf("invalid token")
)

func Tokenize(id string, role string, key []byte) (string, error) {
	nonce, err := crypto.NonceUint64()
	if err != nil {
		return "", ErrNonce
	}
	data := AuthData{
		Version:   TokenV1,
		TokenType: AccessTokenType,
		Nonce:     nonce,
		Expires:   time.Now().UTC().Add(crypto.AuthTimeWindow).Unix(),
		Id:        id,
		Role:      role,
	}
	payload, err := msgpack.Marshal(data)
	if err != nil {
		return "", ErrMarshal
	}
	sig := crypto.Hmac256(key, payload)
	return strings.Join([]string{id, crypto.Encode64(payload), crypto.Encode64(sig)}, ":"), nil
}

func Validate(token string, getKey crypto.KeyGetter) (AuthData, bool, error) {
	authData := AuthData{}

	parts := strings.Split(token, ":")
	if len(parts) != 3 {
		return authData, false, ErrInvalid
	}

	tId := parts[0]
	tPayload := parts[1]
	tSignature := parts[2]

	key, err := getKey(tId)
	if err != nil {
		return authData, false, err
	}

	payload, err := crypto.Decode64(tPayload)
	if err != nil {
		return authData, false, ErrInvalid
	}

	signature, err := crypto.Decode64(tSignature)
	if err != nil {
		return authData, false, ErrInvalid
	}

	expected := crypto.Hmac256(key, payload)
	if !bytes.Equal(signature, expected) {
		return authData, false, err
	}

	err = msgpack.Unmarshal(payload, &authData)
	if err != nil {
		return authData, false, ErrInvalid
	}

	if authData.Version != TokenV1 {
		return authData, false, ErrInvalid
	}

	if authData.Id != tId {
		return authData, false, ErrInvalid
	}

	if authData.Expires < time.Now().UTC().Unix() {
		return authData, false, ErrInvalid
	}

	return authData, true, nil
}
