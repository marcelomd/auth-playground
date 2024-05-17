package main

import (
	"auth-playground/authv1"
	"auth-playground/authv2"
	"auth-playground/authv3"
	"auth-playground/crypto"
	"bytes"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"time"
)

// readBodyBytes returns the body of the request and resets it on the original request.
func readBodyBytes(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, nil
}

// Example middleware for the authv1 scheme.
//
// Action is the HTTP method and resource is the path.
func authMiddlewareV1(keyGetter crypto.KeyGetter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("AuthV1")
		action := r.Method
		resource := html.EscapeString(r.URL.Path)
		data, err := readBodyBytes(r)
		if err != nil {
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}

		valid, err := authv1.Validate(token, keyGetter, action, resource, data)
		if err != nil {
			http.Error(w, "token v1 not valid", http.StatusBadRequest)
			return
		}
		if !valid {
			http.Error(w, "token v1 not valid", http.StatusBadRequest)
			return
		}

		fmt.Println("authv1 ok")
		next.ServeHTTP(w, r)
	})
}

// Example middleware for the authv2 scheme.
//
// Entropy is built using whatever contract exists between client and server. In this case
// we're using parts of the request itself (HTTP verb, path, hash of data) and a string.
// This string could be anything, like a serial or version number.
func authMiddlewareV2(keyGetter crypto.KeyGetter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("AuthV2")
		action := r.Method
		resource := html.EscapeString(r.URL.Path)
		data, err := readBodyBytes(r)
		if err != nil {
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}
		entropy := []string{
			"broccoli",
			action,
			resource,
			crypto.Digest(data),
		}

		valid, err := authv2.Validate(token, keyGetter, entropy)
		if err != nil {
			http.Error(w, "token v2 not valid", http.StatusBadRequest)
			return
		}
		if !valid {
			http.Error(w, "token v2 not valid", http.StatusBadRequest)
			return
		}

		fmt.Println("authv2 ok")
		next.ServeHTTP(w, r)
	})
}

// Example middleware for the authv3 scheme.
//
// This is the simplest scheme.
func authMiddlewareV3(keyGetter crypto.KeyGetter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("AuthV3")
		data, err := readBodyBytes(r)
		if err != nil {
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}
		valid, err := authv3.Validate(token, keyGetter, data)
		if err != nil {
			http.Error(w, "token v3 not valid", http.StatusBadRequest)
			return
		}
		if !valid {
			http.Error(w, "token v3 not valid", http.StatusBadRequest)
			return
		}
		fmt.Println("authv3 ok")
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Some data for us to use in our request
	var (
		id       = "user-id"
		datetime = time.Now().UTC()
		action   = "POST"
		resource = "/path/to/resource"
		data     = []byte("{'burger':'fries'}")
		entropy  = []string{"broccoli", action, resource, crypto.Digest(data)}
		key      = []byte("user-key")
	)
	// Simulates a query to the DB
	keyGetter := func(s string) ([]byte, error) {
		if s == id {
			return key, nil
		}
		return nil, fmt.Errorf("user not found")
	}

	// We will use one request for all schemes, just to keep things simple. Middleware config looks ugly, tho.
	tokenV1 := authv1.Tokenize(id, datetime, action, resource, data, key)
	tokenV2 := authv2.Tokenize(id, datetime, entropy, key)
	tokenV3, _ := authv3.Tokenize(id, datetime, data, key)

	req := httptest.NewRequest("POST", "http://zuchini"+resource, bytes.NewBuffer(data))
	req.Header.Set("AuthV1", tokenV1)
	req.Header.Set("AuthV2", tokenV2)
	req.Header.Set("AuthV3", tokenV3)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("handler")
		w.Write([]byte("OK"))
	})
	handlerToTest := authMiddlewareV1(keyGetter, authMiddlewareV2(keyGetter, authMiddlewareV3(keyGetter, nextHandler)))
	handlerToTest.ServeHTTP(httptest.NewRecorder(), req)
}
