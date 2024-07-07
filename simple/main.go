package main

import (
	"auth-playground/authv1"
	"auth-playground/authv2"
	"auth-playground/authv3"
	"auth-playground/authv4"
	"auth-playground/crypto"
	"fmt"
	"time"
)

func keyGetter(id string) ([]byte, error) {
	if id == "user-id" {
		return []byte("user-key"), nil
	}
	return nil, fmt.Errorf("user not found")
}

func main() {
	id := "user-id"
	datetime := time.Now().UTC()
	action := "POST"
	resource := "/path/to/resource"
	data := []byte("{'burger':'fries'}")
	entropy := []string{"broccoli", action, resource, crypto.Digest(data)}
	key := []byte("user-key")
	role := "chef"

	token1 := authv1.Tokenize(id, datetime, action, resource, data, key)
	fmt.Println("Token 1", token1)
	valid1, err := authv1.Validate(token1, keyGetter, action, resource, data)
	fmt.Println("valid 1", valid1, err)

	token2 := authv2.Tokenize(id, datetime, entropy, key)
	fmt.Println("Token 2", token2)
	valid2, err := authv2.Validate(token2, keyGetter, entropy)
	fmt.Println("valid 2", valid2, err)

	token3, err := authv3.Tokenize(id, datetime, data, key)
	fmt.Println("Token 3", token3, err)
	valid3, err := authv3.Validate(token3, keyGetter, data)
	fmt.Println("valid 3", valid3, err)

	token4, err := authv4.Tokenize(id, role, key)
	fmt.Println("Token 4", token4, err)
	data4, valid4, err := authv4.Validate(token4, keyGetter)
	fmt.Println("valid 4", data4, valid4, err)
}
