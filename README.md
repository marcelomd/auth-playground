# Auth playground

This repository contains 3 authentication schemes that I wrote as an exercise. V1 ended up being used in production and worked well for our use case, low latency REST requests.

I named them V1, V2 and V3, and they are variantions on the same theme. The original idea came from [AWS's V4 signature](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html). Other sources of inspiration were [JWT](https://jwt.io/introduction) and [Fernet](https://github.com/fernet/spec/blob/master/Spec.md)

I've created a module for each, plus two example programs. One that simply calls the primitives directly and a second that shows how to use it as a authenctication middleware.


## Basic idea

I'm not a cryptography or security expert, but, as far as I understand, "adding" elements to the signing key, you make it stronger, harder to duplicate and predict. Helps to prevent replay attacks. By using request specific data, you make each key specific to that request. Also, by incorporating a timestamp, you make the request valid onl y for a window of time.

Maybe this is an illusion, because every piece of extra entropy is passed in the token itself, and all of it is just as strong as the original secret key. It will still protect against rainbow tables and replays.

Again, I'm not an expert. I'd love to have my assumptions corrected here.


## V1

This is a simplification of the AWS V4 signature. Here the token is composed by the `timestamp`, `action` to be performed, `resource` we will act upon and the `data` we're passing. `action` and `resource` originally were the HTTP verb and path.

The token format is:

`<user id>:<timestamp as ISO8601 string>:<action>:<resource>:<SHA256 hash of the data encoded in base64>:<signature in base64>`

The token is signed with a key derived by cascaded HMAC-SHA256 of the `user secret key`, `user id`, `timestamp`, `action`, and `resource`. It is also base64 encoded.

The signature is then appended to the other fields of the token.

Verification is done by building the token using data from the request itself.


## V2

This is a more generic version of V1. Instead of using `action` and `resource`, we're passing an array of strings that will be used to build the token and derive the signing key. We can use this array to use hashes, salts, nonces, tokens, versions, etc.

The token format is:

`<user id>:<timestamp as ISO8601 string>:<list of strings separated by :>:<signature in base64>`


## V3

This is the simplest version. This one uses the user id, a timestamp, a random nonce, and the hash of the data as entropy.

The token format is:

`<user id>:<timestamp as ISO8601 string>:<nonce in base 64>:<SHA256 hash of the data encoded in base64>:<signature in base64>`

This one is probably as secure as the other ones.


## User IDs and keys

Every auth scheme here uses a per-user key. In practical terms the developer needs to provide a function that takes the user id and returns the secret key.

This assumes the key is exchanged in some way and stored securely by the user.

The key of course can be a global key for everyone, or something like that.