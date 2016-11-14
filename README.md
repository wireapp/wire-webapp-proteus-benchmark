# Proteus.js Benchmarks

## Setup

**Lenovo Yoga 900-13ISK**
- Intel® Core™ i7-6500U Prozessor (3.1 GHz)
- 512 GB SSD
- 16 GB RAM
- Windows 10 Home (64 Bit)

## Tests

### sodium.crypto_auth_hmacsha256

> Keyed message authentication using HMAC-SHA-256. The crypto_auth_hmacsha256(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) function authenticates a message `in` whose length is `inlen` using the secret key `k` whose length is `crypto_auth_hmacsha256_KEYBYTES`, and puts the authenticator into `out` (crypto_auth_hmacsha256_BYTES bytes).

### sodium.crypto_auth_hmacsha256_verify

> The crypto_auth_hmacsha256_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k) function verifies in constant time that `h` is a correct authenticator for the message `in` whose length is `inlen` under a secret key `k`.

### sodium.crypto_hash_sha256

> Single-part SHA-256 hashing. The function is not keyed and is thus deterministic. In addition, the untruncated version is vulnerable to length extension attacks. This function is also not suitable for hashing passwords.

### sodium.crypto_scalarmult

> This function can be used to compute a shared secret `q` given a user's secret key and another user's public key. `n` is `crypto_scalarmult_SCALARBYTES` bytes long, `p` and the output are `crypto_scalarmult_BYTES` bytes long. `q` represents the X coordinate of a point on the curve. As a result, the number of possible keys is limited to the group size (≈2^252), and the key distribution is not uniform. Usage: int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p);

### sodium.crypto_sign_detached

> The crypto_sign_detached(unsigned char *sig, unsigned long long *siglen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk) function signs the message `m` whose length is `mlen` bytes, using the secret key `sk`, and puts the signature into `sig`, which can be up to `crypto_sign_BYTES` bytes long.

### sodium.crypto_sign_ed25519_pk_to_curve25519

> The int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk, const unsigned char *ed25519_pk) function converts an Ed25519 public key `ed25519_pk` to a Curve25519 public key and stores it into `curve25519_pk`.

### sodium.crypto_sign_ed25519_sk_to_curve25519

> The crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk, const unsigned char *ed25519_sk) function converts an Ed25519 secret key `ed25519_sk` to a Curve25519 secret key and stores it into `curve25519_sk`.

### sodium.crypto_sign_keypair

> The crypto_sign_keypair(unsigned char *pk, unsigned char *sk) function randomly generates a secret key and a corresponding public key. The public key is put into `pk` (`crypto_sign_PUBLICKEYBYTES` bytes) and the secret key into `sk` (`crypto_sign_SECRETKEYBYTES` bytes).

**Benchmark:**

- Chrome Version 53.0.2785.143 m (64-bit): 255 ops/sec
- Firefox Version 52.0a1 (2016-10-13) (64-bit): 1,159 ops/sec

### sodium.crypto_stream_chacha20_xor

> The crypto_stream_chacha20_xor() function encrypts a message `m` of length `mlen` using a nonce `n` (`crypto_stream_chacha20_NONCEBYTES` bytes) and a secret key `k` (`crypto_stream_chacha20_KEYBYTES` bytes).
