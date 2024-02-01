# Schnorr Signatures

This document specifies the Schnorr signature scheme over the secp256k1 elliptic curve in combination with the keccak256 hash function implemented in `crysol`.

## Introduction

Schnorr signatures provide a number of advantages compared to ECDSA signatures:

- **Provable secure**: Schnorr signatures are provable secure
- **Non-malleability**: Schnorr signatures are non-malleable
- **Linearity**: Schnorr signatures have multi-signature support, ie they provide a mechanism for collaborating parties to produce a signature that is valid over the sum of their public keys

## Terminology

### Functions

- `H() :: bytes -> bytes32` - Keccak256 Function
- `()ₓ :: Secp256k1::PublicKey -> uint` - Function returning the x coordinate of given public key
- `()ₚ :: Secp256k1::PublicKey -> uint ∊ {0, 1}` - Function returning the parity of the y coordinate of given public key
- `()ₑ :: Secp256k1::PublicKey -> address` - Function returning the Ethereum address of given public key

### Operators

- `‖` - Concatenation operator defined via `abi.encodePacked()`

### Constants

- `G :: Secp256k1::PublicKey` - Generator of secp256k1
- `Q :: uint` - Order of secp256k1

### Variables

- `sk :: Secp256k1::SecretKey` - The signer's secret key
- `Pk :: Secp256k1::PublicKey` - The signer's public key, ie `[sk]G`
- `m :: bytes32` - The keccak256 hash digest to sign


## Signature Creation

1. Derive a cryptographically secure nonce from `m` and `sk`.

> TODO: Current implementation uses `keccak256(sk ‖ m) % Q`. Want to move to RFC-6979
>
> Note that the probability of `keccak256(sk ‖ m) ∊ {0, Q}` is negligible.

```
k ∊ [1, Q)
```

2. Compute the nonce's public key

```
R = [k]G
```

3. Derive `commitment` being the Ethereum address of the nonce's public key

```
commitment = Rₑ
```

4. Construct challenge `e`

```
e = H(Pkₓ ‖ Pkₚ ‖ m ‖ r)
```

5. Compute `signature`

```
signature = k + (e * sk) (mod Q)
```

=> Let tuple `(signature, commitment)` be the Schnorr signature

## Signature Verification

* **Input**: `(Pk, m, signature, commitment)`
* **Output**: `True` if signature verification succeeds, `False` otherwise

1. Construct challenge `e`

```
e = H(Pkₓ ‖ Pkₚ ‖ m ‖ r)
```

2. Compute Ethereum address of nonce's public key

```
  ([signature]G - [e]Pk)ₑ        | signature = k + (e * sk)
= ([k + (e * sk)]G - [e]Pk)ₑ     | Pk = [sk]G
= ([k + (e * sk)]G - [e * sk]G)ₑ | Distributive Law
= ([k + (e * sk) - (e * sk)]G)ₑ  | (e * sk) - (e * sk) = 0
= ([k]G)ₑ                        | R = [k]G
= Rₑ
```

3. Return `True` if `([signature]G - [e]P)ₑ == commitment`, `False` otherwise

## Security Notes

> TODO: End goal musig2 and as much BIP-340 compatible as possible.

Note that `crysol`'s Schnorr scheme deviates slightly from the classical Schnorr signature scheme.

Instead of using the secp256k1 point `R = [k]G` directly, this scheme uses the Ethereum address of the point `R` which decreases the difficulty of brute-forcing the signature
from 256 bits (trying random secp256k1 points) to 160 bits (trying random Ethereum addresses).

However, the difficulty of cracking a secp256k1 public key using the baby-step giant-step algorithm is `O(√Q)`[^baby-step-giant-step-wikipedia]. Note that `√Q ~ 3.4e38 < 128 bit`.

Therefore, this signing scheme does not weaken the overall security.

## Implementation Notes

This implementation uses the ecrecover precompile to perform the necessary elliptic curve multiplication in secp256k1 during the verification process.

The ecrecover precompile can roughly be implemented in python via[^vitalik-ethresearch-post]:
```python
def ecdsa_raw_recover(msghash, vrs):
   v, r, s = vrs
   y = # (get y coordinate for EC point with x=r, with same parity as v)
   Gz = jacobian_multiply((Gx, Gy, 1), (Q - hash_to_int(msghash)) % Q)
   XY = jacobian_multiply((r, y, 1), s)
   Qr = jacobian_add(Gz, XY)
   N = jacobian_multiply(Qr, inv(r, Q))
   return from_jacobian(N)
```

A single ecrecover call can compute `([signature]G - [e]Pk)ₑ = ([k]G)ₑ = Rₑ = commitment` via the following inputs:
```
msghash = -signature * Pkₓ
v       = Pkₚ + 27
r       = Pkₓ
s       = Q - (e * Pkₓ)
```

Note that ecrecover returns the Ethereum address of `R` and not `R` itself.

The ecrecover call then digests to:
```
Gz = [Q - (-signature * Pkₓ)]G  | Double negation
   = [Q + (signature * Pkₓ)]G   | Addition with Q can be removed in (mod Q)
   = [signature * Pkₓ]G         | sig = k + (e * sk)
   = [(k + (e * sk)) * Pkₓ]G

XY = [Q - (e * Pkₓ)]Pk        | Pk = [sk]G
   = [(Q - (e * Pkₓ)) * sk]G

Qr = Gz + XY                                            | Gz = [(k + (e * sk)) * Pkₓ]G
   = [(k + (e * sk)) * Pkₓ]G + XY                       | XY = [(Q - (e * Pkₓ)) * sk]G
   = [(k + (e * sk)) * Pkₓ]G + [(Q - (e * Pkₓ)) * sk]G

N  = Qr * Pkₓ⁻¹                                                         | Qr = [(k + (e * sk)) * Pkₓ]G + [(Q - (e * Pkₓ)) * sk]G
   = [(k + (e * sk)) * Pkₓ]G + [(Q - (e * Pkₓ)) * sk]G * Pkₓ⁻¹          | Distributive law
   = [(k + (e * sk)) * Pkₓ * Pkₓ⁻¹]G + [(Q - (e * Pkₓ)) * sk * Pkₓ⁻¹]G  | Pkₓ * Pkₓ⁻¹ = 1
   = [(k + (e * sk))]G + [Q - e * sk]G                                  | signature = k + (e * sk)
   = [signature]G + [Q - e * x]G                                        | Q - (e * sk) = -(e * sk) in (mod Q)
   = [signature]G - [e * sk]G                                           | Pk = [sk]G
   = [signature]G - [e]Pk
```


<!--- References --->
[^baby-step-giant-step-wikipedia]:[Wikipedia: Baby-step giant-step Algorithm](https://en.wikipedia.org/wiki/Baby-step_giant-step)
[^vitalik-ethresearch-post]:[ethresear.ch: You can kinda abuse ecrecode to do ecmul in secp256k1 today](https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384)
