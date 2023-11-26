# Schnorr Signatures

This document specifies the Schnorr signature scheme over the secp256k1 elliptic curve in combination with the keccak256 hash function implemented in `crysol`.

## Introduction

Schnorr signatures provide a number of advantages compared to [ECDSA signatures](./ECDSA.md):

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

- `x :: Secp256k1::PrivateKey` - The signer's private key
- `P :: Secp256k1::PublicKey` - The signer's public key, ie `[x]G`
- `m :: bytes32` - The keccak256 hash digest to sign


## Signature Creation

1. Derive a cryptographically secure nonce from `m` and `x` via `keccak256(x ‖ m) % Q`

Note that the probability of `keccak256(x ‖ m) ∊ {0, Q}` is negligible.

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
e = H(Pₓ ‖ Pₚ ‖ m ‖ r)
```

5. Compute `signature`

```
signature = k + (e * x) (mod Q)
```

=> Let tuple `(signature, commitment)` be the Schnorr signature

## Signature Verification

**Input**: `(P, m, signature, commitment)`
**Output**: `True` if signature verification succeeds, `False` otherwise

1. Construct challenge `e`

```
e = H(Pₓ ‖ Pₚ ‖ m ‖ r)
```

2. Compute nonce's public key

```
  [signature]G - [e]P       | signature = k + (e * x)
= [k + (e * x)]G - [e]P     | P = [x]G
= [k + (e * x)]G - [e * x]G | Distributive Law
= [k + (e * x) - (e * x)]G  | (e * x) - (e * x) = 0
= [k]G                      | R = [k]G
= R
```

3. Derive `commitment` from nonce's public key

```
commitment = Rₑ
```

3. Return `True` if `([signature]G - [e]P)ₑ == commitment`, `False` otherwise

## Security Notes

Note that `crysol`'s Schnorr scheme deviates slightly from the classical Schnorr signature scheme.

Instead of using the secp256k1 point `R = [k]G` directly, this scheme uses the Ethereum address of the point `R`, which decreases the difficulty of brute-forcing the signature from 256 bits (trying random secp256k1 points) to 160 bits (trying random Ethereum addresses).

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

A single ecrecover call can compute `([signature]G - [e]P)ₑ = ([k]G)ₑ = Rₑ = commitment` via the
following inputs:
```
msghash = -signature * Pₓ
v       = Pₚ + 27
r       = Pₓ
s       = Q - (e * Pₓ)
```

Note that ecrecover returns the Ethereum address of `R` and not `R` itself.

The ecrecover call then digests to:
```
Gz = [Q - (-signature * Pₓ)]G     | Double negation
   = [Q + (signature * Pₓ)]G      | Addition with Q can be removed in (mod Q)
   = [signature * Pₓ]G            | sig = k + (e * x)
   = [(k + (e * x)) * Pₓ]G

XY = [Q - (e * Pₓ)]P        | P = [x]G
   = [(Q - (e * Pₓ)) * x]G

Qr = Gz + XY                                        | Gz = [(k + (e * x)) * Pₓ]G
   = [(k + (e * x)) * Pₓ]G + XY                     | XY = [(Q - (e * Pₓ)) * x]G
   = [(k + (e * x)) * Pₓ]G + [(Q - (e * Pₓ)) * x]G

N  = Qr * Pₓ⁻¹                                                    | Qr = [(k + (e * x)) * Pₓ]G + [(Q - (e * Pₓ)) * x]G
   = [(k + (e * x)) * Pₓ]G + [(Q - (e * Pₓ)) * x]G * Pₓ⁻¹         | Distributive law
   = [(k + (e * x)) * Pₓ * Pₓ⁻¹]G + [(Q - (e * Pₓ)) * x * Pₓ⁻¹]G  | Pₓ * Pₓ⁻¹ = 1
   = [(k + (e * x))]G + [Q - e * x]G                              | signature = k + (e * x)
   = [signature]G + [Q - e * x]G                                  | Q - (e * x) = -(e * x) in (mod Q)
   = [signature]G - [e * x]G                                      | P = [x]G
   = [signature]G - [e]P
```


<!--- References --->
[^baby-step-giant-step-wikipedia]:[Wikipedia: Baby-step giant-step Algorithm](https://en.wikipedia.org/wiki/Baby-step_giant-step)
[^vitalik-ethresearch-post]:[ethresear.ch: You can kinda abuse ecrecode to do ecmul in secp256k1 today](https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384)
