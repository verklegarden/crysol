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

1. Derive a cryptographically secure nonce from `m` and `x` following [RFC 6979]

```
k ∊ [1, Q)
```

2. Compute the nonce's public key

```
R = [k]G
```

3. Derive `commitment` being the Ethereum address of the nonce's public key

```
Rₑ
```

4. Construct challenge `e`

```
e = H(Pₓ ‖ Pₚ ‖ m ‖ r)
```

5. Compute `signature`

```
s = k + (e * x) (mod Q)
```

=> Let tuple `(signature, commitment)` be the Schnorr signature

## Signature Verification

**Input**: `(P, m, signature, commitment)`
**Output**: `True` if signature verification succeeds, `False` otherwise

1. Construct challenge `e`

```
e = H(Pₓ ‖ Pₚ ‖ m ‖ r)
```

2. Compute `commitment`

```
  [s]G - [e]P               | s = k + (e * x)
= [k + (e * x)]G - [e]P     | P = [x]G
= [k + (e * x)]G - [e * x]G | Distributive Law
= [k + (e * x) - (e * x)]G  | (e * x) - (e * x) = 0
= [k]G                      | R = [k]G
= R
→ Rₑ
```

3. Return `True` if `([s]G - [e]P)ₑ == Rₑ`, `False` otherwise

## Security Notes

TODO: Schnorr Security Notes

## Implementation Notes

TODO: Implementation Notes
