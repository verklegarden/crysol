**`crysol` is a _simple_ and _secure_ secp256k1 crypto library for EVM applications**

## Types

High-Level:
    SecretKey               uint \in [1, Q)
    PublicKey               Point

Arithmetic:
    Field:
        Felt                uint \in [0, P)

    Point:
        Point               (Felt, Felt)
        ProjectivePoint     (Felt, Felt, Felt)

While types increase costs, it provides more security.

If _not_ using .wrap(), _MUST NOT_ be able to construct invalid object.

## Signatures

ECDSA and Schnorr are supported
