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

tryXXX functions' return value is undefined if !ok.
unsafeXXX functions' behaviour undefined if !ok.

NEVER construct types yourself:
- DON't .wrap
- DON't PublicKey(x, y), Point(x, y), etc

Audit Greps:
- grep -rn "unsafe" src/
- grep -rn "wrap" src/
- grep -rn "PublicKey(" src/
- grep -rn "Point(" src/
- grep -rn "ProjectivePoint(" src/
- grep -rn "Signature(" src/ TODO: ???

## Signatures

ECDSA and Schnorr are supported


TODO: general parsing functions:
    tryPublicKeyFromBlob(bytes);
    publicKeyFromBlob(bytes);
    tryPointFromBlob(bytes);
    pointFromBlob(bytes);
