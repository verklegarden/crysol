from ecdsa import ellipticcurve, numbertheory, SECP256k1
import secrets

curve = SECP256k1.curve
n = SECP256k1.order
G = SECP256k1.generator

# Generate key-pairs.
a = secrets.randbelow(n) + 1
A = G * a
print(f"Generated Alice's private key ({a}) and public key ({A.x()}, {A.y()})")

b = secrets.randbelow(n) + 1
B = G * (b)
print(f"Generated Bob's private key ({b}) and public key ({B.x()}, {B.y()})")

# Generate shared secret point.
C1 = A * b  # C = A*b = G*a*b
C2 = B * a  # C = B*a = G*b*a
assert C1 == C2
print(f"Determined secret shared point ({C1.x()}, {C1.y()})")

# Eve has A and B but cannot compute the shared secret C without a or b.
D = A + B # Eve's misguided attempt to find the shared secret using point addition
assert C1 != D
print(f"Eve's wrong secret (D = A + B): {D.x()}, {D.y()}")
