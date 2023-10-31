# Spec

The `spec/` directory will contain python code used as specification for cryptographic computations.
The test suite will have differential fuzzing tests to ensure `crysol` follows the specification.

The python code will _not be_ crypto production code (eg secure against side channel attacks). Focus is on having clean and understandable code.

Open Questions:
- How to handle python dependencies?
- Can `sage` be used via "normal" python? (ie could `spec/` be mostly sage code?)
