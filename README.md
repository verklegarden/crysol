
## Coding Guidelines

into: No new memory allocation. Just assembly { result := self }

as: Type conversion. Can mean new memory allocation.

to: Computation. Can mean new memory allocation.

--

- `intoXXX()`
    -> Mutates `self` memory and returns `self`
- `asXXX()`
    -> Simple type conversion
- `toXXX()`
    -> Computes something from `self`. `self` not mutated

- Use additive notation. Makes clearer "what is hidden"
