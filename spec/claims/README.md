# Claim types

One file per claim type. Each specifies:

- identifier and version
- what the claim asserts, precisely
- the evidence encoding
- the exact verification procedure, in enough detail that a second
  implementation can be written from this file alone
- known failure modes and the negative test vectors that cover them

## Planned for phase 1 (all tier A)

| Id                | Asserts                                        |
|-------------------|------------------------------------------------|
| `field.prime`     | the field characteristic is prime              |
| `curve.order`     | the curve has exactly `n` points               |
| `group.prime`     | the base point order is prime, with cofactor   |
| `curve.embedding` | embedding degree exceeds a threshold           |
| `curve.cm`        | CM discriminant of the curve                   |
| `twist.order`     | the quadratic twist order and its factorisation|
| `param.rigidity`  | parameters are reproduced from a seed          |
