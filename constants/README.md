# RigidityAudit

For each constant in each standard: an executable derivation, the
expected value, and a category.

| Category | Meaning                                          |
|----------|--------------------------------------------------|
| `full`   | reproduces exactly from documented inputs        |
| `partial`| reproduces given an undocumented choice          |
| `none`   | no published derivation reproduces it            |

## Degrees-of-freedom metric

A derivation is only reassuring if it left its author little room to
search. The metric counts the free choices a claimed derivation admits
(seed strings, encodings, hash instances, iteration counts, offsets) and
reports them in bits. Low bits means the constant could not have been
shopped for; high bits means the derivation proves little.
