# Backends

Heavy computation, each behind a process boundary.

| Backend | Provides                                    | Status   |
|---------|---------------------------------------------|----------|
| `gp`    | SEA point counting, primality certificates  | phase 1  |
| `cm`    | fastECPP for hard cofactors                 | later    |

Backends are never trusted. Whatever they return is re-checked against
the evidence before it enters a bundle.
