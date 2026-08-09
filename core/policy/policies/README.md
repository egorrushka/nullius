# Policies

A policy maps facts to a verdict. It never computes anything.

Each policy declares which claims it requires, the thresholds it applies,
and a citation for every criterion. If a bundle lacks a required claim,
the result is "cannot decide" — never a silent pass.

Planned: `safecurves-2024.yaml`, `nist-sp800-186.yaml`, `zk-friendly.yaml`.
