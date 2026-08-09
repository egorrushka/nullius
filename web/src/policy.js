// Applying a policy, in the browser.
//
// This is a second implementation of the same tiny grammar the Python
// engine reads, and that is on purpose: two readers of one declarative
// file can be compared, and a disagreement between them is a bug worth
// hearing about. The grammar stays small enough that a second version is
// cheap — a field, an operator, a value, and at most three modifiers.
//
// Everything is BigInt. These are 256-bit numbers, and a Number would lose
// them silently, which is the worst way to lose anything.
//
// The rules that matter are the same ones the Python engine holds to: a
// policy reads and never derives, a claim the bundle does not make comes
// back undecided rather than passing, and an unproved claim counts as
// absent unless the policy says otherwise.

const OPERATORS = {
  eq: [(a, b) => a === b, "must equal"],
  ne: [(a, b) => a !== b, "must differ from"],
  lt: [(a, b) => a < b, "must be below"],
  le: [(a, b) => a <= b, "must be at most"],
  gt: [(a, b) => a > b, "must exceed"],
  ge: [(a, b) => a >= b, "must be at least"],
};

const TRANSFORMS = {
  none: (v) => v,
  abs: (v) => (v < 0n ? -v : v),
  bits: (v) => BigInt(bitLength(v < 0n ? -v : v)),
};

export const TIER_OF_EVIDENCE = {
  "candidate.pseudoprime": "X",
  "candidate.sea": "X",
  "proof.ecpp": "A",
  "proof.multiplicative-order": "A",
  "proof.cm-discriminant": "A",
  "check.hasse": "A",
  "check.order-unique": "A",
  "check.seed-derivation": "A",
  "derive.twist-sum": "D",
};

export const TIER_LABEL = { A: "proved", D: "derived", X: "not proved" };

export function bitLength(value) {
  if (value === 0n) return 0;
  return value.toString(2).length;
}

// The one spelling the format allows: no leading zeros, no sign but a
// leading minus, nothing else.
const DECIMAL = /^(0|-?[1-9][0-9]*)$/;

export function parseDecimal(text) {
  if (typeof text !== "string" || !DECIMAL.test(text)) return null;
  return BigInt(text);
}

function parseLiteral(text) {
  const trimmed = String(text).trim();
  if (trimmed.includes("^")) {
    const [base, exponent] = trimmed.split("^");
    return BigInt(base) ** BigInt(exponent);
  }
  return parseDecimal(trimmed);
}

export function claimTier(claim) {
  return TIER_OF_EVIDENCE[claim?.evidence?.type] ?? null;
}

export function findClaim(bundle, name) {
  return bundle.claims.find((claim) => claim.claim === name) ?? null;
}

function read(bundle, policy, claimName, field, transform) {
  const claim = findClaim(bundle, claimName);
  if (!claim) return { undecided: `no claim ${claimName}` };

  const tier = claimTier(claim);
  if (!tier) return { undecided: `unknown evidence in ${claimName}` };
  if (!policy.accept_tiers.includes(tier)) {
    return { undecided: `${claimName} is ${TIER_LABEL[tier]}` };
  }

  const raw = claim.asserts?.[field];
  const value = parseDecimal(raw);
  if (value === null) return { undecided: `${claimName} does not state ${field}` };
  return { value: TRANSFORMS[transform ?? "none"](value) };
}

function threshold(bundle, policy, criterion) {
  if (criterion.value !== null && criterion.value !== undefined) {
    return { value: parseLiteral(criterion.value), label: String(criterion.value) };
  }
  const reference = criterion.value_from;
  const found = read(
    bundle,
    policy,
    reference.claim,
    reference.field,
    reference.transform,
  );
  if (found.undecided) return found;

  let value = found.value;
  let label = `${reference.claim}.${reference.field}`;
  if (reference.minus !== undefined) {
    value -= BigInt(reference.minus);
    label += ` − ${reference.minus}`;
  }
  if (reference.over !== undefined) {
    value /= BigInt(reference.over);
    label += ` ÷ ${reference.over}`;
  }
  return { value, label };
}

function show(value, label) {
  const bits = bitLength(value < 0n ? -value : value);
  if (bits < 40) return value.toString();
  return label ?? `≈2^${bits}`;
}

export function evaluate(bundle, policy) {
  const outcomes = policy.criteria.map((criterion) => {
    const observed = read(
      bundle,
      policy,
      criterion.claim,
      criterion.field,
      criterion.transform,
    );
    if (observed.undecided) {
      return { criterion, status: "undecided", detail: observed.undecided };
    }
    const wanted = threshold(bundle, policy, criterion);
    if (wanted.undecided) {
      return { criterion, status: "undecided", detail: wanted.undecided };
    }

    const [compare, phrase] = OPERATORS[criterion.op];
    const held = compare(observed.value, wanted.value);
    return {
      criterion,
      status: held ? "pass" : "fail",
      detail: `${show(observed.value)} ${phrase} ${show(wanted.value, wanted.label)}`,
    };
  });

  const count = (status) => outcomes.filter((o) => o.status === status).length;
  let result = "passes";
  if (count("fail")) result = "fails";
  else if (count("undecided")) result = "cannot be decided";

  return { policy, outcomes, result, count };
}
