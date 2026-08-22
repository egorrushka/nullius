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
  "proof.point-order": "A",
  "check.cofactor": "A",
  "check.family": "A",
  "derive.twist-class": "A",
  "check.curve-model": "A",
  "derive.order-elimination": "A",
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
    label = `(${label} − ${reference.minus})`;
  }
  if (reference.over !== undefined) {
    value /= BigInt(reference.over);
    label = `${label} ÷ ${reference.over}`;
  }
  return { value, label };
}

function show(value, label) {
  const bits = bitLength(value < 0n ? -value : value);
  if (bits < 40) return value.toString();
  return label ?? `≈2^${bits}`;
}

// Every outcome carries its criterion's model, so a consumer of the
// verdict can tell which lines rest on an estimate rather than on the
// bundle. The command-line engine prints this on a pass as well as a
// failure, and the page could not, because the field never reached it —
// a gap in how trust is presented rather than in the verdict itself.
function withModel(outcome) {
  const model = outcome.criterion?.model;
  return model ? { ...outcome, model: model.name } : outcome;
}

export function evaluate(bundle, policy) {
  const outcomes = policy.criteria.map((criterion) => withModel(_outcome(bundle, policy, criterion)));

  return _verdict(policy, outcomes);
}

function _outcome(bundle, policy, criterion) {
  {
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

    // A criterion may multiply two facts from the bundle: the size of the
    // embedding field is the bit length of p times the embedding degree.
    // Both operands are proved claims, so the product is a fact of the
    // certificate rather than a computation of the policy. Without this
    // the page silently compared the wrong number against the threshold,
    // which is worse than refusing to compare at all.
    let value = observed.value;
    if (criterion.pow) {
      // The transform comes after the power, not before: `bits` describes
      // the quantity being compared, not an intermediate. Applying it
      // first computes bits(p) ** k, which is off by more than an order
      // of magnitude.
      const exponent = read(
        bundle,
        policy,
        criterion.pow.claim,
        criterion.pow.field,
        "none",
      );
      if (exponent.undecided) {
        return { criterion, status: "undecided", detail: exponent.undecided };
      }
      if (exponent.value < 1n || exponent.value > 64n) {
        // Undecided, not failed: a prime-field curve has an embedding
        // degree in the hundreds of bits, so this is the ordinary path
        // for one rather than an error.
        return {
          criterion,
          status: "undecided",
          detail:
            `the embedding degree is ${exponent.value}, outside the 1..64 ` +
            "this criterion can raise to",
        };
      }
      const raw = read(bundle, policy, criterion.claim, criterion.field, "none");
      if (raw.undecided) {
        return { criterion, status: "undecided", detail: raw.undecided };
      }
      value = TRANSFORMS[criterion.transform ?? "none"](
        raw.value ** exponent.value,
      );
    }
    if (criterion.times) {
      const other = read(
        bundle,
        policy,
        criterion.times.claim,
        criterion.times.field,
        criterion.times.transform,
      );
      if (other.undecided) {
        return { criterion, status: "undecided", detail: other.undecided };
      }
      value *= other.value;
    }

    const wanted = threshold(bundle, policy, criterion);
    if (wanted.undecided) {
      return { criterion, status: "undecided", detail: wanted.undecided };
    }

    const [compare, phrase] = OPERATORS[criterion.op];
    const held = compare(value, wanted.value);
    return {
      criterion,
      status: held ? "pass" : "fail",
      detail: `${show(value)} ${phrase} ${show(wanted.value, wanted.label)}`,
    };
  }
}

function _verdict(policy, outcomes) {
  const count = (status) => outcomes.filter((o) => o.status === status).length;
  let result = "passes";
  if (count("fail")) result = "fails";
  else if (count("undecided")) result = "cannot be decided";

  return { policy, outcomes, result, count };
}
