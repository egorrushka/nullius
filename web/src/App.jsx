import { useMemo, useState } from "react";
import { documents, index } from "./corpus.generated.js";
import {
  TIER_LABEL,
  claimTier,
  evaluate,
  findClaim,
  parseDecimal,
  bitLength,
} from "./policy.js";

// Long integers are the subject matter here, not an implementation detail,
// so they get shown rather than hidden behind an ellipsis. Grouping makes a
// 78-digit number checkable by eye against another copy of it.
function grouped(text, size = 6) {
  const out = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out.join(" ");
}

function claimWording(claim) {
  const a = claim.asserts ?? {};
  switch (claim.claim) {
    case "field.characteristic":
      return ["the field has prime order", `p is prime, ${bits(a.p)} bits`];
    case "curve.order.prime":
      return ["the group order is prime", `n is prime, ${bits(a.n)} bits`];
    case "curve.order":
      return ["the group has exactly n points", `cofactor ${a.cofactor}`];
    case "curve.hasse":
      return ["n lies where a group order must", "recomputed from p"];
    case "curve.embedding":
      return ["pairings lead nowhere useful", `embedding degree ${bits(a.degree)} bits`];
    case "curve.cm":
      return [
        "the curve comes from this CM field",
        `discriminant ${bits(a.fundamental)} bits`,
      ];
    case "param.rigidity":
      return ["the parameters follow from a seed", a.method];
    case "twist.cardinality":
      return ["the twist has this many points", "n + n′ = 2p + 2"];
    default:
      return [claim.claim, ""];
  }
}

function bits(text) {
  const value = parseDecimal(text);
  return value === null ? "?" : bitLength(value < 0n ? -value : value);
}

function Number_({ label, value }) {
  const parsed = parseDecimal(value);
  const long = parsed !== null && value.replace("-", "").length > 12;
  return (
    <div className="number">
      <span className="number-label">{label}</span>
      <span className={long ? "number-value long" : "number-value"}>
        {long ? grouped(value) : value}
      </span>
    </div>
  );
}

function Claim({ claim, expanded, onToggle, evidence }) {
  const tier = claimTier(claim);
  const [headline, note] = claimWording(claim);
  const body = claim.evidence?.ref ? evidence[claim.evidence.ref] : null;

  return (
    <li className={`claim tier-${tier}`}>
      <button
        className="claim-head"
        onClick={onToggle}
        aria-expanded={expanded}
      >
        <span className="gutter" aria-hidden="true">
          <span className="mark" />
        </span>
        <span className="claim-text">
          <span className="claim-headline">{headline}</span>
          <span className="claim-note">{note}</span>
        </span>
        <span className="claim-tier">{TIER_LABEL[tier]}</span>
      </button>

      {expanded && (
        <div className="claim-body">
          <div className="claim-id">{claim.claim}</div>
          {Object.entries(claim.asserts ?? {}).map(([key, value]) => (
            <Number_ key={key} label={key} value={value} />
          ))}
          {claim.depends_on?.length > 0 && (
            <p className="depends">
              Holds only if {claim.depends_on.join(", ")} holds.
            </p>
          )}
          <p className="evidence">
            Evidence: <span className="mono">{claim.evidence.type}</span>
            {body?.steps && ` · ${body.steps.length} certificate steps`}
            {body?.factors && ` · ${body.factors.length} proved factors`}
            {body?.seed && ` · seed ${body.seed}`}
          </p>
        </div>
      )}
    </li>
  );
}

function Verdict({ bundle, policies }) {
  const [chosen, setChosen] = useState(policies[0]?.name);
  const policy = policies.find((p) => p.name === chosen) ?? policies[0];
  const verdict = useMemo(() => evaluate(bundle, policy), [bundle, policy]);

  return (
    <section className="verdict">
      <div className="verdict-head">
        <h2>Judged by</h2>
        <select value={chosen} onChange={(e) => setChosen(e.target.value)}>
          {policies.map((p) => (
            <option key={p.name} value={p.name}>
              {p.title}
            </option>
          ))}
        </select>
      </div>
      <p className="source">{policy.source}</p>

      <ul className="criteria">
        {verdict.outcomes.map(({ criterion, status, detail }) => (
          <li key={criterion.id} className={`criterion ${status}`}>
            <span className="criterion-id">{criterion.id}</span>
            <span className="criterion-detail">{detail}</span>
            {status !== "pass" && (
              <p className="criterion-why">{criterion.description}</p>
            )}
          </li>
        ))}
      </ul>

      <p className="result">
        Under these criteria the curve <strong>{verdict.result}</strong>.
      </p>
      {verdict.count("undecided") > 0 && (
        <p className="caveat">
          Undecided is not approval. The certificate does not carry the
          evidence those criteria ask for, and nothing here fills that in.
        </p>
      )}
    </section>
  );
}

export default function App() {
  const [selected, setSelected] = useState(index.bundles[0]?.file ?? null);
  const [open, setOpen] = useState({});

  const bundle = selected ? documents[selected] : null;

  if (!bundle) {
    return (
      <main className="empty">
        No corpus in this build. Run tools\corpus.bat, then
        tools\web_data.bat, then build again.
      </main>
    );
  }

  const entry = index.bundles.find((b) => b.file === selected);
  const order = parseDecimal(findClaim(bundle, "curve.order")?.asserts?.n ?? "0");

  return (
    <div className="page">
      <aside className="index">
        <h1>Nullius</h1>
        <p className="motto">nullius in verba</p>
        <p className="blurb">
          Take nobody's word for it. Every claim below arrives with the
          evidence for it, and a separate program re-checks that evidence
          without redoing the work.
        </p>
        <ul>
          {index.bundles.map((b) => (
            <li key={b.file}>
              <button
                className={b.file === selected ? "current" : ""}
                onClick={() => {
                  setSelected(b.file);
                  setOpen({});
                }}
              >
                <span className="curve-name">{b.label}</span>
                <span className="curve-meta">
                  {b.bits}-bit · {b.tiers.A} proved
                </span>
              </button>
            </li>
          ))}
        </ul>
      </aside>

      <main className="dossier">
        <header>
          <h2>{entry.label}</h2>
          <p className="source">{entry.source}</p>
          <p className="digest mono">{grouped(entry.digest.slice(7), 8)}</p>
          <p className="digest-label">
            SHA-256 of the certificate. Two machines that build this curve
            independently produce this same file, byte for byte.
          </p>
        </header>

        <section className="facts">
          <h3>
            What is proved
            <span className="count">
              {entry.tiers.A} proved · {entry.tiers.D} derived ·{" "}
              {entry.tiers.X} not proved
            </span>
          </h3>
          <ul className="claims">
            {bundle.claims.map((claim, i) => (
              <Claim
                key={claim.claim}
                claim={claim}
                evidence={bundle.evidence}
                expanded={!!open[i]}
                onToggle={() => setOpen((o) => ({ ...o, [i]: !o[i] }))}
              />
            ))}
          </ul>
          {order !== null && order > 0n && (
            <p className="order mono">{grouped(order.toString())}</p>
          )}
          <p className="order-label">
            The number of points on the curve, proved rather than reported.
          </p>
        </section>

        <Verdict bundle={bundle} policies={index.policies} />
      </main>
    </div>
  );
}
