import { useMemo, useState } from "react";
import { documents, index } from "./corpus.generated.js";
import { verify as verifyHere } from "./verifier.generated.js";
import {
  bitLength,
  claimTier,
  evaluate,
  findClaim,
  parseDecimal,
  TIER_LABEL,
} from "./policy.js";

// Long integers are the subject matter here, not an implementation detail,
// so they get shown rather than hidden behind an ellipsis. Grouping makes a
// 78-digit number checkable by eye against another copy of it.
function grouped(text, size = 6) {
  const out = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out.join(" ");
}

function claimWording(claim, evidence) {
  const a = claim.asserts ?? {};
  switch (claim.claim) {
    case "field.characteristic":
      return ["the field has prime order", `p is prime, ${bits(a.p)} bits`];
    case "curve.order.prime":
      return ["the group order is prime", `n is prime, ${bits(a.n)} bits`];
    case "curve.cardinality":
      return ["the curve has exactly n points", `n is ${bits(a.n)} bits`];
    case "curve.order":
      return [
        a.cofactor === "1"
          ? "the group has prime order"
          : "the prime subgroup and what surrounds it",
        a.cofactor === "1"
          ? `cofactor 1, n is ${bits(a.n)} bits`
          : `cofactor ${bits(a.cofactor)} bits, largest factor ${bits(
              a.largest_prime_factor,
            )} bits`,
      ];
    case "curve.hasse":
      return ["n lies where a group order must", "recomputed from p"];
    case "curve.embedding":
      // The wording cannot be fixed, because the fact means opposite
      // things on the two kinds of curve here. A low embedding degree is
      // the transfer attack on secp256k1 and the entire point of
      // BLS12-381. Stating the number and letting the policy judge it is
      // the whole design; a headline that judged it here would put a
      // verdict in the certificate view.
      return [
        Number(a.degree) <= 24
          ? "a pairing is computable, into this degree"
          : "a pairing leads nowhere useful",
        `embedding degree ${a.degree}`,
      ];
    case "g2.cardinality":
      // The degree comes from the evidence, not from a guess.
      //
      // This said "over a quadratic extension" unconditionally, which was
      // true while the format covered only BLS12 and BN. BLS24 puts its
      // second group over F_p^4, so the page was stating one thing and
      // printing a bit length from another in the same line — 1258 bits
      // beside the word quadratic. A reader who trusted the sentence and
      // a reader who trusted the number would have left with different
      // curves in mind.
      return [
        "the second group has exactly n points",
        `over F_p^${evidence?.field?.degree ?? "?"}, ${bits(a.n)} bits`,
      ];
    case "g2.order":
      return [
        "the second group's prime subgroup",
        `cofactor ${bits(a.cofactor)} bits, largest factor ${bits(
          a.largest_prime_factor,
        )} bits`,
      ];
    case "curve.cm":
      return [
        "the curve comes from this CM field",
        `discriminant ${bits(a.fundamental)} bits`,
      ];
    case "curve.family":
      return [
        "the curve is generated, not chosen",
        `${a.family} family at one parameter`,
      ];
    case "g2.twist":
      return [
        "the second group sits on a twist",
        `sextic twist class ${a.class}`,
      ];
    case "curve.model":
      return [
        "published in another model",
        a.model === "montgomery"
          ? "Montgomery form"
          : a.model === "twisted-edwards"
            ? "twisted Edwards form"
            : a.model,
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
  // String() rather than trusting the field to be one. Every assert is a
  // string today, and a numeric field added later would throw here rather
  // than render — a crash for a display decision is a poor trade.
  const text = String(value);
  const parsed = parseDecimal(text);
  const long = parsed !== null && text.replace("-", "").length > 12;
  return (
    <div className="number">
      <span className="number-label">{label}</span>
      <span className={long ? "number-value long" : "number-value"}>
        {long ? grouped(text) : text}
      </span>
    </div>
  );
}

function Claim({ claim, expanded, onToggle, evidence, stated }) {
  const tier = claimTier(claim);
  const body = claim.evidence?.ref ? evidence[claim.evidence.ref] : null;
  const [headline, note] = claimWording(claim, body);

  return (
    <li
      className={`claim tier-${tier}${expanded ? " open" : ""}${
        stated ? " stated" : ""
      }`}
    >
      <button
        className="claim-head"
        onClick={onToggle}
        aria-expanded={expanded}
      >
        <span className="mark" aria-hidden="true" />
        <span className="claim-headline">{headline}</span>
        <span className="claim-note">{note}</span>
        {/* What the mark means depends on whether anything checked it.
            These labels are the document's own account of itself, and
            when the verifier has refused the document — or never ran —
            saying `proved` beside every line puts a wall of green around
            the one red one. A reader skimming that leaves with the
            opposite of the truth. */}
        <span className="claim-tier">
          {stated ? "stated" : TIER_LABEL[tier]}
        </span>
        <span className="chevron" aria-hidden="true" />
      </button>

      {expanded && (
        <div className="claim-body">
          <div className="claim-id">{claim.claim}</div>
          {Object.entries(claim.asserts ?? {}).map(([key, value]) => (
            <Number_ key={key} label={key} value={value} />
          ))}
          {claim.depends_on?.length > 0 && (
            // What it rests on, as a list rather than a sentence. A tier
            // is a statement about everything beneath a claim — nothing
            // proved rests on anything less — so these are not caveats,
            // they are the shape of the argument.
            <div className="depends">
              <span className="depends-label">Rests on</span>
              <ul>
                {claim.depends_on.map((name) => (
                  <li key={name}>{name}</li>
                ))}
              </ul>
            </div>
          )}
          <p className="evidence">
            Evidence: <span className="mono">{claim.evidence.type}</span>
            {body?.steps && ` · ${body.steps.length} certificate steps`}
            {body?.factors && ` · ${body.factors.length} proved factors`}
            {body?.points && ` · ${body.points.length} eliminating point(s)`}
            {body?.seed && ` · seed ${body.seed}`}
          </p>
          {body && (
            // The bytes themselves, for a reader who wants to check the
            // digest by hand rather than take the page's word that the
            // pool is intact. Off by default: it is a wall of decimal
            // digits, and it is here for the one reader in fifty who
            // means to use it.
            <details className="raw">
              <summary>Evidence, as stored</summary>
              <pre className="mono">{JSON.stringify(body, null, 1)}</pre>
            </details>
          )}
        </div>
      )}
    </li>
  );
}

function Criterion({ outcome }) {
  const [open, setOpen] = useState(false);
  const { criterion, status, detail } = outcome;
  // Undecided is the status people misread, so it says so in words rather
  // than relying on a colour nobody has a legend for.
  const label = { pass: "met", fail: "not met", undecided: "unknown" }[status];
  const hasMore = criterion.description || criterion.model;

  return (
    <li className={`criterion ${status}${open ? " open" : ""}`}>
      <button
        className="criterion-head"
        onClick={() => hasMore && setOpen(!open)}
        aria-expanded={hasMore ? open : undefined}
        disabled={!hasMore}
      >
        <span className="dot" aria-hidden="true" />
        <span className="criterion-id">{criterion.id}</span>
        <span className="criterion-detail">{detail}</span>
        {criterion.model && (
          // Marked where it can be seen without opening anything. A
          // threshold drawn from an estimate can move without any fact
          // moving, and a reader scanning the column should be able to
          // tell which lines are of that kind.
          <span className="model-flag" title="threshold comes from a model">
            model
          </span>
        )}
        <span className="criterion-status">{label}</span>
        {hasMore && <span className="chevron" aria-hidden="true" />}
      </button>

      {open && (
        <div className="criterion-body">
          {criterion.model && (
            // Shown on a pass as well as a failure. A threshold that came
            // from a model can move without any fact moving, and hiding
            // that when the answer is favourable would leave a reader
            // thinking the number on the right is as settled as the one
            // on the left.
            <p className="criterion-model">
              Threshold under <strong>{criterion.model.name}</strong>.{" "}
              {criterion.model.source}
            </p>
          )}
          {criterion.description && (
            <p className="criterion-why">{criterion.description}</p>
          )}
        </div>
      )}
    </li>
  );
}

function Verdict({ bundle, policies }) {
  const [chosen, setChosen] = useState(policies[0]?.name);
  const policy = policies.find((p) => p.name === chosen) ?? policies[0];
  const verdict = useMemo(() => evaluate(bundle, policy), [bundle, policy]);
  const unknown = verdict.count("undecided");

  return (
    <aside className="rail verdict">
      <div className="rail-head">
        <h2>Judged by</h2>
        <select
          value={chosen}
          onChange={(e) => setChosen(e.target.value)}
          aria-label="Policy"
        >
          {policies.map((p) => (
            <option key={p.name} value={p.name}>
              {p.title}
            </option>
          ))}
        </select>
      </div>

      <div className="rail-scroll">
        <ul className="criteria">
          {verdict.outcomes.map((outcome) => (
            <Criterion key={outcome.criterion.id} outcome={outcome} />
          ))}
        </ul>
      </div>

      <div className={`rail-foot result-${verdict.result.split(" ")[0]}`}>
        <p className="whence">
          Computed here, in your browser, from the certificate above.
          Nothing was fetched and nothing was asked of anyone.
        </p>
        <p className="result">
          Under these criteria the curve <strong>{verdict.result}</strong>.
        </p>
        {unknown > 0 && (
          <p className="caveat">
            {unknown} criterion{unknown === 1 ? "" : "a"} could not be
            decided. Unknown is not approval: the certificate does not carry
            the evidence they ask for.
          </p>
        )}
      </div>
    </aside>
  );
}

/// A certificate the reader brought, described the way the shipped ones
/// are.
///
/// The page cannot verify it — that is the Rust program's job, and
/// claiming otherwise would be the exact overstatement this project
/// exists to avoid. What it can do is read the claims, apply every policy
/// to them, and say so plainly.
/// What the verifier said about a file the reader brought.
///
/// Placed above everything else about that certificate, because it is the
/// only line on the page that is not the page's own opinion. The claims
/// below it are read out of the document; this is the result of
/// re-deriving them.
function Verified({ verdict }) {
  if (verdict.result === "pending") {
    return (
      <p className="verified pending">
        <b>Verifying…</b> Every claim is being re-derived from the file.
        The page will not respond while it works — a long primality chain
        takes a few seconds — and nothing below has been checked yet.
      </p>
    );
  }
  if (verdict.result === "accepted") {
    return (
      <p className="verified accepted">
        <b>Verified in this page.</b> {verdict.proved} proved,{" "}
        {verdict.derived} derived, {verdict.unproved} not proved — by the same
        program that ships beside this file, compiled for your browser.
      </p>
    );
  }
  if (verdict.result === "refused") {
    return (
      <p className="verified refused">
        <b>Refused.</b> {verdict.reason}
      </p>
    );
  }
  return (
    <p className="verified unavailable">
      <b>Not verified.</b> The verifier did not load ({verdict.reason}), so
      what follows is the document read back to you and nothing more.
    </p>
  );
}

/// Resolve once the browser has painted.
///
/// Two nested frames rather than one: the first callback runs before the
/// upcoming paint, the second after it. Anything shorter and the caller
/// races the renderer, which is exactly the bug this exists to close —
/// ten seconds of a page that had not yet drawn the notice saying it was
/// busy.
function painted() {
  return new Promise((resume) =>
    requestAnimationFrame(() => requestAnimationFrame(() => resume())),
  );
}

function describeImported(document, name) {
  const tiers = { A: 0, D: 0, X: 0 };
  for (const claim of document.claims ?? []) {
    const tier = claimTier(claim);
    if (tier in tiers) tiers[tier] += 1;
  }
  const p = document.subject?.field?.p;
  return {
    file: name,
    label: document.subject?.label ?? name,
    source: document.subject?.source ?? "brought by you, not by us",
    bits: p ? BigInt(p).toString(2).length : 0,
    // No digest: the page did not hash the bytes, and a field that looks
    // like one but was copied from the document would be worse than
    // none.
    digest: null,
    tiers,
    imported: true,
  };
}

export default function App() {
  const [selected, setSelected] = useState(index.bundles[0]?.file ?? null);
  const [open, setOpen] = useState({});
  // Certificates the reader opened, kept alongside the shipped ones and
  // marked as theirs. Nothing is uploaded; the file never leaves the
  // machine, which is the same promise the rest of the page makes.
  const [brought, setBrought] = useState({ entries: [], documents: {} });
  const [complaint, setComplaint] = useState(null);

  const listed = [...index.bundles, ...brought.entries];
  const everything = { ...documents, ...brought.documents };
  const bundle = selected ? everything[selected] : null;

  async function accept(files) {
    setComplaint(null);
    for (const file of files) {
      let document;
      const key = `brought:${file.name}`;
      let text;
      try {
        text = await file.text();
        document = JSON.parse(text);
        if (!Array.isArray(document.claims) || !document.subject) {
          throw new Error("not a certificate: no subject or claims");
        }
      } catch (error) {
        // Named, not swallowed. A file that will not open should say why
        // rather than appear to do nothing.
        setComplaint(`${file.name}: ${error.message}`);
        continue;
      }

      // Shown before it is verified, and marked as such.
      //
      // A long chain takes ten seconds, and holding the page blank for
      // that long taught the reader nothing except that something might
      // be broken. The claims are in the document and can be read at
      // once; what is pending is the verdict, and the banner where the
      // verdict will appear says so in the meantime. One place to watch,
      // and it changes.
      setBrought((current) => ({
        entries: [
          ...current.entries,
          { ...describeImported(document, key), verdict: { result: "pending" } },
        ],
        documents: { ...current.documents, [key]: document },
      }));
      setSelected(key);
      setOpen({});

      // Wait for the browser to actually paint the above before starting
      // the work, which then blocks this thread for as long as it takes.
      //
      // A zero timeout is not enough and that is worth writing down: React
      // schedules its own rendering, so a timer can fire before the commit
      // it was meant to follow. Two nested animation frames do the job —
      // the first is scheduled before the next paint, the second after it,
      // so by the time the second runs there is something on screen.
      await painted();

      let verdict;
      try {
        verdict = await verifyHere(file.name, text);
      } catch (error) {
        // The module failing to load is worth saying out loud. A page
        // that quietly fell back to displaying an unverified file would
        // be the exact dishonesty this feature removes.
        verdict = { result: "unavailable", reason: error.message };
      }

      setBrought((current) => ({
        ...current,
        entries: current.entries.map((entry) =>
          entry.file === key ? { ...entry, verdict } : entry,
        ),
      }));
    }
  }

  if (!bundle) {
    return (
      <main className="empty">
        No corpus in this build. Run tools\corpus.bat, then
        tools\web_data.bat, then build again.
      </main>
    );
  }

  const entry = listed.find((b) => b.file === selected);
  // The number of points on the curve, which is curve.cardinality when a
  // bundle carries one and curve.order otherwise. Reading curve.order
  // alone showed the subgroup order for pairing curves, understating
  // BLS12-381 by the 126 bits of its cofactor.
  const order = parseDecimal(
    findClaim(bundle, "curve.cardinality")?.asserts?.n ??
      findClaim(bundle, "curve.order")?.asserts?.n ??
      "0",
  );

  // Whether anything on this page has been checked, as opposed to read.
  //
  // `accepted` is the only state in which the tiers mean what they say.
  // Refused means the verifier disagreed with the document; unavailable
  // means no verifier loaded and nothing was checked at all. Pending is
  // neither — the answer is on its way — so the marks stay as they are
  // rather than flickering.
  const stated =
    !!entry.verdict &&
    entry.verdict.result !== "accepted" &&
    entry.verdict.result !== "pending";

  return (
    <div className="shell">
      <aside className="rail index">
        <div className="rail-head brand">
          <h1>Nullius</h1>
          <p className="motto">nullius in verba</p>
        </div>

        <div className="rail-scroll">
          <ul className="curves">
            {listed.map((b) => (
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
        </div>

        <div className="bring">
          <label className="bring-button">
            Open a certificate…
            <input
              type="file"
              accept=".ccert,application/json"
              multiple
              onChange={(e) => accept([...e.target.files])}
            />
          </label>
          <p className="bring-note">
            Yours, from this machine. Nothing is uploaded. The policies run
            against it exactly as they run against ours — which is the
            point, since taking our word for our own corpus would be a
            poor way to read this.
          </p>
          {complaint && <p className="bring-complaint">{complaint}</p>}
        </div>

        <p className="rail-foot blurb">
          Take nobody&rsquo;s word for it. Every claim arrives with the
          evidence for it, and a separate program re-checks that evidence
          without redoing the work.
        </p>
      </aside>

      <main className="dossier">
        <header className="subject">
          <div className="subject-line">
            <h2>{entry.label}</h2>
            {/* The counts double as the legend. They already sit at the
                top of the page carrying a colour each, and a number
                beside a colour teaches the colour better than a separate
                strip of prose does — which the separate strip proved by
                being skipped over. */}
            <span className={`tiers${stated ? " stated" : ""}`}>
              <span className="tier-chip proved">
                <span className="mark" aria-hidden="true" />
                {entry.tiers.A} {stated ? "claimed proved" : "proved outright"}
              </span>
              {entry.tiers.D > 0 && (
                <span className="tier-chip derived">
                  <span className="mark" aria-hidden="true" />
                  {entry.tiers.D}{" "}
                  {stated ? "claimed derived" : "follows from those"}
                </span>
              )}
              {entry.tiers.X > 0 && (
                <span className="tier-chip unproved">
                  <span className="mark" aria-hidden="true" />
                  {entry.tiers.X} computed, not proved
                </span>
              )}
            </span>
          </div>
          <p className="source">{entry.source}</p>
          {/* The verdict comes first, above everything else about this
              certificate, because it is the only line here that is not
              this page's own reading of the document. Outside the digest
              branch, too: a file brought by the reader has no published
              digest and is exactly the file most worth verifying. */}
          {entry.verdict && <Verified verdict={entry.verdict} />}
          {entry.digest ? (
            <>
              <p className="digest mono" title="SHA-256 of the certificate bytes">
                <span className="digest-label">sha256</span>
                {grouped(entry.digest.slice(7), 8)}
              </p>
              <p className="reproducible">
                The digest is of the bytes, not of the curve. A rebuild that
                produces a different file is a difference worth chasing.
              </p>
            </>
          ) : (
            <p className="reproducible brought-note">
              Opened from your machine, and never sent anywhere. The
              verifier above ran here, in this page, on these bytes.
            </p>
          )}
        </header>

        <div className="dossier-scroll">
          {/* A legend that is looked at, which the previous one was not.
              It sits directly above the first row it explains, uses the
              same marks at the same size, and states the distinction in
              words rather than naming a tier — "proved outright" against
              "follows from those above" is the difference that matters,
              and neither is obvious from a letter. */}
          <div className="legend">
            <span className="legend-item proved">
              <span className="mark" aria-hidden="true" />
              <span>
                <b>proved outright</b>
                <em>evidence in this file, re-checked</em>
              </span>
            </span>
            <span className="legend-item derived">
              <span className="mark" aria-hidden="true" />
              <span>
                <b>follows from those</b>
                <em>true as far as what it rests on</em>
              </span>
            </span>
            <span className="legend-item unproved">
              <span className="mark" aria-hidden="true" />
              <span>
                <b>computed, not proved</b>
                <em>a program said so; nothing checked it</em>
              </span>
            </span>
          </div>
          <ul className="claims">
            {bundle.claims.map((claim, i) => (
              <Claim
                key={claim.claim}
                claim={claim}
                evidence={bundle.evidence}
                stated={stated}
                expanded={!!open[i]}
                onToggle={() => setOpen((o) => ({ ...o, [i]: !o[i] }))}
              />
            ))}
          </ul>

          {order !== null && order > 0n && (
            <div className="order">
              <span className="order-label">Points on the curve</span>
              <span className="order-value mono">
                {grouped(order.toString())}
              </span>
            </div>
          )}
        </div>
      </main>

      <Verdict bundle={bundle} policies={index.policies} />
    </div>
  );
}
