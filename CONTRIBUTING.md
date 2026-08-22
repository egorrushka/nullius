# Contributing

The short version: evidence over assertion, and refusals over conveniences.

## What a change has to satisfy

**New claims need a verifier before they need a producer.** A claim the
verifier cannot re-establish is not a claim, it is a note. Write the
checking side first; it will tell you whether the evidence you planned to
ship is enough.

**Negative tests are the real tests.** Every bug found in this project so
far was caught by a test that asserted something would be *rejected*, not
by one that asserted success. A pull request that adds a claim type
without adding the ways it can fail is incomplete.

**Unknown means refused.** An unrecognised claim type, evidence type or
field is a hard error everywhere. Do not add a branch that skips what it
does not understand.

**Facts and verdicts stay apart.** Bundles state what is true. Whether a
curve is a good choice is decided by a policy, outside the bundle, and
policies are data rather than code.

**The verifier has a size budget.** No file over 800 lines, and the whole
thing under 1800. It is the component people are expected to read before
trusting anything else here, and it stops being that if it sprawls.
Raising the budget is allowed and has happened twice, both times for
arithmetic that could not be compressed. Make the argument in the pull
request.

## Running things

    tools\build_verifier.bat     build the verifier
    tools\corpus.bat             build and verify every known curve
    tools\test.bat               the whole suite
    tools\policy.bat --list      installed policies
    tools\web.bat                the dossier viewer
    tools\dist.bat               assemble the release

On Linux or macOS, read the batch files; each is three lines and says what
it runs.

## Determinism

Two machines building the same certificate must produce the same bytes.
Anything that varies between runs — a timestamp, a random point, a tool
version — belongs outside the hashed document. If you need such a value,
put it in a run log beside the file.

## Reporting a problem with a certificate

If a certificate in this repository verifies but says something false,
that is the most serious kind of bug here. Open an issue with the file and
the claim, and say what you believe the correct value is and how you
established it.
