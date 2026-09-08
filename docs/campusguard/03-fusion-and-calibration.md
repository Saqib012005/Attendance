# 03 — Evidence fusion and calibration

> **The configuration this build ships is labelled `uncalibrated`, and that label
> is enforced in code.** Nothing has been fitted against labelled data. The score
> is an *ordering*, not a probability, and the implementation refuses to emit a
> probability rather than relying on any reader to remember the caveat. No
> accuracy figure appears in this document because none has been measured.

## Why not just multiply

The obvious design is to give each signal a likelihood ratio and multiply. It is
wrong here, and specifically wrong rather than merely imprecise, because the
signals are functions of one another:

- A committed challenge nearly implies a valid session — the challenge is derived
  *from* the session root key.
- A verified relay hop is, in large part, the teacher origin sighting seen again
  one device further out.
- Device binding and identity authentication both come from the same successful
  login on the same handset.

Multiplying likelihood ratios that share most of their evidence counts the same
observation several times and produces a number that rises with the *number* of
correlated signals rather than with the *strength* of the evidence. A system built
that way reports high confidence for a proof that established one thing three
ways.

## Hard gates come first, and are not scored

Before any arithmetic runs, `gates.clear()` either produces a `Cleared` bundle or
raises. An invalid session, an expired or replayed challenge, a bad signature, an
unknown or revoked device, a duplicate proof: each ends the pipeline with a reason
code and no score at all.

This is the single most important structural decision in the layer. A gate folded
into a score is a gate that a sufficiently high total can buy its way past, and
"the score was 0.97 so we accepted it despite the signature failure" is how
scoring systems get talked past. The only way to guarantee it cannot happen is for
there to be no number at the point of refusal.

`decide.refuse(GateError)` turns a gate failure into a `Decision` directly, and
classifies the reason into one of two families:

- **`FORGERY_SHAPED`** — a forged signature, a fabricated challenge, an unknown
  relay. Something asserted what it could not have known. Verdict: `SUSPICIOUS`.
- **`UNRESOLVED`** — an expired challenge, a session already closed, a proof that
  arrived too late. Nothing was faked; the evidence does not resolve. Verdict:
  `NOT VERIFIED`.

Those two are checked at import time to be disjoint and to jointly cover every
gate reason code, so a new gate cannot be added without deciding which family its
failure belongs to. A reason code that fell through both would silently take
whichever default the code happened to have.

## The evidence vector

`features.extract()` turns a cleared submission into a **sparse** vector of twelve
features across four blocks.

| Block | Features |
|---|---|
| `authentication` | `identity_authenticated`, `device_bound`, `challenge_committed`, `biometric_outcome`, `platform_declared` |
| `network` | `origin_direct`, `relay_depth`, `relay_integrity` |
| `spatial` | `anchor_fingerprint`, `spatial_stability` |
| `temporal` | `queue_age`, `clock_consistency` |

Block membership *is* the dependency treatment: features that are functions of one
another live in the same block and are discounted against each other; blocks are
treated as independent of one another. That is a coarse approximation and it is
deliberately coarser than the truth, for the reason given under *The discount*
below.

### Four kinds of absence, and one of them is different

A missing feature carries a reason, and the reason changes what it means:

| Reason | Meaning | Treated as |
|---|---|---|
| `unsupported` | This handset cannot supply it | Benign |
| `reserved` | **No** build can supply it — the mechanism is unbuilt | Benign |
| `not_observed` | It could have arrived and did not | Benign |
| `failed` | A check ran and failed | **Adverse** |

Only `failed` is adverse. `features.ADVERSE_ABSENCES` contains exactly that one
value, and the rest are `BENIGN_ABSENCES` by subtraction rather than by a second
list that could drift out of step with the first.

This is invariant 3 from `00-architecture.md` implemented rather than asserted: a
student on an old handset that cannot scan for BLE loses *confidence*, moving them
toward `SECONDARY`, and is never pushed toward `SUSPICIOUS`. Owning the wrong phone
is not evidence of cheating.

On this build, `anchor_fingerprint` and `spatial_stability` report `reserved` on
every proof, and `origin_direct`, `relay_depth` and `relay_integrity` report
`unsupported` on every proof. The `network` and `spatial` blocks are empty.

## Millinats

All fusion arithmetic is in **millinats**: thousandths of a natural log-odds unit,
as integers.

Integers, not floats, and the reason is not performance. A verdict must land on the
same side of a threshold on every machine that evaluates it — the server, the
client's local preview, the adversarial lab, a re-derivation during an audit two
years later. Floating-point accumulation order and platform rounding can move a
sum across a threshold by one part in 10^15, which is enough to make an audit
disagree with the original verdict and enough to make a test flaky in a way nobody
can reproduce.

Weights under `2026.09-provisional`, in millinats:

| Feature | Weight | Block |
|---|---|---|
| `anchor_fingerprint` | 3400 | spatial |
| `origin_direct` | 2300 | network |
| `spatial_stability` | 1700 | spatial |
| `challenge_committed` | 1400 | authentication |
| `biometric_outcome` | 1100 | authentication |
| `identity_authenticated` | 900 | authentication |
| `relay_integrity` | 800 | network |
| `device_bound` | 700 | authentication |
| `relay_depth` | 450 | network |
| `clock_consistency` | 250 | temporal |

**Read the top of that table.** The two largest weights in the entire scheme are
the two spatial features, and both are `reserved` on this build. That ordering is
the argument the configuration encodes: the majority of the designed evidence base
is about *where the device is*, and none of it is available. The accepted residual
risk is therefore stated as arithmetic rather than as a caveat somebody has to
remember to repeat.

### The discount

Within a block, the **strongest** feature is credited in full and every other is
credited at `fusion.correlated_credit_pct` — 35% — of its weight. The block total
is then capped at `fusion.block_cap_millinats`, 4600.

One conservative fraction, applied uniformly, is the honest stand-in for a
dependency structure nobody here has measured. A full correlation matrix would
*read* as a measurement, and it would be a fabrication: there is no dataset from
which those correlations were estimated. A single stated fraction is visibly a
choice.

Ties break on the alphabetically first feature name, so the same vector always
credits the same feature in full. An unstable leader would make a recorded figure
irreproducible for no gain in accuracy at all.

### Three totals over the same vector

The identical arithmetic runs three times under three assumptions about the
features that did not arrive:

| Assumption | Absent features are worth |
|---|---|
| `attained` | Nothing. This is the score. |
| `obtainable` | Full weight, if *this handset* could have supplied them |
| `ceiling` | Full weight, unconditionally |

Because the same discount and the same cap apply in all three passes, the three
numbers are directly comparable, and two ratios fall out of them:

- **`coverage_pct` = attained / ceiling** — how much of the *designed* evidence
  base this figure rests on. Not a confidence. On this build it sits near a
  quarter however perfectly a student behaves, because the two spatial weights are
  reserved.
- **`supplied_pct` = attained / obtainable** — how much of what *this handset*
  could have shown, it actually showed. This is the figure that separates an old
  phone that did everything available to it from a capable one that supplied
  nothing. Adverse evidence lowers it, because a check that ran and failed was
  obtainable and was not supplied.

`Fused.__post_init__` asserts `0 ≤ attained ≤ obtainable ≤ ceiling` and raises if
they are out of order, because an inversion means a weight was credited under one
assumption and not another — a bug that would otherwise surface as an inexplicable
confidence figure.

Worked example, a bare authenticated proof on this build:

```
millinats            2595
coverage_pct        26.91      (of the designed evidence base)
supplied_pct       100.0       (of what this handset could supply)
confidence_milli    None       (uncalibrated: no probability is emitted)
ordering_only       True
evidence_present    identity_authenticated, device_bound, challenge_committed,
                    biometric_outcome, clock_consistency
evidence_missing    origin_direct     unsupported
                    relay_depth       unsupported
                    relay_integrity   unsupported
                    anchor_fingerprint  reserved
                    spatial_stability   reserved
```

A student who did everything right, on a fully capable handset, supplies 100% of
what is available and 26.91% of what was designed. Both numbers are true and they
mean different things; reporting only the first would be the more flattering and
less honest choice.

## The prior, and the refusal to invent one

There is **no default prior.** `fusion.Prior` either carries an observed base rate
or explicitly declares itself undetermined.

The only defensible starting point for *this cohort attends* is what this cohort
has been observed to do. A prior of 0.5 is not a measurement of anything — it is
the number that makes the arithmetic run, and using it would let Bayesian
terminology become decorative while the actual behaviour was "add up the weights".

Two degenerate cases are **refused rather than clamped**:

- No sessions expected for this cohort → undetermined, with a reason string.
- An observed rate of exactly 0% or exactly 100% → undetermined, because those
  have infinite log odds and a large finite stand-in would be an assertion about
  how *certain* the base rate is, dressed up as an estimate and invisible in the
  output.

When the prior is undetermined, `fuse` withholds the posterior entirely and the
score remains an ordering. `Fused.__post_init__` enforces that
`ordering_only == (posterior_milli is None)`: a score is either calibrated enough
to state as a probability or it is an ordering, and there is no third state for a
caller to interpret.

Note where the numbers come from: `Prior.from_base_rate` uses
`metrics.safe_pct`, the same function the analytics engine uses, which returns
`None` on a zero denominator. That is why a cohort with no expected sessions
produces an undetermined prior rather than a division error or a `0/0 = 100%`.

## Scoring does not rule

`fusion.fuse` returns a `Fused` with **no status, no threshold and no verdict**.
`decide.decide` reads it and applies policy.

The separation is there so a reviewer can tell a scoring change from a policy
change. A layer that both scored and ruled is a layer where a threshold can hide
inside the arithmetic — a weight quietly raised until a borderline case tips is
indistinguishable, in a diff, from a legitimate re-weighting.

## Thresholds and the four outcomes

Under `2026.09-provisional`:

| Parameter | Value |
|---|---|
| `decide.present_millinats` | 2500 |
| `decide.secondary_millinats` | 1000 |
| `decide.min_coverage_pct` | 20 |
| `decide.min_supplied_pct` | 90 |

A verdict of `PRESENT` requires **all four** of: score ≥ 2500, coverage ≥ 20%,
supplied ≥ 90%, and an affirmative biometric. The two ratio floors are what stop a
high score from being reached by accumulating many weak signals while most of the
evidence base is missing.

| Outcome | Means |
|---|---|
| `PRESENT` | The evidence resolves and clears every floor |
| `SECONDARY` | Evidence is short of `PRESENT` but nothing is wrong; needs a second check |
| `NOT VERIFIED` | The evidence does not resolve. Nothing was faked |
| `SUSPICIOUS` | Something asserted what it could not have known |

`NOT VERIFIED` and `SUSPICIOUS` are deliberately different outcomes. Collapsing
them would either accuse students whose phone ran out of battery, or hide genuine
forgery attempts among ordinary failures. The seven `decide` reason codes name
which floor was missed: `decide_score_below_present`, `decide_score_below_secondary`,
`decide_coverage_below_minimum`, `decide_supplied_below_minimum`,
`decide_adverse_evidence_present`, `decide_biometric_not_affirmative`,
`decide_self_contradiction`.

The last of those covers a proof whose own signed claims contradict each other or
contradict what the server derived — the client claiming `PRESENT` while its
signed biometric field says `cancelled`, for instance. It is a finding rather than
a rejection reason, because the interesting thing is not that the claim was wrong
but that a signed struct disagreed with itself.

## What "confidence" means, and what it does not

`PresenceDecision.confidence_milli` is `null` on every decision this build
produces.

That is not an oversight and not a missing feature. The active configuration
declares `calibration: "uncalibrated"`, and `fuse` will not convert a log-odds
total into a probability without a determined prior and a calibrated
configuration. `_logistic_milli` exists and is tested; it is simply not reached.

**A score of 0.95 does not mean a 95% probability of genuine presence, and will
not mean that until a field study says it does.** Until then what the score
supports is an ordering: proof A rests on more evidence than proof B. That is
genuinely useful — it is what triage needs — and it is less than a probability.

The word "confidence" is used in this codebase to name the ordering. Where a
figure is a probability it will be labelled a probability, the configuration will
say `calibrated`, and this document will name the dataset it was calibrated
against.

## Calibration: what does not exist yet

`presence/calibrate.py` is **not written.** `presence/lab/` is **empty.** Both are
Phase 3. The `__init__.py` layering diagram lists `calibrate` because that is
where it will sit, not because it is there.

When they are built, the pipeline is:

1. **`lab/`** generates labelled scenarios — genuine attendance and each attack
   from the matrix in `10-validation-plan.md` — and runs them through the **real**
   `gates` → `features` → `fusion` → `decide` path. Not a reimplementation: the
   same functions a request uses, which is what "no database in the decision path"
   bought.
2. **`calibrate.py`** fits likelihoods and thresholds from the labelled output and
   reports Brier score, expected calibration error, a reliability diagram, and
   FAR/FRR across operating points.
3. **Thresholds are chosen from measured operating points** rather than picked.
4. The result is a **new** config artifact — never an edit to an existing one —
   with `calibration` set to something other than `uncalibrated`.

Two constraints on that work, worth stating before it starts:

**Simulator output is not field data.** A configuration fitted on the lab must be
labelled as fitted on the lab, and a FAR measured in simulation must be reported as
a simulation result every time it is quoted. The lab knows only what its RF
propagation model was told; the model is an assumption, not an observation.

**The field study is the only thing that produces a real number.** Physical
handsets, real rooms, real densities, real times of day, marking from inside the
room and then from outside the window, outside the door, the corridor and the
adjacent room. Until that exists, every figure in this layer is a target or a
simulation, and `10-validation-plan.md` keeps the two visibly separate.

## Statistics reuse

Presence imports `attendance.analytics.metrics` rather than growing a second
statistics layer. That module is already dependency-free — stdlib `math`,
`random` and `statistics` only, no scipy, no pandas, and it never imports the
pinned numpy — and it already contains most of what calibration needs:
`percentile` and `percentile_rank`, `stdev`, `median`, IQR fencing, the modified
z-score over MAD, `two_proportion_z` with a `math.erf` normal CDF written
specifically to avoid a scipy dependency, `cusum_change_points`, `ewma`,
`ols_slope`, and a seeded `monte_carlo_forecast` whose determinism is pinned by an
existing test.

numpy 2.2.6 *is* pinned in `backend/requirements.txt` already, for
`verification.py`, so the Phase 3 RF propagation model may use it. The decision
path stays stdlib, so a proof can be re-derived anywhere — including on a machine
that cannot install a wheel.
