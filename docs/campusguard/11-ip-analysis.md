# 11 — IP analysis (public stub)

**This file is deliberately incomplete.** The mechanism-by-mechanism analysis, the
prior-art search plan, the trade-secret candidates and the competitor-reproduction
assessment live in `docs/campusguard/private/11-ip-analysis.md`, which is
`.gitignore`d and not committed.

## Why it is withheld

This repository is **public**, under three remotes — `origin`
(Saqib012005/Attendance), `upstream` (Sujan-Bhat/Attendance) and `vizzard`
(VIZZARD-X/Attendance), all confirmed public on 2026-09-05 — with CI deploying
publicly. Two consequences follow, and neither is a matter of preference:

1. **Public availability can start novelty clocks in some jurisdictions.** The source
   is already public, which is a disclosure that has already happened and cannot be
   undone by a directory choice. Adding a document that describes each mechanism, why
   it may be differentiated, and what a search would have to cover is a *further*
   disclosure, and an unusually well-organised one.
2. **A reproduction analysis is a reproduction guide.** §92 asks how quickly a
   competent competitor could rebuild this. Written honestly, that answer is a
   roadmap. It belongs where it is useful to the people who own the work and nowhere
   else.

The protocol and crypto specifications *are* public in this tree
(`01-protocol-spec.md`, `02-crypto-spec.md`), which is a deliberate and defensible
choice for a security design — a protocol whose security depends on its own secrecy
is not a secure protocol. The IP analysis is a different kind of document: it is
about commercial position rather than about whether the system works, and nothing is
lost by keeping it out of the public tree.

## The honest framing, stated publicly because it should be

The individual layers of this system are **well-trodden prior art.** That is worth
saying in the public tree, because the opposite impression is the expensive one.

Sampled prior art, all publicly available and none of it a search result anyone
should rely on as complete:

| Reference | Territory |
|---|---|
| `CN106023021A` | BLE-beacon classroom attendance |
| `US9924026B2` | classroom attendance with device management |
| `US9843896B1` | education proximity services |
| `US10614479B2` | attendance verification (IBM) |
| `US10395450B2` | attendance with location data |
| `ES2550112B1` | classroom presence control |
| `US20230045013A1` | student attendance and movement tracking |
| `US10499196B2` | BLE central/peripheral role reversal, peripheral location determination (Link Labs) |
| *MDPI Information* 11(6):329 (2020) | RSSI-fingerprint BLE indoor positioning for classroom attendance |
| arXiv 2510.16557 | evidence-theoretic fusion of hybrid Wi-Fi/BLE fingerprints |

So: **QR attendance, BLE-proximity attendance, RSSI fingerprinting and biometric
attendance are common prior art.** Any claim to the contrary would be wrong on facts
that take an afternoon to check.

What is *potentially* differentiated is narrower, and stating it narrowly is the
point:

- the authenticated **relay chain of custody as attendance evidence**, rather than as
  a networking mechanism;
- its combination with room-calibrated multi-anchor fingerprints under
  **dependency-aware calibrated fusion** rather than naive multiplication;
- the **offline signed proof with server-side re-derivation**, where the client's own
  verdict, confidence and hop count are recorded as claims and never trusted.

Two of those three are **unbuilt on this scope.** The relay chain is Phase 6 and the
anchor fingerprint is Phase 5. The third is built and tested. A differentiation
argument that leans on the two unbuilt mechanisms is an argument about a design, not
about a system, and the difference matters to anyone evaluating it.

## What this document does not do

- **No patentability opinion.** Not here, and not in the private file either. Whether
  any of this is patentable is a question for qualified counsel, and a novel-sounding
  idea is not a validated invention.
- **No claim that the prior-art sample above is a search.** It is a sample, gathered
  to establish that the territory is dense. A search is a professional exercise with
  a defined scope.
- **No moat claim.** The narrow list above is what might be differentiated, not a
  defensible position, and the two largest items in it do not exist yet.

## Recommendation

**Talk to counsel about the disclosure that has already happened, before any further
public disclosure.** The source has been public across three remotes for some time;
that fact is independent of anything in this documentation and is the first thing a
lawyer will need to know. The decision about whether the protocol specifications
should remain in a public repository is also theirs to inform, not mine to make by
choosing a directory.

Until then the private file is where the analysis lives, and this stub is what the
public tree says about it.
