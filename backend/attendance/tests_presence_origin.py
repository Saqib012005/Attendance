"""Tests for the teacher broadcast origin.

Four claims, and each one is a rule from the brief that would otherwise live only
in a comment.

**A signal strength is recorded, never compared.** `NoThresholdTests` parses the
module and fails if any comparison operator anywhere in it touches an RSSI value.
`RSSI > threshold = present` is the single-signal scheme this layer exists to
replace, and the surest way to keep it out is to make its appearance a test
failure rather than a review comment.

**The counter is the clock, and `observed_at` is a claim.** A step-*n* frame cannot
exist before step *n* begins, because deriving it needs an epoch key the handset
never holds. `ClaimTests` moves the receiver's clock and asserts that nothing which
can reject a frame moves with it - the same argument, and the same test shape, as
`replay.AuthorityTests`.

**Nothing on the air identifies anybody.** `PrivacyTests` walks the frame layout
and the schema. Seventeen bytes, every one at a named offset, no free text
anywhere: there is no room to broadcast a student, so §43 holds structurally
rather than by anybody remembering it.

**A genuine frame is not proof of a room.** `verify_frame` returning normally means
the teacher's device emitted this, in this session, around now. It does not mean
the listener was inside. That is the window attack, it is unmitigated on this
scope, and `EvidenceTests` asserts the module offers no function that claims
otherwise.
"""
import ast
import inspect
import pathlib

import cbor2
from django.test import SimpleTestCase

from .presence import codec, keys
from .presence import origin as origin_mod
from .presence.challenge import Timing
from .presence.origin import (
    CLAIM_AHEAD,
    CLAIM_BEHIND,
    FORGED,
    FUTURE_COUNTER,
    MALFORMED,
    STALE_COUNTER,
    WRONG_SESSION,
    Frame,
    OriginError,
    Sighting,
)

SESSION_ID = bytes(range(16))
OTHER_SESSION_ID = bytes(range(16, 32))
ROOT = b"\x5a" * 32
SIGNING_SEED = b"\x5b" * 32
START = 1_757_000_000


class Case(SimpleTestCase):
    def setUp(self):
        self.timing = Timing.active()
        self.keys = keys.SessionKeys.load(SESSION_ID, ROOT, SIGNING_SEED)
        self.other = keys.SessionKeys.load(OTHER_SESSION_ID, ROOT, SIGNING_SEED)

    def step_start(self, counter):
        return START + counter * self.timing.step_seconds

    def inside(self, counter):
        """A moment comfortably inside the step, so no test depends on a boundary."""
        return self.step_start(counter) + self.timing.step_seconds // 2

    def frame(self, counter=3):
        return origin_mod.build(self.keys, counter, self.timing)

    def verify(self, raw, counter=3, at=None, session_keys=None):
        return origin_mod.verify_frame(
            raw,
            session_keys or self.keys,
            session_start=START,
            at=self.inside(counter) if at is None else at,
            timing=self.timing,
        )

    def refused(self, code, call, *args, **kwargs):
        with self.assertRaises(OriginError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception

    def sighting(self, counter=3, rssi=-67, observed_at=None):
        return origin_mod.record(
            self.frame(counter),
            rssi=rssi,
            observed_at=self.inside(counter) if observed_at is None else observed_at,
        )


class FrameShapeTests(Case):
    def test_a_frame_fits_a_legacy_advertisement(self):
        """The constraint the whole layout exists to satisfy."""
        self.assertEqual(origin_mod.FRAME_LEN, 17)
        self.assertLessEqual(origin_mod.FRAME_LEN, origin_mod.ADVERTISEMENT_BUDGET)
        self.assertEqual(origin_mod.ADVERTISEMENT_BUDGET, 24)
        self.assertEqual(len(self.frame().pack()), origin_mod.FRAME_LEN)

    def test_the_budget_is_derived_from_the_specification_not_stated(self):
        """So a reviewer can check the subtraction instead of trusting a total."""
        self.assertEqual(
            origin_mod.ADVERTISEMENT_BUDGET,
            origin_mod.ADVERTISEMENT_OCTETS
            - origin_mod.FLAGS_AD_LEN
            - origin_mod.AD_HEADER_LEN
            - origin_mod.COMPANY_ID_LEN,
        )

    def test_pack_and_unpack_are_inverses(self):
        built = self.frame(counter=7)
        self.assertEqual(origin_mod.unpack(built.pack()), built)

    def test_the_layout_is_positional_with_nothing_spare(self):
        raw = self.frame(counter=7).pack()
        self.assertEqual(raw[0], origin_mod.FRAME_VERSION)
        self.assertEqual(raw[1:5], origin_mod.session_ref(self.keys))
        self.assertEqual(int.from_bytes(raw[5:9], "big"), 7)
        self.assertEqual(raw[9:], origin_mod.ephemeral_id(self.keys, 7, self.timing))

    def test_a_frame_of_the_wrong_length_is_refused(self):
        raw = self.frame().pack()
        for wrong in (b"", raw[:-1], raw + b"\x00", raw[:1]):
            with self.subTest(length=len(wrong)):
                self.refused(MALFORMED, origin_mod.unpack, wrong)

    def test_an_unknown_frame_version_is_refused_rather_than_guessed(self):
        """A later version may change what every offset after the first means."""
        raw = bytearray(self.frame().pack())
        raw[0] = origin_mod.FRAME_VERSION + 1
        self.refused(MALFORMED, origin_mod.unpack, bytes(raw))

    def test_a_frame_this_build_cannot_speak_is_not_emitted_either(self):
        odd = Frame(session_ref=b"\x00" * 4, counter=1, ephemeral_id=b"\x00" * 8,
                    version=origin_mod.FRAME_VERSION + 1)
        self.refused(MALFORMED, odd.pack)

    def test_field_widths_come_from_the_schema_not_from_this_module(self):
        """One declaration, so the wire layout and the recorded sighting agree."""
        schema = codec.ORIGIN_SIGHTING
        self.assertEqual(
            origin_mod.SESSION_REF_LEN,
            schema.fields[schema.index("session_ref")].size,
        )
        self.assertEqual(
            origin_mod.EPHEMERAL_ID_LEN,
            schema.fields[schema.index("ephemeral_id")].size,
        )

    def test_a_counter_outside_its_four_bytes_is_refused(self):
        self.refused(MALFORMED, origin_mod.build, self.keys, origin_mod.COUNTER_MAX + 1)
        self.refused(MALFORMED, origin_mod.build, self.keys, -1)

    def test_a_boolean_is_not_a_counter(self):
        self.refused(MALFORMED, origin_mod.build, self.keys, True)


class DerivationTests(Case):
    def test_the_session_reference_is_not_a_prefix_of_the_session_id(self):
        """The session id travels in QR payloads and URLs. A broadcast that leaked
        its first four bytes would let anyone in the building join the two up."""
        ref = origin_mod.session_ref(self.keys)
        self.assertEqual(len(ref), origin_mod.SESSION_REF_LEN)
        self.assertNotEqual(ref, SESSION_ID[: origin_mod.SESSION_REF_LEN])
        self.assertNotIn(ref, SESSION_ID)

    def test_the_reference_is_stable_across_the_whole_session(self):
        """It is a filter, so a handset has to be able to match it all lesson."""
        refs = {origin_mod.build(self.keys, c, self.timing).session_ref
                for c in (0, 1, 19, 20, 21, 500)}
        self.assertEqual(len(refs), 1)

    def test_two_sessions_do_not_share_a_reference(self):
        self.assertNotEqual(
            origin_mod.session_ref(self.keys), origin_mod.session_ref(self.other)
        )

    def test_the_reference_context_cannot_collide_with_an_epoch(self):
        """Epoch contexts are eight-byte integers; this one is three ASCII bytes."""
        self.assertEqual(len(origin_mod.REF_CONTEXT), 3)
        self.assertNotEqual(len(origin_mod.REF_CONTEXT), 8)

    def test_the_identifier_rotates_every_step(self):
        seen = [origin_mod.ephemeral_id(self.keys, c, self.timing) for c in range(8)]
        self.assertEqual(len(set(seen)), len(seen))

    def test_the_identifier_is_deterministic_from_the_same_material(self):
        """Teacher handset and server compute identical bytes with no exchange."""
        twin = keys.SessionKeys.load(SESSION_ID, ROOT, SIGNING_SEED)
        self.assertEqual(
            origin_mod.ephemeral_id(self.keys, 5, self.timing),
            origin_mod.ephemeral_id(twin, 5, self.timing),
        )

    def test_a_leaked_epoch_bounds_what_it_yields(self):
        """The reason the key is derived per epoch rather than once per session."""
        per_epoch = self.timing.steps_per_epoch
        first = origin_mod.origin_key(self.keys, 0, self.timing)
        same = origin_mod.origin_key(self.keys, per_epoch - 1, self.timing)
        next_one = origin_mod.origin_key(self.keys, per_epoch, self.timing)
        self.assertEqual(first, same)
        self.assertNotEqual(first, next_one)

    def test_an_origin_identifier_is_domain_separated_from_a_challenge(self):
        from .presence import challenge as challenge_mod
        self.assertNotEqual(
            origin_mod.mac_input(SESSION_ID, 5),
            challenge_mod.mac_input(SESSION_ID, 0, 5),
        )
        self.assertIn(b"origin", origin_mod.mac_input(SESSION_ID, 5))

    def test_the_identifier_is_eight_bytes_because_that_is_what_fits(self):
        """And is therefore a MAC, not a signature - which is why relay hops sign."""
        self.assertEqual(origin_mod.EPHEMERAL_ID_LEN, 8)
        self.assertLess(origin_mod.EPHEMERAL_ID_LEN, keys.SIGNATURE_LEN)


class VerificationTests(Case):
    def test_a_frame_from_this_session_verifies_inside_its_window(self):
        built = self.frame(counter=3)
        self.assertEqual(self.verify(built.pack(), counter=3).counter, 3)

    def test_a_frame_from_another_session_is_refused(self):
        self.refused(WRONG_SESSION, self.verify, self.frame().pack(),
                     session_keys=self.other)

    def test_a_recording_replayed_later_is_refused(self):
        """The attack this window exists for: capture a frame, walk out, rebroadcast."""
        built = self.frame(counter=0)
        later = self.inside(0) + (self.timing.accept_window_steps + 2) * self.timing.step_seconds
        error = self.refused(STALE_COUNTER, self.verify, built.pack(), at=later)
        self.assertIn("recording rather than a broadcast", str(error))

    def test_a_frame_from_a_step_the_session_has_not_reached_is_refused(self):
        built = self.frame(counter=500)
        self.refused(FUTURE_COUNTER, self.verify, built.pack(), at=self.inside(3))

    def test_one_edited_bit_in_the_identifier_is_refused(self):
        raw = bytearray(self.frame().pack())
        raw[-1] ^= 1
        self.refused(FORGED, self.verify, bytes(raw))

    def test_an_identifier_lifted_from_another_step_is_refused(self):
        """Replaying a still-fresh identifier under a different counter."""
        raw = bytearray(self.frame(counter=3).pack())
        raw[9:] = origin_mod.ephemeral_id(self.keys, 4, self.timing)
        self.refused(FORGED, self.verify, bytes(raw), counter=3)

    def test_an_identifier_from_another_session_is_refused_as_the_wrong_session(self):
        """The reference is checked first, so the reason code names the real problem."""
        raw = bytearray(self.frame().pack())
        raw[1:5] = origin_mod.session_ref(self.other)
        self.refused(WRONG_SESSION, self.verify, bytes(raw))

    def test_the_counter_window_is_checked_before_the_mac(self):
        """Deliberate, and the opposite of proof.verify.

        A counter selects the epoch key the MAC is computed under, so an absurd
        counter would fail the MAC and get reported as a forgery when what
        actually happened is a counter out of range. The reason code has to name
        the real problem or an operator reading flags learns the wrong thing.
        """
        absurd = Frame(
            session_ref=origin_mod.session_ref(self.keys),
            counter=10_000,
            ephemeral_id=b"\x00" * 8,
        )
        self.refused(FUTURE_COUNTER, self.verify, absurd, counter=3)

    def test_the_accept_window_reaches_both_ways(self):
        """Capture-then-submit latency in one direction, a fast clock in the other."""
        window = self.timing.accept_window_steps
        for counter in range(3 - window, 3 + window + 1):
            with self.subTest(counter=counter):
                self.assertEqual(
                    self.verify(self.frame(counter).pack(), at=self.inside(3)).counter,
                    counter,
                )

    def test_the_window_comes_from_the_artifact_not_from_this_module(self):
        """A rollout widens it by shipping an artifact, with no code change."""
        wide = Timing(
            step_seconds=self.timing.step_seconds,
            steps_per_epoch=self.timing.steps_per_epoch,
            lifetime_seconds=self.timing.lifetime_seconds,
            clock_skew_seconds=self.timing.clock_skew_seconds,
            accept_window_steps=self.timing.accept_window_steps + 5,
            version="test-artifact",
        )
        old = self.frame(counter=0)
        self.refused(STALE_COUNTER, self.verify, old.pack(), at=self.inside(6))
        self.assertEqual(
            origin_mod.verify_frame(
                old.pack(), self.keys, session_start=START,
                at=self.inside(6), timing=wide,
            ).counter,
            0,
        )

    def test_a_verified_frame_is_returned_so_a_caller_uses_checked_values(self):
        """Not a boolean. A caller that got True back would go on to read the
        counter off the wire itself, which is the field this module just checked."""
        self.assertIsInstance(self.verify(self.frame().pack()), Frame)


class SightingTests(Case):
    def test_a_sighting_round_trips_through_the_canonical_codec(self):
        made = self.sighting()
        self.assertEqual(origin_mod.parse_sighting(made.encode()), made)

    def test_a_sighting_carries_the_frame_plus_what_only_the_receiver_knows(self):
        made = self.sighting(rssi=-71)
        self.assertEqual(made.rssi, -71)
        self.assertEqual(made.frame, self.frame())
        self.assertEqual(
            set(made.values()),
            {"session_ref", "counter", "ephemeral_id", "rssi_offset", "observed_at"},
        )

    def test_a_digest_is_stable_and_is_what_a_proof_commits_to(self):
        made = self.sighting()
        self.assertEqual(made.digest(), codec.digest_bytes(made.encode()))
        self.assertEqual(len(made.digest()), 32)

    def test_a_loosely_encoded_sighting_is_refused(self):
        """One observation must not be re-encodable as a second, independent one."""
        made = self.sighting()
        items = cbor2.loads(made.encode())
        loose = b"\x9f" + b"".join(cbor2.dumps(i) for i in items) + b"\xff"
        self.assertNotEqual(loose, made.encode())
        self.assertEqual(cbor2.loads(loose), items)
        self.refused(MALFORMED, origin_mod.parse_sighting, loose)

    def test_another_struct_cannot_be_read_as_a_sighting(self):
        other = codec.encode(codec.ANCHOR_READING.name, {
            "anchor_ref": b"\x01\x02\x03\x04", "ephemeral_id": b"\xe0" * 8,
            "rssi_offset": 60, "sample_count": 4, "observed_at": START,
        })
        self.refused(MALFORMED, origin_mod.parse_sighting, other)

    def test_a_verified_sighting_comes_back_with_its_signals(self):
        made = self.sighting()
        back, found = origin_mod.verify_sighting(
            made.encode(), self.keys, session_start=START,
            at=self.inside(3), timing=self.timing,
        )
        self.assertEqual(back, made)
        self.assertEqual(found, ())

    def test_a_sighting_of_another_session_is_refused(self):
        self.refused(
            WRONG_SESSION, origin_mod.verify_sighting, self.sighting().encode(),
            self.other, session_start=START, at=self.inside(3), timing=self.timing,
        )

    def test_an_unrepresentable_signal_strength_is_refused(self):
        for dbm in (200, 128, -200, -129):
            with self.subTest(dbm=dbm):
                self.refused(MALFORMED, origin_mod.to_offset, dbm)

    def test_an_implausible_reading_is_encoded_rather_than_judged(self):
        """A positive dBm is not physically sensible for BLE, and this module
        still accepts it. Rejecting it would mean inventing a plausibility bound
        with no artifact behind it - the tuned-value-in-code failure the config
        registry exists to stop. An odd reading is something for fusion to weigh
        against everything else, not something for a codec to refuse.
        """
        self.assertEqual(origin_mod.rssi_dbm(origin_mod.to_offset(5)), 5)

    def test_the_representable_range_spans_what_a_radio_reports(self):
        for dbm in (-100, -90, -67, -40, -20, 0):
            with self.subTest(dbm=dbm):
                self.assertEqual(origin_mod.rssi_dbm(origin_mod.to_offset(dbm)), dbm)

    def test_a_signal_strength_is_unsigned_on_the_wire(self):
        """The codec carries no signed integers, so a negative dBm is offset once
        and converted back once, rather than at every call site."""
        field = codec.ORIGIN_SIGHTING.fields[codec.ORIGIN_SIGHTING.index("rssi_offset")]
        self.assertEqual(field.kind, codec.UINT)
        self.assertGreaterEqual(origin_mod.to_offset(-100), 0)


class ClaimTests(Case):
    """§39 in this module: the counter is the clock, `observed_at` is a claim."""

    def test_nothing_that_can_reject_a_sighting_moves_with_the_receivers_clock(self):
        for claimed in (0, START, START + 100_000, codec.UINT_MAX):
            with self.subTest(observed_at=claimed):
                made = self.sighting(observed_at=claimed)
                back, _ = origin_mod.verify_sighting(
                    made.encode(), self.keys, session_start=START,
                    at=self.inside(3), timing=self.timing,
                )
                self.assertEqual(back.frame.counter, 3)

    def test_a_disagreeing_clock_produces_a_signal_and_not_a_refusal(self):
        """Common and innocent. A handset with a wrong clock is not an attacker."""
        ahead = self.sighting(observed_at=self.inside(3) + 100_000)
        behind = self.sighting(observed_at=START - 100_000 if START > 100_000 else 0)
        self.assertEqual(origin_mod.signals(ahead, START, self.timing), (CLAIM_AHEAD,))
        self.assertEqual(origin_mod.signals(behind, START, self.timing), (CLAIM_BEHIND,))

    def test_a_clock_inside_the_skew_allowance_produces_nothing(self):
        skew = self.timing.clock_skew_seconds
        edge = self.sighting(observed_at=self.inside(3) + skew)
        self.assertEqual(origin_mod.signals(edge, START, self.timing), ())

    def test_the_signal_check_is_not_given_the_current_time_at_all(self):
        """Its signature is the guarantee: the comparison is claim against counter,
        so there is nowhere to pass in a moment that could be tuned to agree."""
        parameters = set(inspect.signature(origin_mod.signals).parameters)
        self.assertEqual(parameters, {"sighting", "session_start", "timing"})

    def test_the_authoritative_window_comes_from_the_counter(self):
        earliest, latest = origin_mod.counter_bounds(START, 3, self.timing)
        self.assertEqual(earliest, START + 3 * self.timing.step_seconds)
        self.assertEqual(latest, earliest + self.timing.lifetime_seconds)

    def test_a_signal_is_not_a_reason_code(self):
        """Two vocabularies, deliberately disjoint: one weighs, the other refuses."""
        self.assertEqual(origin_mod.SIGNALS & origin_mod.REASON_CODES, frozenset())

    def test_a_sighting_names_its_own_claim_as_a_claim(self):
        self.assertIn("claimed_observed_at", self.sighting().describe())
        self.assertNotIn("observed_at", self.sighting().describe())


class NoThresholdTests(Case):
    """§16, enforced by reading the module rather than by remembering the rule."""

    def source(self):
        return pathlib.Path(inspect.getfile(origin_mod)).read_text(encoding="utf-8")

    # The only names an RSSI comparison may mention. Everything here is about
    # whether a reading fits in the byte the codec carries; nothing here is about
    # where the reading came from. A comparison against any other name is either a
    # distance test or a tuned bound, and both belong somewhere else.
    REPRESENTABILITY = {
        "RSSI_OFFSET_MIN", "RSSI_OFFSET_MAX", "RSSI_OFFSET_BASE",
        "offset", "dbm", "rssi", "rssi_offset",
    }

    def test_no_comparison_in_this_module_thresholds_a_signal_strength(self):
        tree = ast.parse(self.source())
        checked = 0
        offences = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            names = {
                n.id for n in ast.walk(node) if isinstance(n, ast.Name)
            } | {
                n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)
            }
            if not any("rssi" in name.lower() or name == "dbm" for name in names):
                continue
            checked += 1
            stray = names - self.REPRESENTABILITY
            if stray:
                offences.append("line %d compares against %s" % (
                    node.lineno, ", ".join(sorted(stray))
                ))
        self.assertGreater(checked, 0, "no rssi comparison found; is the scan working?")
        self.assertEqual(
            offences, [],
            "an rssi comparison against anything but the representable range is a "
            "distance test or a tuned threshold. Neither belongs in this module: "
            "a bound goes in a configuration artifact, and a distance is a model's "
            "job, not a codec's.\n" + "\n".join(offences),
        )

    def test_the_module_offers_no_function_that_judges_distance_or_presence(self):
        """A verdict-shaped name is how RSSI thresholding gets reintroduced."""
        forbidden = ("distance", "meters", "metres", "nearby", "proximity",
                     "is_present", "in_room", "inside")
        for name in dir(origin_mod):
            if name.startswith("_"):
                continue
            with self.subTest(name=name):
                self.assertFalse(
                    any(word in name.lower() for word in forbidden),
                    "%s reads like a spatial verdict; this module records "
                    "observations and decides nothing" % name,
                )

    def test_verification_ignores_the_signal_strength_entirely(self):
        """The strongest form of the rule: the reading cannot affect the outcome."""
        outcomes = set()
        for dbm in (-100, -67, -20):
            made = self.sighting(rssi=dbm)
            back, found = origin_mod.verify_sighting(
                made.encode(), self.keys, session_start=START,
                at=self.inside(3), timing=self.timing,
            )
            outcomes.add((back.frame.counter, found))
        self.assertEqual(len(outcomes), 1, outcomes)


class PrivacyTests(Case):
    """§43: nothing identifying goes on the air, and the layout is the guarantee."""

    def test_the_frame_has_no_room_for_anything_but_its_four_fields(self):
        self.assertEqual(
            origin_mod.VERSION_LEN
            + origin_mod.SESSION_REF_LEN
            + origin_mod.COUNTER_LEN
            + origin_mod.EPHEMERAL_ID_LEN,
            origin_mod.FRAME_LEN,
        )

    def test_the_frame_carries_no_session_identifier(self):
        raw = self.frame().pack()
        self.assertNotIn(SESSION_ID, raw)
        for width in range(4, len(SESSION_ID) + 1):
            with self.subTest(width=width):
                self.assertNotIn(SESSION_ID[:width], raw)

    def test_the_frame_carries_no_key_material(self):
        raw = self.frame().pack()
        self.assertNotIn(ROOT, raw)
        self.assertNotIn(SIGNING_SEED, raw)
        self.assertNotIn(self.keys.public().public_bytes, raw)
        self.assertNotIn(origin_mod.origin_key(self.keys, 3, self.timing), raw)

    def test_a_sighting_says_nothing_about_who_observed_it(self):
        """Who comes from the proof that commits to the digest, resolved through a
        device key. An observation on its own is not attributable to a student,
        which is what lets one be discarded without discarding a person's record."""
        names = {f.name for f in codec.ORIGIN_SIGHTING.fields}
        for forbidden in ("student", "student_id", "device_key_id", "email", "name"):
            with self.subTest(field=forbidden):
                self.assertNotIn(forbidden, names)

    def test_no_field_anywhere_carries_free_text(self):
        """Free text is where a face template or an email address would fit."""
        for f in codec.ORIGIN_SIGHTING.fields:
            with self.subTest(field=f.name):
                self.assertIn(f.kind, (codec.UINT, codec.BYTES))
                if f.kind == codec.BYTES:
                    self.assertLessEqual(f.size, 8)

    def test_describing_a_sighting_leaks_no_key_material(self):
        rendered = repr(self.sighting().describe())
        self.assertNotIn(ROOT.hex(), rendered)
        self.assertNotIn(origin_mod.origin_key(self.keys, 3, self.timing).hex(), rendered)

    def test_the_linkability_cost_is_the_one_that_was_accepted(self):
        """Stated rather than hidden: a listener can tell two frames belong to the
        same session, because that is what makes the reference usable as a filter.
        It lasts one period and links to no person. What a listener must not be
        able to do is tie two sessions together."""
        mine = origin_mod.build(self.keys, 3, self.timing).session_ref
        theirs = origin_mod.build(self.other, 3, self.timing).session_ref
        self.assertEqual(mine, origin_mod.build(self.keys, 9, self.timing).session_ref)
        self.assertNotEqual(mine, theirs)


class EvidenceTests(Case):
    """A genuine frame is evidence. It is not proof of a room, and this is where
    that is written down in a form that fails if somebody changes their mind."""

    def test_a_frame_verified_from_outside_the_room_still_verifies(self):
        """The window attack, asserted rather than described.

        Nothing about position enters `verify_frame`, so a student in the corridor
        holding a genuine frame is indistinguishable from one in the third row.
        That is the accepted, unmitigated residual risk on this scope, and only
        the deferred anchor-fingerprint work gives spatial discrimination. A test
        that failed here would mean somebody had started to believe otherwise.
        """
        outside = self.sighting(rssi=-95)
        inside = self.sighting(rssi=-52)
        args = dict(session_start=START, at=self.inside(3), timing=self.timing)
        self.assertEqual(
            origin_mod.verify_sighting(outside.encode(), self.keys, **args)[1],
            origin_mod.verify_sighting(inside.encode(), self.keys, **args)[1],
        )

    def test_there_is_no_reason_code_for_a_missing_frame(self):
        """Absence is not negative evidence. Most handsets on this scope cannot
        scan at all, and a student with the wrong phone must not become
        unverifiable - it lowers confidence toward SECONDARY and nothing more."""
        for code in origin_mod.REASON_CODES:
            with self.subTest(code=code):
                for word in ("absent", "missing", "none", "unavailable"):
                    self.assertNotIn(word, code)

    def test_every_reason_code_is_declared_before_it_can_be_raised(self):
        with self.assertRaises(AssertionError):
            OriginError("origin_invented_on_the_spot", "not in REASON_CODES")

    def test_the_module_says_out_loud_what_a_pass_does_not_mean(self):
        """Documentation that a test enforces is documentation that survives."""
        doc = origin_mod.__doc__
        self.assertIn("evidence, not a gate", doc)
        self.assertIn("does not prove a room", doc)
        verify_doc = origin_mod.verify_frame.__doc__
        self.assertIn("does not mean the listener was in the room", verify_doc)
