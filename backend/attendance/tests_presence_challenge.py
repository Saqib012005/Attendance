"""Tests for the rolling challenge.

The old primitive failed in one sentence: possession of a session UUID and a
two-digit code was enough to be marked present, all lesson, from anywhere. So the
tests here are organised around what specifically must now be impossible, not
around the functions in the module:

* a capture cannot be re-presented after its step (`ServerVerificationTests`,
  `StudentVerificationTests`),
* a value cannot be manufactured without the session's root secret
  (`KeySeparationTests`),
* and the numbers that decide all of the above come from a configuration artifact
  rather than from the module (`TimingArtifactTests`), which is also how the last
  of those tests proves the two overlapping staleness bounds are both live.

`SimpleTestCase`: nothing here touches the database. Times are integers chosen so
arithmetic is checkable by eye, and never `now()` - a test that reads the clock
tests the clock.
"""
from types import MappingProxyType

from django.test import SimpleTestCase

from .presence import challenge as C
from .presence import codec, config
from .presence.keys import SessionKeys

SESSION_ID = bytes(range(16))
OTHER_SESSION_ID = bytes(range(16, 32))

# A round number well clear of any epoch boundary in the artifact, so a reader can
# add step offsets in their head.
START = 1_757_000_000


class ChallengeCase(SimpleTestCase):
    """Shared fixture: one session's keys, the active timing, one step-0 challenge."""

    def setUp(self):
        self.keys = SessionKeys.generate(SESSION_ID)
        self.public = self.keys.public()
        self.timing = C.Timing.active()
        self.step = self.timing.step_seconds
        self.challenge = self.issue(at=START + 1)

    def issue(self, *, at, keys=None, start=START, timing=None):
        return C.issue(
            keys or self.keys,
            session_start=start,
            at=at,
            timing=timing or self.timing,
        )

    def resigned(self, base=None, **overrides):
        """A challenge with altered fields and a *valid* signature over them.

        Needed because the signature covers every field: without re-signing, every
        tampering test would stop at BAD_SIGNATURE and the checks behind it - the
        structural ones, and the derivation - would never be exercised at all. It
        also happens to model a real threat: whoever holds the session signing key
        but not the root secret.
        """
        values = dict((base or self.challenge).values)
        values.update(overrides)
        signature = self.keys.signing.sign(codec.encode(codec.QR_CHALLENGE.name, values))
        return C.Challenge(signature=signature, **values)

    def assertCode(self, code, callable_obj):
        with self.assertRaises(C.ChallengeError) as caught:
            callable_obj()
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception

    def verify_public(self, ch=None, *, at, **kwargs):
        kwargs.setdefault("verify_key", self.public)
        kwargs.setdefault("session_id", SESSION_ID)
        kwargs.setdefault("session_start", START)
        kwargs.setdefault("timing", self.timing)
        return C.verify_public((ch or self.challenge).payload, at=at, **kwargs)

    def verify_server(self, ch=None, *, at, **kwargs):
        kwargs.setdefault("session_keys", self.keys)
        kwargs.setdefault("session_start", START)
        kwargs.setdefault("timing", self.timing)
        return C.verify_authoritative((ch or self.challenge).payload, at=at, **kwargs)


class StepArithmeticTests(ChallengeCase):
    def test_a_step_covers_exactly_step_seconds(self):
        self.assertEqual(C.step_index(START, START, self.timing), 0)
        self.assertEqual(C.step_index(START, START + self.step - 1, self.timing), 0)
        self.assertEqual(C.step_index(START, START + self.step, self.timing), 1)

    def test_a_moment_before_the_session_is_a_negative_step(self):
        """Not clamped to zero: clamping would accept a pre-session challenge."""
        self.assertEqual(C.step_index(START, START - 1, self.timing), -1)
        self.assertEqual(C.step_index(START, START - self.step, self.timing), -1)
        self.assertEqual(C.step_index(START, START - self.step - 1, self.timing), -2)

    def test_epoch_turns_over_after_steps_per_epoch(self):
        n = self.timing.steps_per_epoch
        self.assertEqual(C.epoch_of(n - 1, self.timing), 0)
        self.assertEqual(C.epoch_of(n, self.timing), 1)
        self.assertEqual(C.epoch_of(2 * n, self.timing), 2)

    def test_step_bounds_start_on_the_boundary_and_outlive_the_step(self):
        issued, expires = C.step_bounds(START, 3, self.timing)
        self.assertEqual(issued, START + 3 * self.step)
        self.assertEqual(expires, issued + self.timing.lifetime_seconds)
        self.assertGreater(
            expires - issued, self.step, "a scan straddling a rotation must survive"
        )

    def test_the_mac_input_is_a_fixed_thirty_two_bytes(self):
        raw = C.mac_input(SESSION_ID, 1, 2)
        self.assertEqual(len(raw), 32)
        self.assertEqual(raw[:16], SESSION_ID)
        self.assertEqual(raw[16:24], (1).to_bytes(8, "big"))
        self.assertEqual(raw[24:], (2).to_bytes(8, "big"))

    def test_the_mac_input_refuses_anything_it_cannot_lay_out(self):
        for args in (
            (SESSION_ID[:15], 0, 0),
            (SESSION_ID + b"x", 0, 0),
            (SESSION_ID, -1, 0),
            (SESSION_ID, 0, C.SENTINEL + 1),
            (SESSION_ID, True, 0),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    C.mac_input(*args)


class IssueTests(ChallengeCase):
    def test_a_challenge_is_a_pure_function_of_its_step(self):
        """Every instant inside one step yields byte-identical payloads.

        This is what lets the teacher's offline device and the server agree, and it
        means the displayed QR only needs redrawing when the step turns over.
        """
        payloads = {self.issue(at=START + i).payload for i in range(self.step)}
        self.assertEqual(len(payloads), 1)

    def test_the_next_step_is_different_bytes(self):
        self.assertNotEqual(
            self.issue(at=START).payload, self.issue(at=START + self.step).payload
        )

    def test_each_step_carries_its_predecessor(self):
        first = self.issue(at=START)
        second = self.issue(at=START + self.step)
        third = self.issue(at=START + 2 * self.step)
        self.assertEqual(second.prev_link, first.challenge)
        self.assertEqual(third.prev_link, second.challenge)

    def test_the_chain_links_across_an_epoch_boundary(self):
        n = self.timing.steps_per_epoch
        last_of_epoch = self.issue(at=START + (n - 1) * self.step)
        first_of_next = self.issue(at=START + n * self.step)
        self.assertEqual(last_of_epoch.epoch, 0)
        self.assertEqual(first_of_next.epoch, 1)
        self.assertEqual(first_of_next.prev_link, last_of_epoch.challenge)
        self.assertNotEqual(self.keys.epoch_key(0), self.keys.epoch_key(1))

    def test_step_zero_carries_a_genesis_link_that_is_not_zeros(self):
        """Zeros would be a value anyone can write; this one needs the epoch key."""
        self.assertEqual(self.issue(at=START).prev_link, C.genesis_link(self.keys))
        self.assertNotEqual(C.genesis_link(self.keys), bytes(C.LINK_LEN))

    def test_the_genesis_link_cannot_collide_with_a_real_step(self):
        """The sentinel epoch and step are unreachable, so no real value equals it."""
        genesis = C.genesis_link(self.keys)
        for seq in range(0, 3 * self.timing.steps_per_epoch):
            epoch = C.epoch_of(seq, self.timing)
            value = C.challenge_value(
                self.keys.epoch_key(epoch), SESSION_ID, epoch, seq
            )
            self.assertNotEqual(value, genesis)

    def test_a_challenge_before_the_session_is_refused(self):
        self.assertCode(C.NOT_YET_VALID, lambda: self.issue(at=START - 1))

    def test_two_sessions_never_share_a_challenge_value(self):
        other = SessionKeys.generate(OTHER_SESSION_ID)
        self.assertNotEqual(
            self.issue(at=START).challenge, self.issue(at=START, keys=other).challenge
        )

    def test_the_payload_is_the_signed_struct_then_the_signature(self):
        ch = self.challenge
        self.assertEqual(ch.payload, ch.signed_bytes + ch.signature)
        self.assertEqual(len(ch.signature), C.SIGNATURE_LEN)
        self.assertEqual(ch.digest, codec.digest(codec.QR_CHALLENGE.name, ch.values))

    def test_the_display_code_is_the_same_bytes_in_readable_form(self):
        code = self.challenge.display_code()
        self.assertEqual(len(code), 13)
        self.assertNotIn("=", code)
        self.assertEqual(code, code.upper())


class StudentVerificationTests(ChallengeCase):
    """What a handset can establish offline, holding only the session public key."""

    def test_a_current_challenge_verifies(self):
        self.assertEqual(
            self.verify_public(at=START + 1).challenge, self.challenge.challenge
        )

    def test_it_works_without_knowing_when_the_session_started(self):
        """A weaker check rather than a fabricated one, and it says which it is."""
        self.verify_public(at=START + 1, session_start=None)

    def test_a_challenge_for_another_session_is_refused(self):
        self.assertCode(
            C.WRONG_SESSION,
            lambda: self.verify_public(at=START + 1, session_id=OTHER_SESSION_ID),
        )

    def test_a_challenge_signed_by_another_session_key_is_refused(self):
        other = SessionKeys.generate(SESSION_ID)
        self.assertCode(
            C.UNKNOWN_KEY,
            lambda: self.verify_public(at=START + 1, verify_key=other.public()),
        )

    def test_a_bad_signature_is_refused(self):
        forged = C.Challenge(signature=bytes(C.SIGNATURE_LEN), **self.challenge.values)
        self.assertCode(C.BAD_SIGNATURE, lambda: self.verify_public(forged, at=START + 1))

    def test_one_flipped_bit_under_the_signature_is_refused(self):
        """The low bit of the last field: still canonical CBOR, still this
        session, so the signature is the check that has to catch it."""
        raw = bytearray(self.challenge.payload)
        raw[-C.SIGNATURE_LEN - 1] ^= 0x01
        self.assertCode(
            C.BAD_SIGNATURE,
            lambda: C.verify_public(
                bytes(raw),
                verify_key=self.public,
                session_id=SESSION_ID,
                at=START + 1,
                timing=self.timing,
            ),
        )

    def test_a_screenshot_from_a_previous_step_is_refused(self):
        """The whole point. A forwarded capture is stale before it can be used."""
        self.assertCode(
            C.EXPIRED,
            lambda: self.verify_public(at=START + self.timing.lifetime_seconds + 100),
        )

    def test_clock_tolerance_is_exactly_the_declared_allowance(self):
        limit = START + self.timing.lifetime_seconds + self.timing.clock_skew_seconds
        self.verify_public(at=limit)
        self.assertCode(C.EXPIRED, lambda: self.verify_public(at=limit + 1))

    def test_tolerance_applies_in_both_directions(self):
        later = self.issue(at=START + 5 * self.step)
        early = later.issued_at - self.timing.clock_skew_seconds
        self.verify_public(later, at=early)
        self.assertCode(C.NOT_YET_VALID, lambda: self.verify_public(later, at=early - 1))

    def test_the_expiry_message_admits_the_tolerance_it_already_gave(self):
        exc = self.assertCode(
            C.EXPIRED, lambda: self.verify_public(at=START + 10_000)
        )
        self.assertIn("clock tolerance already allowed", str(exc))

    def test_a_structurally_impossible_challenge_is_refused_without_any_secret(self):
        """No epoch key needed to see that epoch 3 does not contain step 0."""
        self.assertCode(
            C.TIMING_INCONSISTENT,
            lambda: self.verify_public(self.resigned(epoch=3), at=START + 1),
        )


class ParseTests(ChallengeCase):
    def test_junk_is_refused(self):
        for bad in (b"", b"\x00" * 40, b"not a challenge at all", bytes(200)):
            with self.subTest(length=len(bad)):
                self.assertCode(C.MALFORMED, lambda bad=bad: C.parse(bad))

    def test_non_bytes_is_refused(self):
        for bad in (None, 17, "8a0101", ["payload"]):
            with self.subTest(value=bad):
                self.assertCode(C.MALFORMED, lambda bad=bad: C.parse(bad))

    def test_trailing_bytes_are_refused(self):
        """Strict decoding: two byte strings must never stand for one challenge."""
        self.assertCode(
            C.MALFORMED, lambda: C.parse(self.challenge.payload + b"\xff")
        )

    def test_a_proof_struct_is_not_a_challenge(self):
        values = {
            f.name: (
                bytes(f.size) if f.kind == codec.BYTES
                else [] if f.kind == codec.ARRAY
                else 1
            )
            for f in codec.ATTENDANCE_PROOF.fields
        }
        raw = codec.encode(codec.ATTENDANCE_PROOF.name, values) + bytes(C.SIGNATURE_LEN)
        self.assertCode(C.MALFORMED, lambda: C.parse(raw))

    def test_parse_makes_no_authenticity_claim(self):
        """It returns a Challenge for a well-formed, wholly unsigned struct."""
        unsigned = C.Challenge(signature=bytes(C.SIGNATURE_LEN), **self.challenge.values)
        self.assertEqual(C.parse(unsigned.payload).seq, self.challenge.seq)


class ServerVerificationTests(ChallengeCase):
    """What the server establishes, holding the root secret. Nothing is trusted."""

    def test_a_current_challenge_verifies(self):
        self.verify_server(at=START + 1)

    def test_a_challenge_one_step_behind_is_still_accepted(self):
        """Capture-then-submit latency is not an attack."""
        first = self.issue(at=START)
        self.verify_server(first, at=START + self.step + 1)

    def test_a_challenge_too_far_behind_is_refused(self):
        exc = self.assertCode(
            C.STALE_STEP,
            lambda: self.verify_server(at=START + 5 * self.step),
        )
        self.assertIn("steps behind", str(exc))

    def test_a_challenge_the_session_has_not_reached_is_refused(self):
        """A future step cannot have been displayed, so it is not latency."""
        ahead = self.issue(at=START + 9 * self.step)
        self.assertCode(C.FUTURE_STEP, lambda: self.verify_server(ahead, at=START + 1))

    def test_no_clock_tolerance_is_granted_to_the_client(self):
        """The server's clock is the authority; a handset's disagreement is not evidence."""
        past_public_tolerance = (
            START + self.timing.lifetime_seconds + self.timing.clock_skew_seconds
        )
        self.verify_public(at=past_public_tolerance)
        exc = self.assertCode(
            C.EXPIRED, lambda: self.verify_server(at=past_public_tolerance)
        )
        self.assertNotIn("tolerance", str(exc))

    def test_liveness_is_skipped_only_when_the_caller_says_so(self):
        """`at=None` is the queued-proof path: the challenge is legitimately dead.

        How long the proof may have been queued is `proof.max_offline_hours`,
        enforced where that parameter lives. The omission has to be written out, so
        it cannot be skipped by accident.
        """
        self.verify_server(at=None)

    def test_a_forged_challenge_value_is_refused(self):
        """The check a signature cannot substitute for."""
        self.assertCode(
            C.FORGED,
            lambda: self.verify_server(self.resigned(challenge=b"\x01" * 8), at=START + 1),
        )

    def test_a_value_from_a_different_step_of_the_same_session_is_refused(self):
        """Lifting a real challenge value into another step's struct fails."""
        later = self.issue(at=START + 3 * self.step)
        self.assertCode(
            C.FORGED,
            lambda: self.verify_server(
                self.resigned(challenge=later.challenge), at=START + 1
            ),
        )

    def test_a_broken_chain_link_is_refused(self):
        exc = self.assertCode(
            C.LINK_BROKEN,
            lambda: self.verify_server(self.resigned(prev_link=b"\x02" * 8), at=START + 1),
        )
        self.assertIn("genesis", str(exc))

    def test_a_later_step_must_carry_the_right_predecessor(self):
        third = self.issue(at=START + 3 * self.step)
        self.assertCode(
            C.LINK_BROKEN,
            lambda: self.verify_server(
                self.resigned(third, prev_link=C.genesis_link(self.keys)),
                at=START + 3 * self.step,
            ),
        )

    def test_a_restamped_challenge_is_refused(self):
        """Moving a dead challenge forward in time breaks the step arithmetic."""
        for field in ("issued_at", "expires_at"):
            with self.subTest(field=field):
                moved = self.resigned(**{field: getattr(self.challenge, field) + 600})
                self.assertCode(
                    C.TIMING_INCONSISTENT, lambda: self.verify_server(moved, at=START + 1)
                )

    def test_a_challenge_from_another_session_is_refused(self):
        other = SessionKeys.generate(OTHER_SESSION_ID)
        theirs = self.issue(at=START + 1, keys=other)
        self.assertCode(C.WRONG_SESSION, lambda: self.verify_server(theirs, at=START + 1))

    def test_checks_run_cheapest_first(self):
        """A malformed payload must never reach an HMAC computation.

        Asserted through the reason code rather than by instrumentation: a struct
        that is both undecodable and unsigned reports MALFORMED, which only the
        first check produces.
        """
        self.assertCode(
            C.MALFORMED,
            lambda: C.verify_authoritative(
                self.challenge.payload + b"\x00",
                session_keys=self.keys,
                session_start=START,
                at=START + 1,
                timing=self.timing,
            ),
        )


class KeySeparationTests(ChallengeCase):
    """Who can do what. The asymmetries here are the reason for two hierarchies."""

    def test_the_public_key_verifies_and_cannot_mint(self):
        """A student's device holds this. It is enough to check, never to produce."""
        impostor = SessionKeys.generate(SESSION_ID)
        self.assertCode(
            C.UNKNOWN_KEY,
            lambda: self.verify_public(self.issue(at=START + 1, keys=impostor), at=START + 1),
        )

    def test_the_signing_key_alone_cannot_produce_a_chain_value(self):
        """Signature valid, derivation wrong: exactly what a leaked key looks like."""
        without_secret = SessionKeys.load(SESSION_ID, bytes(32), self.keys.signing.seed)
        theirs = self.issue(at=START + 1, keys=without_secret)
        self.verify_public(theirs, at=START + 1)
        self.assertCode(C.FORGED, lambda: self.verify_server(theirs, at=START + 1))

    def test_the_root_secret_alone_cannot_sign(self):
        """The mirror case: right challenge value, wrong signing identity."""
        other_signer = SessionKeys.generate(SESSION_ID)
        without_signing = SessionKeys.load(
            SESSION_ID, self.keys.root_secret, other_signer.signing.seed
        )
        theirs = self.issue(at=START + 1, keys=without_signing)
        self.assertEqual(theirs.challenge, self.challenge.challenge)
        self.assertCode(C.UNKNOWN_KEY, lambda: self.verify_server(theirs, at=START + 1))

    def test_a_leaked_epoch_key_does_not_yield_another_epoch(self):
        """What the per-epoch derivation is for, stated as a test.

        A compromised teacher handset, or a chain recovered from a screen recording,
        bounds the damage to the epoch it came from - in both directions.
        """
        n = self.timing.steps_per_epoch
        leaked = self.keys.epoch_key(1)
        for seq in (0, n - 1, 2 * n, 3 * n + 4):
            epoch = C.epoch_of(seq, self.timing)
            with self.subTest(seq=seq, epoch=epoch):
                self.assertNotEqual(
                    C.challenge_value(leaked, SESSION_ID, epoch, seq),
                    C.challenge_value(self.keys.epoch_key(epoch), SESSION_ID, epoch, seq),
                )


class TimingArtifactTests(ChallengeCase):
    """Every number this module decides with comes from a configuration artifact."""

    def artifact(self, **overrides):
        values = dict(config.active().values)
        values.update(overrides)
        return config.Artifact(
            version="test-artifact",
            calibration=config.UNCALIBRATED,
            notes="built by tests_presence_challenge",
            values=MappingProxyType(values),
        )

    def use(self, **overrides):
        config.set_active(self.artifact(**overrides))
        self.addCleanup(config.set_active, None)
        return C.Timing.active()

    def test_timing_reads_the_active_artifact(self):
        active = config.active()
        t = C.Timing.active()
        self.assertEqual(t.step_seconds, active["challenge.step_seconds"])
        self.assertEqual(t.lifetime_seconds, active["challenge.lifetime_seconds"])
        self.assertEqual(t.version, active.version)

    def test_the_version_travels_with_the_parameters(self):
        """So PresenceDecision records what actually produced the verdict."""
        self.assertEqual(self.use().version, "test-artifact")

    def test_a_longer_step_moves_the_boundaries(self):
        t = self.use(**{"challenge.step_seconds": 60, "challenge.lifetime_seconds": 90})
        self.assertEqual(C.step_index(START, START + 59, t), 0)
        self.assertEqual(C.step_index(START, START + 60, t), 1)
        ch = C.issue(self.keys, session_start=START, at=START + 59, timing=t)
        self.assertEqual((ch.issued_at, ch.expires_at), (START, START + 90))

    def test_both_staleness_bounds_are_live(self):
        """The overlap documented in `_check_window`, asserted rather than assumed.

        Under the shipping artifact the expiry is the tighter bound, so STALE_STEP is
        unreachable there. Raise the lifetime past (accept_window_steps + 1) steps and
        the step window becomes the binding one - so neither check is dead code, and
        no future artifact can silently disable one of them.
        """
        t = self.use(**{
            "challenge.step_seconds": 15,
            "challenge.lifetime_seconds": 600,
            "challenge.accept_window_steps": 2,
        })
        ch = C.issue(self.keys, session_start=START, at=START, timing=t)
        C.verify_authoritative(
            ch.payload, session_keys=self.keys, session_start=START,
            at=START + 2 * 15, timing=t,
        )
        with self.assertRaises(C.ChallengeError) as caught:
            C.verify_authoritative(
                ch.payload, session_keys=self.keys, session_start=START,
                at=START + 3 * 15, timing=t,
            )
        self.assertEqual(caught.exception.code, C.STALE_STEP)
        # ... while the challenge is still inside its own declared lifetime there.
        C.verify_public(
            ch.payload, verify_key=self.public, session_id=SESSION_ID,
            at=START + 3 * 15, timing=t,
        )

    def test_the_artifact_out_votes_the_module(self):
        """Crude but load-bearing: changing only the artifact must change behaviour.

        If a step length were ever inlined here, a challenge issued under a
        one-hour artifact would still rotate every fifteen seconds, and this fails.
        """
        t = self.use(**{"challenge.step_seconds": 3600, "challenge.lifetime_seconds": 3600})
        one = C.issue(self.keys, session_start=START, at=START, timing=t)
        two = C.issue(self.keys, session_start=START, at=START + 1800, timing=t)
        self.assertEqual(one.payload, two.payload)
        self.assertEqual(one.seq, 0)


class ReasonCodeTests(SimpleTestCase):
    def test_every_code_is_declared(self):
        """REASON_CODES is what gates.py and the flag types get validated against."""
        for name in dir(C):
            value = getattr(C, name)
            if name.isupper() and isinstance(value, str) and value.startswith("challenge_"):
                self.assertIn(value, C.REASON_CODES, name)
        self.assertEqual(len(C.REASON_CODES), 11)

    def test_an_undeclared_code_cannot_be_raised(self):
        """A typo would otherwise become a reason code nothing recognises."""
        with self.assertRaises(AssertionError):
            raise C.ChallengeError("challenge_typo", "nope")

    def test_describe_carries_no_secret(self):
        keys = SessionKeys.generate(SESSION_ID)
        line = C.describe(C.issue(keys, session_start=START, at=START))
        self.assertIn("step=0", line)
        self.assertNotIn(keys.root_secret.hex(), line)
        self.assertNotIn(keys.signing.seed.hex(), line)
