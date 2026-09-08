"""Tests for replay defence.

Three claims are being pinned, and each is a place where a correctly signed proof
is still not usable evidence.

**The clock that decides is the server's.** `queue_age` is derived from the step the
challenge belongs to, never from `captured_at`, because a challenge for step *n*
cannot exist before step *n* began - producing its value needs an epoch key the
handset does not hold. `AuthorityTests` moves `captured_at` to absurd values and
asserts that nothing which can reject a proof moves with it.

**A retry and a doctored resubmission are different events.** Byte-identical
resubmission is what a client with an unconfirmed sync does, and it is answered
with `DUPLICATE_PROOF` so the caller can be idempotent. Edit one field and the
digest changes; the nonce catches it as `NONCE_REUSED`, which is not a retry and
must not be answered like one.

**The write is the authority, not the checks that precede it.** `ConcurrencyTests`
submits one proof from several threads at once and asserts exactly one is recorded.
A check-then-write that passed the checks twice would admit both.
"""
import threading

from django.test import SimpleTestCase

from .presence import challenge as challenge_mod
from .presence import codec, config, replay
from .presence.replay import (
    DUPLICATE_PROOF,
    MALFORMED,
    NONCE_REUSED,
    STEP_NOT_YET_ISSUED,
    STEP_REGRESSION,
    TOO_OLD,
    Entry,
    MemoryLedger,
    ReplayError,
)

SESSION_ID = bytes(range(16))
OTHER_SESSION_ID = bytes(range(16, 32))
DEVICE = b"\xd0" * 8
OTHER_DEVICE = b"\xd1" * 8
NONCE = b"\xa0" * 16
OTHER_NONCE = b"\xa1" * 16
START = 1_757_000_000


def proof_values(**overrides):
    """A plausible attendance_proof, so digests come from the real identity function."""
    values = {
        "session_id": SESSION_ID,
        "device_key_id": DEVICE,
        "challenge": b"\xc0" * 8,
        "challenge_epoch": 0,
        "challenge_seq": 1,
        "nonce": NONCE,
        "captured_at": START + 15,
        "biometric": 1,
        "platform": 1,
        "capabilities": 0,
        "claimed_status": 1,
        "claimed_confidence_milli": 900,
        "claimed_hop_count": 0,
        "observations": [],
    }
    values.update(overrides)
    return values


def digest_of(**overrides):
    return codec.digest(codec.ATTENDANCE_PROOF.name, proof_values(**overrides))


class Case(SimpleTestCase):
    def setUp(self):
        self.ledger = MemoryLedger()
        self.bounds = replay.Bounds.active()
        self.timing = challenge_mod.Timing.active()

    def tearDown(self):
        config.set_active(None)

    def step_start(self, step):
        return challenge_mod.step_bounds(START, step, self.timing)[0]

    def admit(self, **overrides):
        kwargs = {
            "digest": digest_of(),
            "session_id": SESSION_ID,
            "device_key_id": DEVICE,
            "nonce": NONCE,
            "step": 1,
            "session_start": START,
            "received_at": self.step_start(1),
        }
        kwargs.update(overrides)
        return replay.admit(self.ledger, **kwargs)

    def refused(self, code, **overrides):
        with self.assertRaises(ReplayError) as caught:
            self.admit(**overrides)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception


class ShapeTests(Case):
    def test_the_nonce_length_comes_from_the_schema(self):
        """Restating it would let the wire format and this check drift apart."""
        field = codec.ATTENDANCE_PROOF.fields[codec.ATTENDANCE_PROOF.index("nonce")]
        self.assertEqual(replay.NONCE_LEN, field.size)

    def test_a_wrong_length_nonce_is_refused(self):
        for wrong in (b"", NONCE[:-1], NONCE + b"\x00"):
            with self.subTest(length=len(wrong)):
                self.refused(MALFORMED, nonce=wrong)

    def test_a_step_must_be_a_non_negative_integer(self):
        """bool included: True would otherwise be admitted as step 1."""
        for bad in (-1, True, 1.5, "1", None):
            with self.subTest(step=repr(bad)):
                self.refused(MALFORMED, step=bad)

    def test_a_proof_must_name_a_session_and_a_device(self):
        self.refused(MALFORMED, session_id=b"")
        self.refused(MALFORMED, device_key_id=b"")

    def test_a_digest_must_be_the_length_the_codec_produces(self):
        """A digest is identity here. Two identities computed differently cannot
        be compared, so a wrong-length one is a caller bug, not a near-miss."""
        self.assertEqual(replay.DIGEST_LEN, len(codec.digest_bytes(b"")))
        for wrong in (b"", bytes(16), digest_of() + bytes(1)):
            with self.subTest(length=len(wrong)):
                self.refused(MALFORMED, digest=wrong)

    def test_a_shape_failure_is_refused_before_anything_is_recorded(self):
        """A malformed proof must not leave a nonce or a high-water mark behind."""
        self.refused(MALFORMED, nonce=b"short")
        self.assertEqual(len(self.ledger), 0)
        self.assertIsNone(self.ledger.highest_step(SESSION_ID, DEVICE))


class AdmissionTests(Case):
    def test_a_first_proof_is_admitted_and_recorded(self):
        receipt = self.admit()
        self.assertEqual(receipt.entry.step, 1)
        self.assertEqual(receipt.queued_seconds, 0)
        self.assertEqual(receipt.signals, ())
        self.assertTrue(self.ledger.seen_digest(digest_of()))
        self.assertTrue(self.ledger.seen_nonce(DEVICE, NONCE))

    def test_the_receipt_names_the_configuration_that_judged_it(self):
        """A verdict has to be explainable with the parameters that produced it."""
        self.assertEqual(self.admit().config_version, config.active().version)

    def test_a_byte_identical_resubmission_is_a_duplicate(self):
        self.admit()
        error = self.refused(DUPLICATE_PROOF)
        self.assertIn("already", str(error).lower())

    def test_one_edited_field_changes_the_digest_and_is_caught_by_the_nonce(self):
        """The case the digest cannot see: same nonce, different bytes."""
        self.admit()
        forged = digest_of(claimed_confidence_milli=1000)
        self.assertNotEqual(forged, digest_of())
        self.refused(NONCE_REUSED, digest=forged)

    def test_a_nonce_is_scoped_to_the_device_that_used_it(self):
        """Two handsets picking the same 16 bytes is chance, not an attack."""
        self.admit()
        self.admit(digest=digest_of(device_key_id=OTHER_DEVICE),
                   device_key_id=OTHER_DEVICE)
        self.assertEqual(len(self.ledger), 2)

    def test_a_nonce_is_not_scoped_to_the_session_and_should_not_be(self):
        """Deliberately wider than the session, and it costs a compliant client nothing.

        A handset picking 16 random bytes per proof does not repeat one across two
        periods; the chance is not worth a sentence. Scoping the ledger per session
        would, though, let a nonce captured in one period be re-spent in the next,
        which is the whole move this defence exists to refuse.
        """
        self.admit()
        self.refused(
            NONCE_REUSED,
            digest=digest_of(session_id=OTHER_SESSION_ID),
            session_id=OTHER_SESSION_ID,
        )

    def test_a_fresh_nonce_from_the_same_device_is_fine(self):
        self.admit()
        self.admit(digest=digest_of(nonce=OTHER_NONCE, challenge_seq=2),
                   nonce=OTHER_NONCE, step=2,
                   received_at=self.step_start(2))
        self.assertEqual(len(self.ledger), 2)


class AuthorityTests(Case):
    """§39, made structural: the client's clock cannot move any bound."""

    def test_queue_age_is_measured_from_the_step_the_challenge_belongs_to(self):
        step = 4
        start = self.step_start(step)
        self.assertEqual(replay.queue_age(START, step, start, self.timing), 0)
        self.assertEqual(replay.queue_age(START, step, start + 90, self.timing), 90)

    def test_queue_age_takes_no_client_field_at_all(self):
        """Its signature is the guarantee: there is nowhere to pass a claim in."""
        import inspect

        parameters = set(inspect.signature(replay.queue_age).parameters)
        self.assertEqual(parameters, {"session_start", "step", "received_at", "timing"})

    def test_a_lying_capture_claim_cannot_extend_the_offline_allowance(self):
        """The proof is too old on the server's clock; a fresh claim must not save it."""
        step = 1
        late = self.step_start(step) + self.bounds.max_offline_seconds + 1
        for claim in (late, late + 10_000, START):
            with self.subTest(captured_at=claim):
                self.refused(TOO_OLD, step=step, received_at=late, captured_at=claim)

    def test_a_lying_capture_claim_cannot_shorten_it_either(self):
        """An old claim on an in-window proof is a signal, never a rejection."""
        step = 1
        received = self.step_start(step) + 60
        receipt = self.admit(step=step, received_at=received, captured_at=START - 99_999)
        self.assertEqual(receipt.queued_seconds, 60)
        self.assertIn(replay.SIGNAL_CLAIM_PREDATES_CHALLENGE, receipt.signals)

    def test_the_recorded_age_does_not_move_with_the_claim(self):
        step = 3
        received = self.step_start(step) + 120
        ages = set()
        for i, claim in enumerate((START, received, received + 10_000)):
            ledger = MemoryLedger()
            receipt = replay.admit(
                ledger,
                digest=digest_of(challenge_seq=step, captured_at=claim),
                session_id=SESSION_ID,
                device_key_id=DEVICE,
                nonce=bytes([i]) + NONCE[1:],
                step=step,
                session_start=START,
                received_at=received,
                captured_at=claim,
            )
            ages.add(receipt.queued_seconds)
        self.assertEqual(ages, {120})


class WindowTests(Case):
    def test_a_proof_from_a_step_that_has_not_started_is_refused(self):
        """It cannot exist: computing its value needs an epoch key the handset lacks."""
        step = 5
        error = self.refused(
            STEP_NOT_YET_ISSUED, step=step, received_at=self.step_start(step) - 1
        )
        self.assertIn("step 5", str(error))

    def test_the_offline_allowance_boundary_is_inclusive(self):
        step = 1
        edge = self.step_start(step) + self.bounds.max_offline_seconds
        self.admit(step=step, received_at=edge)
        self.refused(
            TOO_OLD,
            digest=digest_of(nonce=OTHER_NONCE),
            nonce=OTHER_NONCE,
            step=step,
            received_at=edge + 1,
        )

    def test_the_allowance_is_the_declared_one(self):
        self.assertEqual(
            self.bounds.max_offline_seconds,
            config.get("proof.max_offline_hours") * replay.SECONDS_PER_HOUR,
        )

    def test_an_artifact_change_moves_the_allowance_without_a_code_change(self):
        """The point of the registry: one number in a file, no edit here."""
        step = 1
        received = self.step_start(step) + 3 * replay.SECONDS_PER_HOUR
        config.set_active(config.Artifact(
            version="test-artifact",
            calibration=config.UNCALIBRATED,
            notes="tightened offline allowance",
            values=dict(config.active().values, **{
                "proof.max_offline_hours": 1, "proof.nonce_retention_hours": 2,
            }),
        ))
        self.bounds = replay.Bounds.active()
        self.refused(TOO_OLD, step=step, received_at=received)


class SignalTests(Case):
    """Claims that do not line up are recorded, and reject nothing."""

    def test_a_claim_further_ahead_than_the_skew_allowance_is_a_signal(self):
        step, received = 2, self.step_start(2)
        allowance = self.bounds.max_future_skew_seconds
        self.assertEqual(
            replay.claim_signals(
                captured_at=received + allowance,
                session_start=START, step=step, received_at=received,
            ),
            (),
            "the boundary itself is tolerance, not a signal",
        )
        self.assertEqual(
            replay.claim_signals(
                captured_at=received + allowance + 1,
                session_start=START, step=step, received_at=received,
            ),
            (replay.SIGNAL_FUTURE_CLAIM,),
        )

    def test_a_claim_before_the_challenge_existed_is_a_signal(self):
        step = 4
        step_start = self.step_start(step)
        skew = self.bounds.clock_skew_seconds
        self.assertEqual(
            replay.claim_signals(
                captured_at=step_start - skew,
                session_start=START, step=step, received_at=step_start + 5,
            ),
            (),
        )
        self.assertEqual(
            replay.claim_signals(
                captured_at=step_start - skew - 1,
                session_start=START, step=step, received_at=step_start + 5,
            ),
            (replay.SIGNAL_CLAIM_PREDATES_CHALLENGE,),
        )

    def test_a_claim_can_be_wrong_in_both_directions_at_once(self):
        """Only if the step is far enough ahead of the receipt to allow it."""
        step = 40
        received = self.step_start(step) - 10_000
        signals = replay.claim_signals(
            captured_at=received + self.bounds.max_future_skew_seconds + 1,
            session_start=START, step=step, received_at=received,
        )
        self.assertEqual(len(signals), 2)

    def test_no_signal_ever_rejects(self):
        step, received = 2, self.step_start(2) + 30
        receipt = self.admit(
            step=step, received_at=received, captured_at=received + 100_000
        )
        self.assertEqual(receipt.signals, (replay.SIGNAL_FUTURE_CLAIM,))
        self.assertTrue(self.ledger.seen_digest(receipt.entry.digest))

    def test_omitting_the_claim_produces_no_signals(self):
        """A proof from a platform that does not report a capture time is not suspect."""
        self.assertEqual(self.admit(captured_at=None).signals, ())

    def test_every_signal_is_declared(self):
        self.assertEqual(
            replay.SIGNALS,
            {replay.SIGNAL_FUTURE_CLAIM, replay.SIGNAL_CLAIM_PREDATES_CHALLENGE},
        )
        for signal in replay.SIGNALS:
            with self.subTest(signal=signal):
                self.assertTrue(signal.startswith("signal_"))

    def test_an_undeclared_signal_cannot_reach_a_receipt(self):
        """Fusion weighs these by name; an unknown name would be silently ignored."""
        entry = Entry(digest_of(), SESSION_ID, DEVICE, NONCE, 1, START)
        with self.assertRaises(AssertionError):
            replay.Receipt(entry, 0, ("signal_invented_here",), "v")

    def test_there_is_no_queued_a_long_time_signal(self):
        """Deliberate: every version of it needed a fraction no artifact declares.

        The receipt carries `queued_seconds` as a number instead, so fusion can
        weigh how long a proof sat in a queue without anyone picking a boundary
        for it here.
        """
        self.assertNotIn("long", " ".join(replay.SIGNALS))
        self.assertIsInstance(self.admit().queued_seconds, int)


class StepOrderTests(Case):
    def test_a_strictly_earlier_step_from_the_same_device_is_refused(self):
        """Forward-only per device: a captured older challenge cannot be re-spent."""
        self.admit(digest=digest_of(challenge_seq=5), step=5,
                   received_at=self.step_start(5))
        error = self.refused(
            STEP_REGRESSION,
            digest=digest_of(challenge_seq=4, nonce=OTHER_NONCE),
            nonce=OTHER_NONCE,
            step=4,
            received_at=self.step_start(5) + 1,
        )
        self.assertIn("4", str(error))
        self.assertIn("5", str(error))

    def test_the_same_step_twice_is_not_a_replay_question(self):
        """How many marks a student may have belongs to the record's uniqueness
        constraint. Refusing it here would also refuse a legitimate resubmission
        after a partially failed sync."""
        self.admit()
        receipt = self.admit(
            digest=digest_of(nonce=OTHER_NONCE), nonce=OTHER_NONCE
        )
        self.assertEqual(receipt.entry.step, 1)

    def test_the_high_water_mark_is_per_device(self):
        self.admit(digest=digest_of(challenge_seq=9), step=9,
                   received_at=self.step_start(9))
        self.admit(
            digest=digest_of(device_key_id=OTHER_DEVICE, challenge_seq=2),
            device_key_id=OTHER_DEVICE, step=2,
            received_at=self.step_start(9),
        )
        self.assertEqual(self.ledger.highest_step(SESSION_ID, DEVICE), 9)
        self.assertEqual(self.ledger.highest_step(SESSION_ID, OTHER_DEVICE), 2)

    def test_the_high_water_mark_is_per_session(self):
        """A session is a fresh trust domain; last period's step tells us nothing.

        Unlike the nonce ledger, this one has to reset: step indices restart with
        every session, so carrying a mark across would refuse the first scan of
        every subsequent period.
        """
        self.admit(digest=digest_of(challenge_seq=9), step=9,
                   received_at=self.step_start(9))
        receipt = self.admit(
            digest=digest_of(session_id=OTHER_SESSION_ID, challenge_seq=1,
                             nonce=OTHER_NONCE),
            session_id=OTHER_SESSION_ID, nonce=OTHER_NONCE, step=1,
            received_at=self.step_start(9),
        )
        self.assertEqual(receipt.entry.step, 1)
        self.assertEqual(self.ledger.highest_step(SESSION_ID, DEVICE), 9)


class OrderingTests(Case):
    """The reported reason must be the most useful one, not the first to run."""

    def test_a_duplicate_is_reported_as_a_duplicate_even_when_it_is_also_too_old(self):
        """A client retrying an unconfirmed sync needs to hear 'already have it'."""
        self.admit()
        self.refused(
            DUPLICATE_PROOF,
            received_at=self.step_start(1) + self.bounds.max_offline_seconds + 5,
        )

    def test_nonce_reuse_outranks_step_regression(self):
        self.admit(digest=digest_of(challenge_seq=5), step=5,
                   received_at=self.step_start(5))
        self.refused(
            NONCE_REUSED,
            digest=digest_of(challenge_seq=4),
            step=4,
            received_at=self.step_start(5) + 1,
        )

    def test_shape_outranks_everything(self):
        self.admit()
        self.refused(MALFORMED, nonce=b"short")

    def test_every_reason_code_is_declared_and_namespaced(self):
        self.assertEqual(
            replay.REASON_CODES,
            {DUPLICATE_PROOF, NONCE_REUSED, TOO_OLD, STEP_REGRESSION,
             STEP_NOT_YET_ISSUED, MALFORMED},
        )
        for code in replay.REASON_CODES:
            with self.subTest(code=code):
                self.assertTrue(code.startswith("replay_"))

    def test_an_undeclared_reason_code_cannot_be_raised(self):
        with self.assertRaises(AssertionError):
            raise ReplayError("replay_invented_here", "message")


class LedgerTests(Case):
    def test_an_empty_ledger_knows_nothing(self):
        self.assertFalse(self.ledger.seen_digest(digest_of()))
        self.assertFalse(self.ledger.seen_nonce(DEVICE, NONCE))
        self.assertIsNone(self.ledger.highest_step(SESSION_ID, DEVICE))
        self.assertEqual(len(self.ledger), 0)

    def test_record_is_the_authority_not_the_checks_before_it(self):
        """Called directly, bypassing every read-check, it must still refuse."""
        entry = Entry(digest_of(), SESSION_ID, DEVICE, NONCE, 1, START)
        self.ledger.record(entry)
        with self.assertRaises(ReplayError) as caught:
            self.ledger.record(entry)
        self.assertEqual(caught.exception.code, DUPLICATE_PROOF)

    def test_record_refuses_a_reused_nonce_under_a_new_digest(self):
        self.ledger.record(Entry(digest_of(), SESSION_ID, DEVICE, NONCE, 1, START))
        with self.assertRaises(ReplayError) as caught:
            self.ledger.record(
                Entry(digest_of(biometric=0), SESSION_ID, DEVICE, NONCE, 1, START)
            )
        self.assertEqual(caught.exception.code, NONCE_REUSED)

    def test_pruning_forgets_entries(self):
        self.admit()
        dropped = self.ledger.prune(START + 10_000_000)
        self.assertEqual(dropped, 1)
        self.assertEqual(len(self.ledger), 0)
        self.assertFalse(self.ledger.seen_digest(digest_of()))

    def test_pruning_keeps_the_high_water_marks(self):
        """One small integer per (session, device), and forgetting one would
        re-open the regression it exists to refuse."""
        self.admit(digest=digest_of(challenge_seq=6), step=6,
                   received_at=self.step_start(6))
        self.ledger.prune(START + 10_000_000)
        self.assertEqual(self.ledger.highest_step(SESSION_ID, DEVICE), 6)
        self.refused(
            STEP_REGRESSION,
            digest=digest_of(challenge_seq=5),
            step=5,
            received_at=self.step_start(6) + 1,
        )

    def test_pruning_keeps_entries_inside_the_horizon(self):
        received = self.step_start(1)
        self.admit(received_at=received)
        self.assertEqual(self.ledger.prune(received - 1), 0)
        self.assertEqual(len(self.ledger), 1)

    def test_a_pruned_old_proof_is_still_refused_by_the_layer_behind_it(self):
        """Defence in depth: the nonce is forgotten, the window is not."""
        received = self.step_start(1)
        self.admit(received_at=received)
        self.ledger.prune(received + self.bounds.nonce_retention_seconds + 1)
        self.assertFalse(self.ledger.seen_nonce(DEVICE, NONCE))
        self.refused(
            TOO_OLD,
            received_at=received + self.bounds.nonce_retention_seconds + 1,
        )


class RetentionTests(Case):
    def test_retention_outlasts_the_offline_allowance(self):
        """Forgetting a nonce while a proof carrying it is still acceptable is a
        replay window. The config cross-check is what actually enforces this."""
        self.assertGreater(
            self.bounds.nonce_retention_seconds, self.bounds.max_offline_seconds
        )
        self.assertEqual(config.cross_check(), ())

    def test_the_horizon_is_retention_behind_the_clock(self):
        self.assertEqual(
            replay.retention_horizon(START),
            START - config.get("proof.nonce_retention_hours") * replay.SECONDS_PER_HOUR,
        )

    def test_the_bounds_carry_the_version_that_produced_them(self):
        self.assertEqual(self.bounds.version, config.active().version)

    def test_bounds_are_read_once_per_operation(self):
        """Not per comparison: an artifact swap mid-decision would be incoherent."""
        first = replay.Bounds.active()
        config.set_active(config.Artifact(
            version="test-artifact",
            calibration=config.UNCALIBRATED,
            notes="swapped underneath",
            values=dict(config.active().values, **{"proof.max_offline_hours": 2}),
        ))
        self.assertEqual(first.max_offline_hours, 24)
        self.assertEqual(replay.Bounds.active().max_offline_hours, 2)


class ConcurrencyTests(Case):
    def test_one_proof_submitted_at_once_from_many_threads_is_recorded_once(self):
        """Two proofs arriving together is ordinary, and only the write can settle it."""
        threads, attempts = [], 8
        barrier = threading.Barrier(attempts)
        outcomes = []
        lock = threading.Lock()

        def submit():
            barrier.wait()
            try:
                self.admit()
                result = "admitted"
            except ReplayError as exc:
                result = exc.code
            with lock:
                outcomes.append(result)

        for _ in range(attempts):
            threads.append(threading.Thread(target=submit))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(outcomes.count("admitted"), 1, outcomes)
        self.assertEqual(len(outcomes), attempts)
        self.assertEqual(len(self.ledger), 1)
        for outcome in outcomes:
            if outcome != "admitted":
                self.assertIn(outcome, {DUPLICATE_PROOF, NONCE_REUSED})
