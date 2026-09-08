"""Tests for the proof submission endpoint.

Every module under `presence/` is tested against its own contract already. What
those tests cannot reach is the boundary: the three things `presence_views` is
responsible for that the protocol package has no way to enforce on its own.

**The clock is the server's.** No field of a request can move `received_at`, which
is what closes the hole the old marking path had, where `marked_at` came straight
out of the request body. `ClockTests` submits a proof whose own account of when it
was captured is an hour stale and asserts the row records both facts separately -
the claim as a claim, the server's time as the time.

**A refusal is not a diagnosis a student reads.** The reason code is stored, and it
is put in front of an administrator on the flag; the response carries an outcome and
at most one plain sentence. `DisclosureTests` serialises whole response bodies and
fails if any reason code from any of the four vocabularies appears in one.

**A retried submission is not a second attempt.** An offline queue whose
acknowledgement was lost resends, and that is the ordinary case. `RetryTests`
asserts a resubmitted proof answers with the verdict already stored, writes no
second row, and cannot turn a stored `present` into the refusal a repeated digest
would otherwise earn.

Two more properties are asserted here because this is where they become observable:
that a refused proof leaves the replay ledger untouched, so the nonce a legitimate
copy needs is still available (`LedgerTests`), and that the server re-derives the
verdict rather than reading the one the handset claimed (`ClaimTests`).
"""
import json
import uuid
from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from . import models, presence_views
from .presence import challenge, config, decide, gates, keys, proof, replay


def b64(raw):
    """Base64 as the wire carries it, since JSON cannot hold bytes."""
    import base64
    return base64.b64encode(bytes(raw)).decode('ascii')


class EndpointFixture(TestCase):
    """A student holding a real signing key, enrolled in a live session.

    Real Ed25519 keys rather than fill bytes, because the whole point of this
    endpoint is that a signature is checked: a fixture whose keys cannot sign would
    test the plumbing and none of the defence.
    """

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('presence_submit_proof')
        self.timing = challenge.Timing.active()

        self.teacher = models.User.objects.create_user(
            username='teacher_one', email='teacher_one@example.com',
            password='x', role='teacher',
        )
        self.student = models.User.objects.create_user(
            username='student_one', email='student_one@example.com',
            password='x', role='student',
        )
        self.klass = models.Class.objects.create(
            class_code='CG101', class_name='Presence', semester='2026-1',
            teacher=self.teacher,
        )
        models.Enrollment.objects.create(class_obj=self.klass, student=self.student)

        # The session's step counter is placed so that `self.seq` is the step the
        # server is in right now. Nothing here depends on when the suite runs, and
        # the request's own clock is the server's, so the challenge has to be live
        # against real time rather than against a frozen instant.
        self.seq = 4
        self.now = int(timezone.now().timestamp())
        self.start = self.now - self.seq * self.timing.step_seconds - 1

        opened = timezone.now() - timedelta(seconds=self.now - self.start)
        self.session = models.AttendanceSession.objects.create(
            class_obj=self.klass, teacher=self.teacher, start_time=opened,
            duration_minutes=50, end_time=opened + timedelta(minutes=50),
            qr_code_data='{}',
        )
        self.keys = keys.SessionKeys.generate(self.session.session_id.bytes)
        self.presence = models.PresenceSession.objects.create(
            session=self.session,
            protocol_version='1',
            config_version=config.active().version,
            root_secret=self.keys.root_secret,
            signing_seed=self.keys.signing.seed,
            signing_key_id=self.keys.public().key_id.hex(),
            chain_start_unix=self.start,
        )
        self.signing = self.enrol_device(self.student, b'endpoint-device')
        self.client.force_authenticate(user=self.student)

    # --- fixture helpers ----------------------------------------------------

    def enrol_device(self, student, label, **over):
        """A real Ed25519 key bound to `student`, and the signer that holds it."""
        signing = keys.SigningKey.from_seed(label.ljust(keys.SEED_LEN, b'.'))
        public = signing.public()
        fields = dict(
            student=student,
            key_id=public.key_id.hex(),
            public_key=public.public_bytes.hex(),
            platform=proof.PLATFORM_ANDROID,
            capabilities=proof.CAP_BIOMETRIC | proof.CAP_HARDWARE_KEYSTORE,
        )
        fields.update(over)
        models.RegisteredDevice.objects.create(**fields)
        return signing

    def at(self, seq=None):
        """One second into step `seq`, on the session's own chain."""
        found = self.seq if seq is None else seq
        return self.start + found * self.timing.step_seconds + 1

    def step_start(self, seq=None):
        found = self.seq if seq is None else seq
        return challenge.step_bounds(self.start, found, self.timing)[0]

    def value_for(self, seq=None, epoch=None):
        found = self.seq if seq is None else seq
        found_epoch = challenge.epoch_of(found, self.timing) if epoch is None else epoch
        return challenge.challenge_value(
            self.keys.epoch_key(found_epoch),
            self.session.session_id.bytes,
            found_epoch,
            found,
        )

    def signed(self, *, seq=None, signer=None, captured_at=None, biometric=None,
               claims=None, nonce=None, value=None, session_id=None,
               observations=()):
        found = self.seq if seq is None else seq
        who = self.signing if signer is None else signer
        built = proof.build(
            session_id=(
                self.session.session_id.bytes if session_id is None else session_id
            ),
            device_key_id=who.public().key_id,
            challenge=self.value_for(found) if value is None else value,
            challenge_epoch=challenge.epoch_of(found, self.timing),
            challenge_seq=found,
            captured_at=self.at(found) if captured_at is None else captured_at,
            biometric=proof.BIOMETRIC_SUCCESS if biometric is None else biometric,
            platform=proof.PLATFORM_ANDROID,
            capabilities=proof.CAP_BIOMETRIC | proof.CAP_HARDWARE_KEYSTORE,
            nonce=nonce,
            claims=claims,
            observations=proof.observation_digests(*observations),
        )
        return proof.sign(built, who)

    def post(self, signed=None, *, signature=None, body=None, observations=None,
             raw=None):
        """One submission, encoded the way a handset encodes it."""
        if raw is not None:
            return self.client.post(self.url, raw, format='json')
        payload = {
            'proof': b64(signed.body if body is None else body),
            'signature': b64(signed.signature if signature is None else signature),
        }
        if observations is not None:
            payload['observations'] = observations
        return self.client.post(self.url, payload, format='json')

    def accept(self, **over):
        """A submission that is expected to succeed, with the response asserted."""
        answer = self.post(self.signed(**over))
        self.assertEqual(answer.status_code, 200, answer.data)
        return answer

    def counts(self):
        """Every durable row this endpoint can write, in one comparable shape."""
        return {
            'proofs': models.AttendanceProof.objects.count(),
            'decisions': models.PresenceDecision.objects.count(),
            'records': models.AttendanceRecord.objects.count(),
            'flags': models.AttendanceFlag.objects.count(),
            'observations': models.PresenceObservation.objects.count(),
            'ledger': models.ReplayEntry.objects.count(),
        }

    def assertNothingRecorded(self, answer=None):
        """Nothing at all, which is the point: a fact about a request writes no row."""
        self.assertEqual(
            self.counts(),
            {'proofs': 0, 'decisions': 0, 'records': 0, 'flags': 0,
             'observations': 0, 'ledger': 0},
            answer.data if answer is not None else None,
        )

    def decision(self):
        return models.PresenceDecision.objects.get()

    def proof_row(self):
        return models.AttendanceProof.objects.get()


class AcceptTests(EndpointFixture):
    """The round trip: a signed proof becomes a mark, and the mark cites the proof."""

    def test_a_signed_proof_is_admitted_and_marks_the_student_present(self):
        answer = self.accept()
        self.assertEqual(answer.data['status'], 'present')
        self.assertEqual(answer.data['attendance'], 'present')
        self.assertIs(answer.data['duplicate'], False)
        self.assertEqual(
            self.counts(),
            {'proofs': 1, 'decisions': 1, 'records': 1, 'flags': 0,
             'observations': 0, 'ledger': 1},
        )
        record = models.AttendanceRecord.objects.get()
        self.assertEqual(record.status, 'present')
        self.assertEqual(record.student_id, self.student.id)
        self.assertEqual(record.session_id, self.session.id)

    def test_the_mark_and_the_proof_and_the_decision_point_at_each_other(self):
        """A verdict nobody can trace back to a body is not evidence of anything."""
        self.accept()
        row, decided = self.proof_row(), self.decision()
        record = models.AttendanceRecord.objects.get()
        self.assertEqual(row.record_id, record.id)
        self.assertEqual(decided.proof_id, row.id)
        self.assertEqual(decided.record_id, record.id)
        self.assertEqual(row.validation_state, 'accepted')
        self.assertEqual(row.device_id, models.RegisteredDevice.objects.get().id)

    def test_the_stored_body_is_the_bytes_the_signature_was_checked_over(self):
        """Not a re-encoding of them. A proof nobody can re-verify is a memory."""
        submitted = self.signed()
        self.assertEqual(self.post(submitted).status_code, 200)
        row = self.proof_row()
        self.assertEqual(bytes(row.proof_bytes), submitted.body)
        self.assertEqual(row.digest, submitted.proof.digest().hex())
        self.assertEqual(row.nonce, submitted.proof.nonce.hex())
        self.assertEqual(row.step, self.seq)
        # Re-verifiable from the row alone, with nothing kept in memory.
        self.assertEqual(
            proof.parse(bytes(row.proof_bytes)).digest(), submitted.proof.digest(),
        )

    def test_no_flag_is_raised_for_a_verdict_nobody_needs_to_look_at(self):
        self.accept()
        self.assertEqual(models.AttendanceFlag.objects.count(), 0)


class HonestyTests(EndpointFixture):
    """What the answer must refuse to claim.

    A confidence that is not a probability is not reported as one, and the
    evidence this build cannot gather is named rather than passed over. Both
    properties are enforced inside `decide`; what is tested here is that the
    boundary carries them out to the client instead of flattening them into a
    number and a word.
    """

    def test_an_uncalibrated_artifact_reports_no_percentage(self):
        answer = self.accept()
        self.assertIsNone(answer.data['confidence_milli'])
        self.assertIs(answer.data['ordering_only'], True)
        self.assertIn('uncalibrated', answer.data['ordering_reason'])
        stored = self.decision()
        self.assertIsNone(stored.confidence_milli)
        self.assertTrue(stored.ordering_only)

    def test_the_answer_names_the_evidence_this_build_cannot_gather(self):
        """Every platform is in degraded mode on this scope, so silence would lie.

        A result screen that showed only what was collected would be claiming a
        completeness the system does not have. The categories are named; the
        mechanics behind them are not, which is the line §45 draws.
        """
        answer = self.accept()
        self.assertEqual(
            sorted(answer.data['evidence_present']),
            ['biometric_outcome', 'challenge_committed', 'clock_consistency',
             'device_bound', 'identity_authenticated'],
        )
        missing = answer.data['evidence_missing']
        self.assertEqual(missing['anchor_fingerprint'], 'reserved')
        self.assertEqual(missing['origin_direct'], 'unsupported')
        self.assertEqual(
            sorted(missing),
            ['anchor_fingerprint', 'origin_direct', 'relay_depth',
             'relay_integrity', 'spatial_stability'],
        )

    def test_the_decision_records_the_parameters_that_produced_it(self):
        """A rollout that re-tunes fusion must not silently re-decide history."""
        self.accept()
        stored = self.decision()
        self.assertEqual(stored.config_version, config.active().version)
        self.assertEqual(stored.calibration, config.UNCALIBRATED)
        self.assertEqual(stored.config_version, self.presence.config_version)
        self.assertEqual(stored.room_profile_version, '')

    def test_the_whole_machine_account_is_kept_verbatim(self):
        self.accept()
        audit = self.decision().audit
        self.assertEqual(audit['status_name'], 'present')
        self.assertEqual(audit['policy']['config_version'], config.active().version)
        self.assertIn('fused', audit)
        self.assertIs(audit['refused'], False)

    def test_no_score_is_written_into_the_old_verification_column(self):
        """Millinats are not the 0..1 vision score analytics already reads."""
        self.accept()
        self.assertIsNone(models.AttendanceRecord.objects.get().verification_score)


class ClaimTests(EndpointFixture):
    """The server re-derives; the handset's own conclusions are only recorded (§39).

    A client that computed its own verdict is not lying by doing so - an offline
    handset has to show the student something. What it must not be able to do is
    have that number counted. The claims are kept because a device whose account
    disagrees with the server's is worth knowing about either way round.
    """

    def claiming(self, status, **over):
        return self.signed(
            claims=proof.Claims(status=status, confidence_milli=1000, hop_count=7),
            **over,
        )

    def test_a_claimed_verdict_does_not_become_the_verdict(self):
        answer = self.post(self.claiming(proof.STATUS_NOT_VERIFIED))
        self.assertEqual(answer.status_code, 200, answer.data)
        # The handset said it had failed. The proof says otherwise, and the proof
        # is the thing that was signed.
        self.assertEqual(answer.data['status'], 'present')
        self.assertEqual(answer.data['attendance'], 'present')

    def test_the_claim_is_stored_beside_the_finding_and_not_as_it(self):
        self.post(self.claiming(proof.STATUS_NOT_VERIFIED))
        row, decided = self.proof_row(), self.decision()
        self.assertEqual(row.claimed_status, proof.STATUS_NOT_VERIFIED)
        self.assertEqual(row.claimed_confidence_milli, 1000)
        self.assertEqual(row.claimed_hop_count, 7)
        self.assertEqual(decided.status, proof.STATUS_PRESENT)
        # The claimed confidence did not become the confidence. Nothing may, while
        # the artifact is uncalibrated.
        self.assertIsNone(decided.confidence_milli)

    def test_a_claimed_hop_count_conjures_no_hops(self):
        """Seven claimed hops, no observation attached, so no relay evidence."""
        self.post(self.claiming(proof.STATUS_PRESENT))
        self.assertEqual(models.PresenceObservation.objects.count(), 0)
        self.assertIn('relay_depth', self.decision().evidence_missing)

    def test_a_claimed_present_cannot_rescue_a_forged_proof(self):
        submitted = self.claiming(proof.STATUS_PRESENT)
        answer = self.post(submitted, signature=bytes(64))
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertIsNone(answer.data['attendance'])
        self.assertEqual(models.AttendanceRecord.objects.count(), 0)


class ClockTests(EndpointFixture):
    """The clock is the server's, and the request cannot reach it.

    This is the hole the old marking path had: `marked_at` came straight out of the
    request body behind a 24-hour window check, so a client could backdate its own
    attendance. Here `captured_at` is still in the request - it has to be, an
    offline handset knows when it scanned - but it is stored as a claim and the
    server's receipt time is taken from the server.
    """

    def setUp(self):
        super().setUp()
        self.bounds = replay.Bounds.active()

    def test_the_receipt_time_and_the_claim_are_two_separate_facts(self):
        stale = self.step_start() - self.bounds.clock_skew_seconds
        answer = self.accept(captured_at=stale)
        self.assertEqual(answer.data['status'], 'present')
        row = self.proof_row()
        self.assertEqual(row.captured_at_claim, stale)
        self.assertGreater(row.received_at, row.captured_at_claim)
        # Within a few seconds of real time, which is the only source it has.
        self.assertLess(abs(row.received_at - int(timezone.now().timestamp())), 30)

    def test_a_backdated_capture_claim_backdates_nothing(self):
        """An hour-stale claim, and the disagreement is what gets noticed."""
        answer = self.accept(captured_at=self.step_start() - 3600)
        row, decided = self.proof_row(), self.decision()
        self.assertEqual(row.captured_at_claim, self.step_start() - 3600)
        self.assertLess(abs(row.received_at - int(timezone.now().timestamp())), 30)
        # A device that cannot account for its own timing does not get a mark for
        # it. The claim is recorded, the contradiction is recorded, and the
        # attendance row is not written.
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertIsNone(answer.data['attendance'])
        self.assertEqual(models.AttendanceRecord.objects.count(), 0)
        self.assertIn(decide.SELF_CONTRADICTION, decided.reasons)
        self.assertIn(
            replay.SIGNAL_CLAIM_PREDATES_CHALLENGE, decided.audit['contradictions'],
        )

    def test_a_capture_claim_from_the_future_is_not_believed_either(self):
        ahead = int(timezone.now().timestamp()) + self.bounds.max_future_skew_seconds
        answer = self.accept(captured_at=ahead + 60)
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertIn(
            replay.SIGNAL_FUTURE_CLAIM, self.decision().audit['contradictions'],
        )

    def test_the_mark_is_timestamped_by_the_database_and_not_the_request(self):
        self.accept(captured_at=self.step_start() - self.bounds.clock_skew_seconds)
        record = models.AttendanceRecord.objects.get()
        self.assertLess(abs((timezone.now() - record.marked_at).total_seconds()), 30)

    def test_the_queued_interval_is_measured_and_not_asserted(self):
        """`queued_seconds` is receipt minus the step, so no claim can move it."""
        self.accept()
        row = self.proof_row()
        self.assertIsNotNone(row.queued_seconds)
        self.assertEqual(row.queued_seconds, row.received_at - self.step_start())


class RetryTests(EndpointFixture):
    """A resubmission is the ordinary case, not a second attempt.

    An offline queue whose acknowledgement was lost resends. Every honest client
    does this, so the endpoint has to answer with the verdict it already reached -
    and in particular must not let the refusal a repeated digest earns overwrite a
    stored `present`.
    """

    def test_a_resubmitted_proof_answers_with_the_stored_verdict(self):
        submitted = self.signed()
        first = self.post(submitted)
        second = self.post(submitted)
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertEqual(second.data['status'], 'present')
        self.assertEqual(second.data['attendance'], 'present')
        self.assertIs(second.data['duplicate'], True)
        self.assertIs(first.data['duplicate'], False)

    def test_a_resubmission_writes_no_second_row(self):
        submitted = self.signed()
        self.post(submitted)
        before = self.counts()
        self.post(submitted)
        self.post(submitted)
        self.assertEqual(self.counts(), before)

    def test_the_answer_is_read_back_from_the_row_and_not_rebuilt(self):
        """The two replies must be the same reply, or one of them is a story."""
        submitted = self.signed()
        first = self.post(submitted).data
        second = self.post(submitted).data
        self.assertEqual(
            {k: v for k, v in first.items() if k != 'duplicate'},
            {k: v for k, v in second.items() if k != 'duplicate'},
        )

    def test_a_duplicate_refusal_does_not_overwrite_a_stored_present(self):
        """The second idempotency door, reached directly.

        Two workers draining one queue can both pass the up-front lookup and meet
        `replay` instead, which has no choice but to refuse a repeated digest. What
        must not happen then is a fresh NOT_VERIFIED landing on top of a `present`
        the first worker already recorded. Called here rather than raced, because a
        race that passes once has not been tested.
        """
        submitted = self.signed()
        self.assertEqual(self.post(submitted).status_code, 200)
        before = self.counts()
        answer = presence_views._answer_refusal(
            gates.GateError(replay.DUPLICATE_PROOF, 'already recorded'),
            self.presence, self.student, submitted.proof, submitted.body,
            submitted.proof.digest().hex(), int(timezone.now().timestamp()),
            decide.Policy.load(self.presence.artifact()),
        )
        self.assertEqual(answer.data['status'], 'present')
        self.assertIs(answer.data['duplicate'], True)
        self.assertEqual(self.counts(), before)
        self.assertEqual(models.AttendanceRecord.objects.get().status, 'present')

    def test_a_second_distinct_proof_updates_the_mark_rather_than_duplicating_it(self):
        """A student who syncs twice from one lesson has one attendance row."""
        self.assertEqual(self.post(self.signed()).status_code, 200)
        self.assertEqual(self.post(self.signed()).status_code, 200)
        self.assertEqual(models.AttendanceProof.objects.count(), 2)
        self.assertEqual(models.PresenceDecision.objects.count(), 2)
        self.assertEqual(models.AttendanceRecord.objects.count(), 1)


class RefusalTests(EndpointFixture):
    """What a refusal is: a verdict, recorded, answered 200.

    A refused proof is a request the server understood. Answering 4xx would tell an
    offline queue to retry a decision that will never come out differently, and
    would make "your attendance was not verified" indistinguishable from "your
    request was malformed" to any client that reads only the status line.
    """

    def test_a_forged_signature_is_suspicious_and_marks_nobody(self):
        answer = self.post(self.signed(), signature=bytes(64))
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertIsNone(answer.data['attendance'])
        self.assertEqual(models.AttendanceRecord.objects.count(), 0)
        row, decided = self.proof_row(), self.decision()
        self.assertEqual(row.validation_state, 'refused')
        self.assertIsNone(row.record_id)
        self.assertIs(decided.refused, True)
        self.assertEqual(decided.gate_code, proof.BAD_SIGNATURE)

    def test_a_refusal_leaves_a_trace_an_administrator_can_act_on(self):
        """Otherwise "nobody tried" and "somebody tried with a forgery" are one state."""
        self.post(self.signed(), signature=bytes(64))
        flag = models.AttendanceFlag.objects.get()
        self.assertEqual(flag.flag_type, 'presence_suspicious')
        self.assertEqual(flag.severity, 'critical')
        self.assertEqual(flag.student_id, self.student.id)
        self.assertEqual(flag.session_id, self.session.id)
        self.assertEqual(flag.evidence['gate_code'], proof.BAD_SIGNATURE)
        # Not a measured anomaly strength. Inventing one would put a fabricated
        # number in the column the integrity engine fills with real ones.
        self.assertEqual(flag.score, 0.0)

    def test_a_proof_from_an_unknown_key_is_recorded_against_the_submitter(self):
        """Not a 403. An unregistered device is a real verdict about a real attempt."""
        stranger = keys.SigningKey.from_seed(b'never-enrolled'.ljust(keys.SEED_LEN, b'.'))
        answer = self.post(self.signed(signer=stranger))
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertEqual(
            answer.data['message'], presence_views.ACTIONABLE[gates.UNKNOWN_DEVICE],
        )
        self.assertNotEqual(
            answer.data['message'], presence_views.GENERIC[decide.SUSPICIOUS],
        )
        row = self.proof_row()
        self.assertEqual(row.student_id, self.student.id)
        self.assertIsNone(row.device_id)
        self.assertEqual(self.decision().gate_code, gates.UNKNOWN_DEVICE)

    def test_a_revoked_device_is_told_to_register_the_current_one(self):
        models.RegisteredDevice.objects.update(is_active=False)
        answer = self.post(self.signed())
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertEqual(self.decision().gate_code, gates.DEVICE_REVOKED)
        self.assertIn('revoked', answer.data['message'])

    def test_a_student_off_the_roster_is_not_verified_rather_than_accused(self):
        models.Enrollment.objects.all().delete()
        answer = self.post(self.signed())
        self.assertEqual(answer.data['status'], 'not_verified')
        self.assertEqual(self.decision().gate_code, gates.DEVICE_NOT_ENROLLED)
        self.assertEqual(models.AttendanceFlag.objects.get().flag_type, 'presence_refused')
        self.assertEqual(models.AttendanceFlag.objects.get().severity, 'warning')

    def test_a_challenge_the_session_has_not_reached_is_a_fabrication(self):
        answer = self.post(self.signed(seq=self.seq + 40))
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertIn(
            self.decision().gate_code,
            (challenge.FUTURE_STEP, replay.STEP_NOT_YET_ISSUED),
        )

    def test_an_invented_challenge_value_does_not_pass_for_one(self):
        answer = self.post(self.signed(value=bytes(challenge.CHALLENGE_LEN)))
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertEqual(self.decision().gate_code, challenge.FORGED)

    def test_two_forged_attempts_at_one_body_are_two_attempts(self):
        """Not one. Collapsing them would make one forgery and fifty look alike.

        This is what the accepted-only uniqueness on `digest` buys: the same bytes
        can be refused repeatedly, each attempt written down, while still only ever
        being admitted once. A plain unique index would have forced the second
        attempt to either overwrite the first or be dropped, and either way the
        count an administrator reads would stop being the number of attempts.
        """
        submitted = self.signed()
        for _ in range(2):
            answer = self.post(submitted, signature=bytes(64))
            self.assertEqual(answer.data['status'], 'suspicious')
        self.assertEqual(models.AttendanceProof.objects.count(), 2)
        self.assertEqual(models.PresenceDecision.objects.count(), 2)
        self.assertEqual(
            list(models.AttendanceProof.objects.values_list('digest', flat=True)),
            [submitted.proof.digest().hex()] * 2,
        )
        # One flag, though: it is the standing state of a student in a session, not
        # a log line, and `_raise_flag` updates the existing row rather than adding.
        self.assertEqual(models.AttendanceFlag.objects.count(), 1)


class LedgerTests(EndpointFixture):
    """A refused proof burns nothing, so the genuine copy still works.

    `replay.admit` is the only writer in `gates.clear` and it runs last, which is
    what makes this possible: replaying one malformed copy of a submission cannot
    consume the nonce the real submission needs. Tested at the boundary as well as
    in `gates`, because the transaction wrapping the view is the other half of the
    guarantee - a crash after the nonce was burnt and before the verdict was written
    would lock a student out of their own attendance for good.
    """

    def test_a_forged_proof_leaves_the_ledger_untouched(self):
        submitted = self.signed()
        self.post(submitted, signature=bytes(64))
        self.assertEqual(models.ReplayEntry.objects.count(), 0)

    def test_the_genuine_copy_of_a_forged_proof_still_succeeds(self):
        """The whole point. Fail closed, but not at a real student's expense."""
        submitted = self.signed()
        self.post(submitted, signature=bytes(64))
        answer = self.post(submitted)
        self.assertEqual(answer.data['status'], 'present')
        self.assertIs(answer.data['duplicate'], False)
        self.assertEqual(models.AttendanceRecord.objects.get().status, 'present')

    def test_an_admitted_proof_burns_its_nonce(self):
        submitted = self.signed()
        self.post(submitted)
        entry = models.ReplayEntry.objects.get()
        self.assertEqual(entry.digest, submitted.proof.digest().hex())
        self.assertEqual(entry.nonce, submitted.proof.nonce.hex())
        self.assertEqual(entry.step, self.seq)
        self.assertEqual(entry.session_id, self.session.session_id.bytes.hex())

    def test_a_reused_nonce_under_a_different_proof_is_refused(self):
        first = self.signed()
        self.post(first)
        answer = self.post(self.signed(nonce=first.proof.nonce, captured_at=self.at() + 2))
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertEqual(self.decision_for(replay.NONCE_REUSED).gate_code,
                         replay.NONCE_REUSED)
        # The first verdict stands and is not disturbed by the second attempt.
        self.assertEqual(models.AttendanceRecord.objects.get().status, 'present')

    def test_every_refusal_before_the_ledger_leaves_it_empty(self):
        """One assertion per door, because "fails closed" should be readable."""
        stranger = keys.SigningKey.from_seed(b'ledger-stranger'.ljust(keys.SEED_LEN, b'.'))
        for label, kwargs, over in (
            ('truncated signature', {}, {'signature': bytes(64)}),
            ('forged challenge', {'value': bytes(challenge.CHALLENGE_LEN)}, {}),
            ('unreached step', {'seq': self.seq + 40}, {}),
            ('unknown device', {'signer': stranger}, {}),
        ):
            with self.subTest(label):
                models.ReplayEntry.objects.all().delete()
                answer = self.post(self.signed(**kwargs), **over)
                self.assertEqual(answer.status_code, 200, answer.data)
                self.assertEqual(models.ReplayEntry.objects.count(), 0, label)

    def decision_for(self, gate_code):
        return models.PresenceDecision.objects.get(gate_code=gate_code)


class AuthorizationTests(EndpointFixture):
    """Facts about a request, answered as facts about the request.

    Every case here is refused before any verdict exists, and the assertion each
    time is that nothing was written. That distinction is the whole class: a proof
    the server declines to rule on must not leave an attendance finding behind,
    because a decision row is a statement about a person and none of these are.
    """

    def test_a_teacher_posting_a_proof_is_refused_and_recorded_nowhere(self):
        """Wrong endpoint for that account, not an attendance outcome."""
        submitted = self.signed()
        self.client.force_authenticate(user=self.teacher)
        answer = self.post(submitted)
        self.assertEqual(answer.status_code, 403)
        self.assertNothingRecorded(answer)

    def test_the_role_check_runs_before_the_body_is_even_read(self):
        """So a teacher's client defect is answered as the authorization it is."""
        self.client.force_authenticate(user=self.teacher)
        answer = self.post(raw={'proof': 'not base64 at all', 'signature': '!!'})
        self.assertEqual(answer.status_code, 403)
        self.assertNothingRecorded(answer)

    def test_another_students_device_cannot_be_submitted_under_this_account(self):
        """And nothing is filed against the owner, who may have done nothing."""
        other = models.User.objects.create_user(
            username='student_two', email='student_two@example.com',
            password='x', role='student',
        )
        models.Enrollment.objects.create(class_obj=self.klass, student=other)
        theirs = self.enrol_device(other, b'endpoint-other-device')
        answer = self.post(self.signed(signer=theirs))
        self.assertEqual(answer.status_code, 403)
        self.assertNothingRecorded(answer)

    def test_an_unauthenticated_submission_is_not_a_verdict(self):
        submitted = self.signed()
        self.client.force_authenticate(user=None)
        answer = self.post(submitted)
        self.assertEqual(answer.status_code, 401)
        self.assertNothingRecorded(answer)

    def test_a_body_that_cannot_be_read_is_a_client_defect_and_not_a_finding(self):
        """Unreadable bytes name no session, so there is nothing to record against."""
        answer = self.post(raw={'proof': b64(b'not a proof'), 'signature': b64(bytes(64))})
        self.assertEqual(answer.status_code, 400)
        self.assertNothingRecorded(answer)

    def test_a_proof_naming_no_session_is_answered_with_no_session(self):
        stranger = uuid.uuid4().bytes
        answer = self.post(self.signed(session_id=stranger))
        self.assertEqual(answer.status_code, 404)
        self.assertNothingRecorded(answer)

    def test_more_observations_than_a_proof_can_commit_to_is_refused(self):
        """The cap is the commitment's own length. Past it, nothing covers them."""
        submitted = self.signed()
        too_many = [b64(bytes(4)) for _ in range(presence_views.MAX_OBSERVATIONS + 1)]
        answer = self.post(submitted, observations=too_many)
        self.assertEqual(answer.status_code, 400)
        self.assertNothingRecorded(answer)

    def test_exactly_the_cap_is_not_refused_for_its_length(self):
        """The boundary from the other side, so the cap is off-by-one proof.

        These digests are not committed to by the proof, so the submission does not
        succeed - but it must fail on the commitment check inside the gates and be
        ruled on, not be turned away by this view for being too long.
        """
        submitted = self.signed()
        answer = self.post(
            submitted, observations=[b64(bytes(4))] * presence_views.MAX_OBSERVATIONS,
        )
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(self.decision().gate_code, gates.OBSERVATION_NOT_COMMITTED)

    def test_observations_must_arrive_as_a_list(self):
        submitted = self.signed()
        for label, value in (('text', 'AAAA'), ('object', {'a': b64(bytes(4))})):
            with self.subTest(label):
                answer = self.post(submitted, observations=value)
                self.assertEqual(answer.status_code, 400)
                self.assertNothingRecorded(answer)

    def test_a_field_that_is_not_base64_is_refused(self):
        for label, payload in (
            ('proof', {'proof': 'not base64!', 'signature': b64(bytes(64))}),
            ('signature', {'proof': b64(bytes(120)), 'signature': 'not base64!'}),
        ):
            with self.subTest(label):
                answer = self.post(raw=payload)
                self.assertEqual(answer.status_code, 400)
                self.assertNothingRecorded(answer)

    def test_both_fields_are_required(self):
        for label, payload in (
            ('no proof', {'signature': b64(bytes(64))}),
            ('no signature', {'proof': b64(bytes(120))}),
            ('neither', {}),
            ('proof is not text', {'proof': 7, 'signature': b64(bytes(64))}),
        ):
            with self.subTest(label):
                answer = self.post(raw=payload)
                self.assertEqual(answer.status_code, 400)
                self.assertNothingRecorded(answer)

    def test_the_observation_cap_is_the_protocols_own_and_not_a_number_here(self):
        """A cap chosen in a view would be a tuned threshold in the wrong place.

        Worth its own assertion because an earlier draft of this endpoint carried
        32 while the wire schema carried 64, which would have quietly refused
        evidence a compliant client had every right to attach.
        """
        self.assertEqual(presence_views.MAX_OBSERVATIONS, proof.MAX_OBSERVATIONS)
        self.assertEqual(presence_views.MAX_OBSERVATIONS, 64)


class DisclosureTests(EndpointFixture):
    """The refusal vocabulary does not travel to the handset.

    A student is owed an outcome and a sentence they can act on. A student is not
    owed the name of the check that failed, because a refusal vocabulary returned to
    whoever is probing it is a map of the checks - submit, read the code, adjust,
    repeat. So the whole battery of answers is serialised here and searched for every
    internal code, rather than each case asserting about its own field and leaving
    the next one free to leak.

    The two halves have to be tested together to mean anything. Withholding is only
    a defence if the code survives somewhere an administrator reads it, and naming
    it on the decision row is only safe if it never reaches the response.
    """

    def forbidden(self):
        """Every internal vocabulary. Refusals, non-fatal signals, drop reasons."""
        return gates.REASON_CODES | gates.SIGNALS | gates.DROP_REASONS

    def battery(self):
        """Every kind of answer this endpoint gives, each yielded with its label."""
        first = self.signed()
        yield 'accepted', self.post(first)
        yield 'duplicate', self.post(first)
        yield 'forged signature', self.post(self.signed(), signature=bytes(64))
        yield 'forged challenge', self.post(
            self.signed(value=bytes(challenge.CHALLENGE_LEN)))
        yield 'unreached step', self.post(self.signed(seq=self.seq + 40))
        stranger = keys.SigningKey.from_seed(
            b'disclosure-stranger'.ljust(keys.SEED_LEN, b'.'))
        yield 'unknown device', self.post(self.signed(signer=stranger))
        yield 'uncommitted observation', self.post(
            self.signed(), observations=[b64(bytes(4))])
        yield 'stale capture claim', self.post(self.signed(captured_at=self.at() - 3600))
        models.RegisteredDevice.objects.filter(student=self.student).update(
            is_active=False)
        yield 'revoked device', self.post(self.signed())
        models.RegisteredDevice.objects.filter(student=self.student).update(
            is_active=True)
        models.Enrollment.objects.all().delete()
        yield 'unenrolled', self.post(self.signed())
        models.Enrollment.objects.create(class_obj=self.klass, student=self.student)

    def test_no_answer_this_endpoint_gives_names_a_check(self):
        forbidden = self.forbidden()
        seen = 0
        for label, answer in self.battery():
            with self.subTest(label):
                self.assertEqual(answer.status_code, 200, answer.data)
                blob = json.dumps(answer.data)
                leaked = sorted(code for code in forbidden if code in blob)
                self.assertEqual(leaked, [], '%s leaked %s' % (label, leaked))
                seen += 1
        # Otherwise a battery that silently stopped yielding would pass.
        self.assertEqual(seen, 10)

    def test_the_canned_sentences_name_no_check_either(self):
        """Including the ones no scenario in the battery happens to produce."""
        forbidden = self.forbidden()
        for message in list(presence_views.ACTIONABLE.values()) + list(
                presence_views.GENERIC.values()):
            with self.subTest(message):
                self.assertEqual(
                    [code for code in forbidden if code in message], [],
                )

    def test_the_two_vocabularies_are_disjoint_so_the_filter_means_something(self):
        """A gate code and a decision reason must never be the same string.

        If they overlapped, withholding one would withhold the other, and the
        explanation a student is owed would disappear along with the map of checks.
        """
        self.assertEqual(decide.REASON_CODES & self.forbidden(), frozenset())

    def test_a_decision_reason_does_reach_the_student(self):
        """So the class above is not testing that the response says nothing at all."""
        answer = self.post(self.signed(captured_at=self.at() - 3600))
        self.assertEqual(answer.data['status'], 'suspicious')
        self.assertIn(decide.SELF_CONTRADICTION, answer.data['reasons'])
        self.assertTrue(set(answer.data['reasons']) <= decide.REASON_CODES)

    def test_a_refusal_withholds_the_reason_list_whole_rather_than_filtering_it(self):
        """The one shape that cannot leak by omission.

        `decide.refuse` puts the gate code in the decision's reasons, so filtering
        that list would mean a refused answer whose reasons are empty for one code
        and populated for another - and the difference is itself the information.
        """
        answer = self.post(self.signed(), signature=bytes(64))
        self.assertEqual(answer.data['reasons'], [])
        stored = self.decision()
        self.assertIs(stored.refused, True)
        self.assertEqual(list(stored.reasons), [proof.BAD_SIGNATURE])

    def test_the_code_is_kept_where_an_administrator_reads_it(self):
        """The other half. Withholding is only defensible if it is not erasure."""
        self.post(self.signed(signer=keys.SigningKey.from_seed(
            b'disclosure-audit'.ljust(keys.SEED_LEN, b'.'))))
        self.assertEqual(self.decision().gate_code, gates.UNKNOWN_DEVICE)
        self.assertEqual(
            models.AttendanceFlag.objects.get().evidence['gate_code'],
            gates.UNKNOWN_DEVICE,
        )
        # The code lives on the decision and on the flag, and not on the proof row,
        # which records only that this submission was refused. One home for the
        # reason means the response cannot disagree with the audit trail.
        self.assertEqual(self.proof_row().validation_state, 'refused')
