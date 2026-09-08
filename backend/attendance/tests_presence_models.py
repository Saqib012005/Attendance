"""Tests for the presence storage layer and the Django replay ledger.

Two things are worth testing here and one of them is easy to skip. The first is
that the constraints actually constrain - a unique index that was declared but
never exercised is a comment. The second, and the reason this file is longer than
the models deserve, is *parity*: `DjangoLedger` and `replay.MemoryLedger` are two
implementations of the same defence, one used in tests and the lab and one used in
production, and any behavioural gap between them is a gap that will only ever show
up in production. So most assertions run the same sequence through both and demand
the same answer, including the same refusal code.
"""
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from . import models
from .presence import challenge, codec, config, keys, proof, replay
from .presence_ledger import DjangoLedger


def _bytes(n, fill):
    return bytes([fill]) * n


class PresenceFixture(TestCase):
    """A teacher, a student, a class, a session and its presence half."""

    def setUp(self):
        # Distinctive names, not 't' and 's': one test asserts that no identifier
        # reaches the durable audit snapshot, and a one-character username occurs
        # by accident in every other word, so the search would always "find" it and
        # the assertion would mean nothing.
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
        start = timezone.now()
        self.session = models.AttendanceSession.objects.create(
            class_obj=self.klass, teacher=self.teacher, start_time=start,
            duration_minutes=50, end_time=start + timedelta(minutes=50),
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
            chain_start_unix=int(start.timestamp()),
        )
        self.device = self.register(self.student, fill=0x11)

    def register(self, student, fill, **over):
        public = _bytes(keys.PUBLIC_KEY_LEN, fill)
        fields = dict(
            student=student,
            key_id=keys.key_id_for(public).hex(),
            public_key=public.hex(),
            platform=1,
            capabilities=proof.CAP_BIOMETRIC | proof.CAP_HARDWARE_KEYSTORE,
        )
        fields.update(over)
        return models.RegisteredDevice.objects.create(**fields)

    def entry(self, *, digest=0xA0, nonce=0xB0, step=4, received_at=1000, device=None):
        """A ledger entry, with every byte string derived from one small integer.

        Fixtures that spell out 32-byte literals are unreadable and, worse,
        invite two 'different' digests that differ in a byte nobody notices.
        """
        return replay.Entry(
            digest=_bytes(replay.DIGEST_LEN, digest),
            session_id=self.session.session_id.bytes,
            device_key_id=bytes.fromhex((device or self.device).key_id),
            nonce=_bytes(proof.NONCE_LEN, nonce),
            step=step,
            received_at=received_at,
        )

    def ledgers(self):
        """Both implementations, so a claim can be made about the defence itself."""
        return (('django', DjangoLedger()), ('memory', replay.MemoryLedger()))


class LedgerParityTests(PresenceFixture):
    """The Django ledger and the in-memory one must be the same defence."""

    def test_a_fresh_ledger_remembers_nothing(self):
        for name, ledger in self.ledgers():
            e = self.entry()
            self.assertIsNone(ledger.seen_digest(e.digest), name)
            self.assertIsNone(ledger.seen_nonce(e.device_key_id, e.nonce), name)
            self.assertIsNone(ledger.highest_step(e.session_id, e.device_key_id), name)

    def test_a_recorded_proof_is_found_by_digest_and_by_nonce(self):
        for name, ledger in self.ledgers():
            e = self.entry()
            ledger.record(e)
            self.assertEqual(ledger.seen_digest(e.digest), e, name)
            self.assertEqual(ledger.seen_nonce(e.device_key_id, e.nonce), e, name)
            self.assertEqual(ledger.highest_step(e.session_id, e.device_key_id), e.step, name)

    def test_the_same_proof_twice_is_refused_as_a_duplicate(self):
        for name, ledger in self.ledgers():
            e = self.entry()
            ledger.record(e)
            with self.assertRaises(replay.ReplayError) as caught:
                ledger.record(e)
            self.assertEqual(caught.exception.code, replay.DUPLICATE_PROOF, name)

    def test_a_reused_nonce_is_refused_even_under_a_different_digest(self):
        """The digest changes with any edit to the proof, so digest alone is not
        enough: an attacker who re-signs a modified copy gets a new digest for
        free. The nonce is what says 'this device already spoke once'."""
        for name, ledger in self.ledgers():
            ledger.record(self.entry(digest=0xA0))
            with self.assertRaises(replay.ReplayError) as caught:
                ledger.record(self.entry(digest=0xA1))
            self.assertEqual(caught.exception.code, replay.NONCE_REUSED, name)

    def test_two_devices_may_use_the_same_nonce(self):
        """Nonce uniqueness is per device. Making it global would let one student's
        submission refuse another's on a collision they had no part in."""
        other = self.register(self.student, fill=0x22, is_active=False)
        for name, ledger in self.ledgers():
            ledger.record(self.entry(digest=0xA0))
            ledger.record(self.entry(digest=0xA1, device=other))
            self.assertEqual(len(ledger), 2, name)

    def test_the_high_water_mark_only_ever_moves_forward(self):
        for name, ledger in self.ledgers():
            ledger.record(self.entry(digest=0xA0, nonce=0xB0, step=9))
            ledger.record(self.entry(digest=0xA1, nonce=0xB1, step=3))
            key = (self.session.session_id.bytes, bytes.fromhex(self.device.key_id))
            self.assertEqual(ledger.highest_step(*key), 9, name)

    def test_pruning_forgets_entries_but_not_how_far_a_device_got(self):
        """The divergence this table was added to prevent.

        If the high-water mark were derived from the entries, pruning would forget
        it and a replayed older step would look new again - the housekeeping
        undoing the defence. Both ledgers must keep the mark past a prune.
        """
        for name, ledger in self.ledgers():
            e = self.entry(step=7, received_at=100)
            ledger.record(e)
            self.assertEqual(ledger.prune(before=200), 1, name)
            self.assertIsNone(ledger.seen_digest(e.digest), name)
            self.assertEqual(ledger.highest_step(e.session_id, e.device_key_id), 7, name)

    def test_pruning_spares_entries_newer_than_the_horizon(self):
        for name, ledger in self.ledgers():
            ledger.record(self.entry(digest=0xA0, nonce=0xB0, received_at=100))
            ledger.record(self.entry(digest=0xA1, nonce=0xB1, received_at=300))
            self.assertEqual(ledger.prune(before=200), 1, name)
            self.assertEqual(len(ledger), 1, name)

    def test_a_refused_record_leaves_the_connection_usable(self):
        """Specific to the Django side, and the reason `record` nests an atomic.

        A constraint violation marks the surrounding transaction unusable, so
        without the nested block the two lookups that explain *which* rule was
        broken would themselves raise, and the caller would get a database error
        where a reason code belongs.
        """
        ledger = DjangoLedger()
        ledger.record(self.entry())
        with self.assertRaises(replay.ReplayError):
            ledger.record(self.entry())
        # The query that proves the connection survived.
        self.assertEqual(models.ReplayEntry.objects.count(), 1)

    def test_the_two_ledgers_agree_on_every_step_of_one_sequence(self):
        """A single ordered run, compared move for move rather than case by case."""
        script = [(0xA0, 0xB0, 5), (0xA1, 0xB1, 2), (0xA2, 0xB2, 8)]
        seen = {}
        for name, ledger in self.ledgers():
            trace = []
            for digest, nonce, step in script:
                ledger.record(self.entry(digest=digest, nonce=nonce, step=step))
                trace.append((
                    len(ledger),
                    ledger.highest_step(
                        self.session.session_id.bytes,
                        bytes.fromhex(self.device.key_id),
                    ),
                ))
            seen[name] = trace
        self.assertEqual(seen['django'], seen['memory'])


class ConstraintTests(PresenceFixture):
    """Declared constraints, exercised. An unindexed claim is not a constraint."""

    def test_only_one_device_may_be_active_per_student(self):
        """Two live devices would restore the attack device binding exists to close:
        one handset in the room, one in a pocket somewhere else, both signing."""
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                self.register(self.student, fill=0x33)

    def test_a_revoked_device_does_not_block_its_replacement(self):
        """A student who breaks a phone must be able to register the next one."""
        self.device.is_active = False
        self.device.revoked_at = timezone.now()
        self.device.save(update_fields=['is_active', 'revoked_at'])
        replacement = self.register(self.student, fill=0x44)
        self.assertTrue(replacement.is_active)
        self.assertEqual(self.student.presence_devices.count(), 2)

    def test_a_revoked_device_is_kept_rather_than_deleted(self):
        self.device.is_active = False
        self.device.revocation_reason = 'handset lost'
        self.device.save(update_fields=['is_active', 'revocation_reason'])
        kept = models.RegisteredDevice.objects.get(pk=self.device.pk)
        self.assertEqual(kept.revocation_reason, 'handset lost')

    def test_two_students_may_not_share_one_public_key(self):
        other = models.User.objects.create_user(
            username='student_two', email='student_two@example.com',
            password='x', role='student',
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                self.register(other, fill=0x11)

    def test_only_one_config_version_may_be_active(self):
        models.ConfigVersion.objects.create(
            version='a', digest='0' * 64, calibration=config.UNCALIBRATED, is_active=True,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                models.ConfigVersion.objects.create(
                    version='b', digest='1' * 64,
                    calibration=config.UNCALIBRATED, is_active=True,
                )

    def test_only_one_room_profile_may_be_active_per_room(self):
        room = models.Room.objects.create(code='B-101')
        models.RoomProfile.objects.create(
            room=room, calibration_version='v1', is_active=True,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                models.RoomProfile.objects.create(
                    room=room, calibration_version='v2', is_active=True,
                )


class NamespaceTests(TestCase):
    """The table names are a contract with a database that already exists.

    This repo's history holds an abandoned migration lineage whose tables
    `registered_devices`, `attendance_verifications` and `attendance_audit_events`
    survive in at least one developer database with no model on this branch. A new
    model reusing one of those names migrates cleanly everywhere except that
    machine, where it fails with "table already exists" - a bug that reproduces for
    exactly one person.

    The expected names are spelled out rather than derived. Restating them is the
    test: a rename that was fine in the abstract has to be looked at again here,
    against the names the orphans occupy.
    """
    EXPECTED = {
        'Room': 'presence_rooms',
        'RoomProfile': 'presence_room_profiles',
        'Anchor': 'presence_anchors',
        'RegisteredDevice': 'presence_registered_devices',
        'PresenceSession': 'presence_sessions',
        'SessionEpoch': 'presence_session_epochs',
        'PresenceObservation': 'presence_observations',
        'ReplayEntry': 'presence_replay_entries',
        'StepHighWater': 'presence_step_high_water',
        'AttendanceProof': 'presence_proofs',
        'RelayChainRecord': 'presence_relay_chains',
        'PresenceDecision': 'presence_decisions',
        'ManualOverride': 'presence_manual_overrides',
        'ConfigVersion': 'presence_config_versions',
    }
    ORPHANED = {
        'registered_devices', 'attendance_verifications', 'attendance_audit_events',
    }

    def test_every_presence_model_uses_its_namespaced_table(self):
        for name, table in self.EXPECTED.items():
            model = getattr(models, name)
            self.assertEqual(model._meta.db_table, table, name)

    def test_no_model_in_the_app_reclaims_an_orphaned_table_name(self):
        from django.apps import apps
        used = {m._meta.db_table for m in apps.get_app_config('attendance').get_models()}
        self.assertEqual(used & self.ORPHANED, set())

    def test_the_presence_tables_are_exactly_the_ones_declared_here(self):
        """Catches a new presence model added without a prefix, or without a test."""
        from django.apps import apps
        prefixed = {
            m._meta.db_table
            for m in apps.get_app_config('attendance').get_models()
            if m._meta.db_table.startswith('presence_')
        }
        self.assertEqual(prefixed, set(self.EXPECTED.values()))


class VocabularyTests(TestCase):
    """Database choices are read from the protocol package, not restated.

    A status integer means the same thing in a signed proof, in a decision row and
    in an API response. If the model spelled its own list, the three could drift
    apart by someone editing one of them, and the drift would show up as a proof
    that decodes to `suspicious` being stored as `present`.
    """

    def test_the_status_choices_come_from_the_wire_vocabulary(self):
        self.assertEqual(
            dict(models.PRESENCE_STATUS_CHOICES).keys(), proof.STATUS_NAMES.keys(),
        )

    def test_the_platform_choices_come_from_the_wire_vocabulary(self):
        self.assertEqual(
            dict(models.PLATFORM_CHOICES).keys(), proof.PLATFORM_NAMES.keys(),
        )

    def test_the_biometric_choices_come_from_the_wire_vocabulary(self):
        self.assertEqual(
            dict(models.BIOMETRIC_CHOICES).keys(), proof.BIOMETRIC_NAMES.keys(),
        )

    def test_the_calibration_choices_come_from_the_config_layer(self):
        """So no row can claim a calibration state the loader has never heard of -
        'field validated', in particular, which is a claim about evidence."""
        self.assertEqual(
            {value for value, _ in models.CALIBRATION_CHOICES},
            set(config.CALIBRATION_STATES),
        )

    def test_every_status_a_decision_can_carry_is_a_storable_choice(self):
        from .presence import decide
        routed = {decide.PRESENT, decide.SECONDARY, decide.NOT_VERIFIED, decide.SUSPICIOUS}
        storable = dict(models.PRESENCE_STATUS_CHOICES)
        for status in routed:
            self.assertIn(status, storable, proof.STATUS_NAMES.get(status))

    def test_the_presence_flag_types_fit_the_column_and_are_registered(self):
        declared = dict(models.AttendanceFlag.FLAG_TYPE_CHOICES)
        presence = {k for k in declared if k.startswith('presence_')}
        self.assertEqual(len(presence), 4)
        width = models.AttendanceFlag._meta.get_field('flag_type').max_length
        for key in presence:
            self.assertLessEqual(len(key), width, key)

    def test_no_protocol_refusal_code_leaks_into_a_teacher_facing_flag_label(self):
        """Flag types name what happened to the student. The refusal codes name how
        the detection works, and they belong in `evidence` where an admin reads
        them - a label that taught the mechanic would teach the way around it."""
        from .presence import gates
        declared = {k for k, _ in models.AttendanceFlag.FLAG_TYPE_CHOICES}
        self.assertEqual(declared & set(gates.REASON_CODES), set())
        self.assertEqual(declared & set(replay.REASON_CODES), set())


class SecretTests(PresenceFixture):
    """The two secrets in `presence_sessions`, and the places they must not reach."""

    def reloaded(self):
        """The row as a second process would see it - fetched, not the one in hand."""
        return models.PresenceSession.objects.get(pk=self.presence.pk)

    def test_a_session_key_survives_the_round_trip_through_the_database(self):
        """The property the entire offline path rests on.

        A challenge is verified by re-deriving its MAC from the epoch key, so a
        secret that came back from storage as anything other than the bytes that
        went in - a memoryview, a truncated blob, a re-encoded string - would fail
        every proof from every handset, for a reason no reason code describes.
        """
        restored = self.reloaded().session_keys()
        for epoch in (0, 1, 7):
            self.assertEqual(restored.epoch_key(epoch), self.keys.epoch_key(epoch), epoch)
        self.assertEqual(restored.public().key_id, self.keys.public().key_id)

    def test_a_challenge_issued_before_the_round_trip_verifies_after_it(self):
        """The same claim end to end: issued from memory, authorised from the row.

        `verify_authoritative` is the path that re-derives rather than trusting, so
        this is the one assertion that covers the stored secret, the stored seed and
        the stored chain start together.
        """
        start = self.presence.chain_start_unix
        issued = challenge.issue(self.keys, session_start=start, at=start + 5)
        parsed = challenge.verify_authoritative(
            issued.payload,
            session_keys=self.reloaded().session_keys(),
            session_start=start,
            at=start + 5,
        )
        self.assertEqual(parsed.challenge, issued.challenge)
        self.assertEqual(parsed.seq, issued.seq)

    def test_the_stored_signing_key_id_matches_the_stored_seed(self):
        """Two columns describing one key, so they can disagree. They must not.

        `signing_key_id` is what a client looks the verifying key up by; the seed is
        what the server signs with. A mismatch would produce signatures nobody can
        check, and the sessions would look healthy until the first scan.
        """
        self.assertEqual(
            self.presence.signing_key_id,
            self.reloaded().session_keys().public().key_id.hex(),
        )


class StoredFixture(PresenceFixture):
    """A proof, a decision about it, and the observations it was built from.

    The decision is produced by the real `decide.decide` over the real fusion of a
    real vector, not hand-written, because a hand-written decision would agree with
    whatever the storage layer happened to do with it.
    """

    def observation(self, kind='origin', **over):
        fields = dict(
            presence_session=self.presence,
            student=self.student,
            device=self.device,
            kind=kind,
            step=4,
            observed_at_claim=self.presence.chain_start_unix + 20,
            # No signal strength and no identifier: an observation payload is
            # purged on session close, and what survives must not need purging.
            payload={'note': 'a sighting'},
        )
        fields.update(over)
        return models.PresenceObservation.objects.create(**fields)

    def stored_proof(self, **over):
        fields = dict(
            presence_session=self.presence,
            student=self.student,
            device=self.device,
            digest=_bytes(replay.DIGEST_LEN, 0xA0).hex(),
            nonce=_bytes(proof.NONCE_LEN, 0xB0).hex(),
            step=4,
            proof_bytes=b'signed-bytes-stand-in',
            biometric=proof.BIOMETRIC_SUCCESS,
            platform=proof.PLATFORM_ANDROID,
            capabilities=proof.CAP_BIOMETRIC | proof.CAP_HARDWARE_KEYSTORE,
            captured_at_claim=self.presence.chain_start_unix + 20,
            received_at=self.presence.chain_start_unix + 25,
        )
        fields.update(over)
        return models.AttendanceProof.objects.create(**fields)

    def reached(self):
        """What the server would decide, through the production code path."""
        from .presence import decide, fusion
        from .tests_presence_fusion import assemble
        return decide.decide(fusion.fuse(assemble()), biometric=proof.BIOMETRIC_SUCCESS)

    def stored_decision(self, **over):
        return models.PresenceDecision.from_decision(
            self.reached(), proof_row=self.stored_proof(**over),
        )


class LifecycleTests(StoredFixture):
    """Session close and the purge it triggers (privacy requirement: no permanent
    RF record of where a student sat, and no monitoring outside a live session)."""

    def test_purging_deletes_the_observations_and_records_that_it_happened(self):
        self.observation()
        self.observation(kind='anchor')
        self.assertEqual(self.presence.purge_observations(), 2)
        self.assertEqual(self.presence.observations.count(), 0)
        self.assertIsNotNone(self.presence.observations_purged_at)

    def test_closing_sets_closed_at_and_purges_in_one_call(self):
        """The two halves of closing are one guarantee, not two.

        `closed_at` is what the session-open gate reads. A session that purged its
        observations but never recorded a close would leave that gate inert, and one
        that closed without purging would keep the radio rows past the lesson.
        """
        self.observation()
        self.assertIsNone(self.presence.closed_at)
        self.assertEqual(self.presence.close(), 1)
        reloaded = models.PresenceSession.objects.get(pk=self.presence.pk)
        self.assertIsNotNone(reloaded.closed_at)
        self.assertIsNotNone(reloaded.observations_purged_at)
        self.assertEqual(reloaded.observations.count(), 0)

    def test_closing_twice_does_not_move_the_close_time(self):
        """Idempotent, because more than one path may end a session.

        If a second call re-stamped `closed_at`, a session ended once and synced
        again later would appear to have stayed open until the sync - and every
        proof in between would pass a gate that should have refused it.
        """
        self.presence.close()
        first = models.PresenceSession.objects.get(pk=self.presence.pk).closed_at
        self.observation()
        self.assertEqual(self.presence.close(), 1)
        again = models.PresenceSession.objects.get(pk=self.presence.pk)
        self.assertEqual(again.closed_at, first)
        self.assertEqual(again.observations.count(), 0)

    def test_purging_is_recorded_on_the_row_and_not_only_in_memory(self):
        """So a second worker can tell a purged session from one never purged.

        Without the write, a restarted process would see a session with no
        observations and no way to know whether that was housekeeping or a session
        during which nothing was ever seen.
        """
        self.observation()
        self.presence.purge_observations()
        reloaded = models.PresenceSession.objects.get(pk=self.presence.pk)
        self.assertIsNotNone(reloaded.observations_purged_at)

    def test_purging_keeps_the_decision_the_observations_produced(self):
        """The line the retention rule draws.

        Raw evidence is transient; the verdict and its audit snapshot are the
        student's attendance record and are kept. If a purge took the decision with
        it, closing a session would erase the attendance it had just established.
        """
        self.observation()
        decision = self.stored_decision()
        self.presence.purge_observations()
        kept = models.PresenceDecision.objects.get(pk=decision.pk)
        self.assertEqual(kept.status, decision.status)
        self.assertEqual(models.AttendanceProof.objects.count(), 1)

    def test_purging_an_untouched_session_is_not_an_error(self):
        """Close runs on every session, including ones nobody scanned."""
        self.assertEqual(self.presence.purge_observations(), 0)

    def test_a_purge_does_not_reach_another_session(self):
        other_start = self.session.start_time + timedelta(hours=2)
        other_session = models.AttendanceSession.objects.create(
            class_obj=self.klass, teacher=self.teacher, start_time=other_start,
            duration_minutes=50, end_time=other_start + timedelta(minutes=50),
            qr_code_data='{}',
        )
        other_keys = keys.SessionKeys.generate(other_session.session_id.bytes)
        other = models.PresenceSession.objects.create(
            session=other_session, protocol_version='1',
            config_version=config.active().version,
            root_secret=other_keys.root_secret, signing_seed=other_keys.signing.seed,
            signing_key_id=other_keys.public().key_id.hex(),
            chain_start_unix=int(other_start.timestamp()),
        )
        self.observation()
        self.observation(presence_session=other)
        self.assertEqual(other.purge_observations(), 1)
        self.assertEqual(self.presence.observations.count(), 1)


class AuditTests(StoredFixture):
    """What a decision row promises: that its columns and its snapshot agree, that
    the snapshot names nothing about the student, and that an override adds to the
    record rather than replacing it."""

    # Column name -> snapshot key. Restated rather than derived, because the point
    # of the test is that a column added without a snapshot key, or renamed on one
    # side only, has to be looked at here.
    MIRRORED = (
        'status', 'millinats', 'coverage_pct', 'supplied_pct', 'confidence_milli',
        'ordering_only', 'refused', 'calibration', 'config_version',
    )

    def test_a_stored_decision_is_a_faithful_index_into_its_snapshot(self):
        """The columns exist to order a review queue without opening the JSON.

        Which makes them a copy, and a copy can be wrong. A row whose `status`
        column disagreed with its snapshot would show a teacher one verdict and an
        auditor another, and both would be citing the same decision.
        """
        row = self.stored_decision()
        for key in self.MIRRORED:
            self.assertEqual(getattr(row, key), row.audit[key], key)
        self.assertEqual(row.reasons, row.audit['reasons'])
        self.assertEqual(row.evidence_present, row.audit['evidence_present'])
        self.assertEqual(row.evidence_missing, row.audit['evidence_missing'])
        self.assertEqual(row.gate_code, row.audit['gate_code'] or '')
        self.assertEqual(row.ordering_reason, row.audit['ordering_reason'] or '')

    def test_the_stored_snapshot_names_nothing_about_the_student(self):
        """`audit` is durable and a teacher reads it, so it holds what was weighed
        and not who was weighed - no identifier, no nonce, no digest, no signal
        strength. Storing it would build the permanent record this design refuses."""
        import json
        row = self.stored_decision()
        text = json.dumps(row.audit)
        for secret in (row.proof.nonce, row.proof.digest, self.device.key_id,
                       self.student.username, self.student.email):
            self.assertNotIn(secret, text, secret)

    def test_a_decision_records_the_versions_that_produced_it(self):
        """A decision from last term has to be re-arguable under the parameters that
        were in force then, which means the row must say which those were."""
        row = self.stored_decision()
        self.assertEqual(row.config_version, config.active().version)
        self.assertEqual(row.codec_version, codec.CODEC_VERSION)
        self.assertIn(row.calibration, config.CALIBRATION_STATES)

    def test_an_override_keeps_the_original_decision_and_names_who_changed_it(self):
        """A teacher may correct a verdict; nobody may erase the one the machine
        reached. Both readings have to survive, because an override is evidence
        about the system as much as about the student."""
        row = self.stored_decision()
        override = models.ManualOverride.objects.create(
            decision=row, actor=self.teacher,
            original_status=row.status, new_status=proof.STATUS_PRESENT,
            reason='student was in the room; handset battery died mid-session',
            original_decision=row.audit,
        )
        self.assertEqual(override.original_status, row.status)
        self.assertEqual(override.original_decision, row.audit)
        self.assertEqual(override.actor, self.teacher)
        self.assertIsNotNone(override.created_at)

    def test_an_override_will_not_save_without_a_reason(self):
        """An unexplained override is indistinguishable from an unexplained change of
        the attendance record, which is the thing this table exists to rule out."""
        from django.core.exceptions import ValidationError
        row = self.stored_decision()
        blank = models.ManualOverride(
            decision=row, actor=self.teacher, original_status=row.status,
            new_status=proof.STATUS_PRESENT, reason='', original_decision=row.audit,
        )
        with self.assertRaises(ValidationError) as caught:
            blank.full_clean()
        self.assertIn('reason', caught.exception.message_dict)

    def test_an_override_does_not_edit_the_decision_it_overrides(self):
        row = self.stored_decision()
        before = dict(row.audit)
        models.ManualOverride.objects.create(
            decision=row, actor=self.teacher, original_status=row.status,
            new_status=proof.STATUS_SUSPICIOUS, reason='marked in error',
            original_decision=row.audit,
        )
        after = models.PresenceDecision.objects.get(pk=row.pk)
        self.assertEqual(after.status, row.status)
        self.assertEqual(after.audit, before)

    def test_the_actor_of_an_override_cannot_be_deleted_out_from_under_it(self):
        """Deleting the teacher would leave an anonymous change to a student's
        attendance record, so the account is protected while the override stands."""
        from django.db.models import ProtectedError
        row = self.stored_decision()
        models.ManualOverride.objects.create(
            decision=row, actor=self.teacher, original_status=row.status,
            new_status=proof.STATUS_PRESENT, reason='confirmed by roll call',
            original_decision=row.audit,
        )
        with self.assertRaises(ProtectedError):
            self.teacher.delete()


class CapabilityTests(PresenceFixture):
    """`capability_names` reads the protocol bit definitions, so a capability
    defined there becomes visible here without a second list to maintain."""

    def test_the_names_are_read_from_the_protocol_bits(self):
        names = self.device.capability_names
        self.assertEqual(names, sorted(['biometric', 'hardware_keystore']))

    def test_every_declared_bit_has_a_name(self):
        """A device that reported everything must not silently drop a capability
        whose bit was added to the protocol and nowhere else."""
        every = 0
        for name in dir(proof):
            if name.startswith('CAP_'):
                every |= getattr(proof, name)
        device = self.register(self.student, fill=0x55, is_active=False,
                               capabilities=every)
        expected = sorted(
            name[len('CAP_'):].lower() for name in dir(proof) if name.startswith('CAP_')
        )
        self.assertEqual(device.capability_names, expected)

    def test_a_device_that_declares_nothing_names_nothing(self):
        """The degraded platforms this scope ships on. An empty list is the honest
        answer; it must not read as a device that failed a check."""
        device = self.register(self.student, fill=0x66, is_active=False, capabilities=0)
        self.assertEqual(device.capability_names, [])

    def test_a_public_key_round_trips_as_bytes(self):
        self.assertEqual(
            self.device.public_key_bytes(), _bytes(keys.PUBLIC_KEY_LEN, 0x11),
        )
        self.assertEqual(
            keys.key_id_for(self.device.public_key_bytes()).hex(), self.device.key_id,
        )
