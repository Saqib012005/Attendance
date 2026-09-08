"""Tests for the wiring, as distinct from the protocol.

Every module under `presence/` was tested in isolation long before anything called
it, which is the right order to build in and the wrong order to stop in: a layer can
be entirely correct and entirely unreachable. Three properties this suite exists to
hold, each of which was untrue at some point in this build:

1. **Creating a session opens the presence layer for it.** Without that call every
   proof answers 404 and attendance falls back to the unsigned payload.
2. **A proof is judged by the artifact its session pinned**, not by the artifact
   deployed when it happened to sync. Otherwise re-tuning a threshold silently
   re-decides history, and `PresenceDecision.config_version` names an artifact that
   did not produce the verdict.
3. **The teacher's screen can get a challenge, and nobody else can**, and no key
   material leaves the server on that path.
"""
import base64
import json
import os
import uuid
from datetime import timedelta
from types import MappingProxyType
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from . import checks, models
from .presence import challenge, config, keys
from .tests_presence_endpoint import EndpointFixture


class SessionOpeningTests(TestCase):
    """`POST /api/v1/sessions/create/` opens exactly one presence row."""

    def setUp(self):
        self.client = APIClient()
        self.teacher = models.User.objects.create_user(
            username='opening_teacher', email='opening_teacher@example.com',
            password='x', role='teacher',
        )
        self.klass = models.Class.objects.create(
            class_code='CG201', class_name='Opening', semester='2026-1',
            teacher=self.teacher,
        )
        self.client.force_authenticate(user=self.teacher)

    def create(self, **over):
        body = {'class_id': self.klass.id, 'duration_minutes': 50}
        body.update(over)
        return self.client.post(reverse('create_session'), body, format='json')

    def test_creating_a_session_opens_its_presence_layer(self):
        answer = self.create()
        self.assertEqual(answer.status_code, 201, answer.data)
        self.assertEqual(models.PresenceSession.objects.count(), 1)
        presence = models.PresenceSession.objects.get()
        self.assertEqual(presence.session.teacher, self.teacher)

    def test_the_opened_row_pins_the_active_configuration_version(self):
        """The version is recorded at open time, never read again for this session."""
        self.create()
        presence = models.PresenceSession.objects.get()
        self.assertEqual(presence.config_version, config.active().version)
        self.assertEqual(presence.protocol_version, str(challenge.PROTOCOL_VERSION))

    def test_the_key_material_is_real_and_usable(self):
        """Not zero-filled columns: the row must be able to sign and re-derive.

        A presence row whose secrets were placeholder bytes would pass every schema
        check and fail every verification, which is the failure mode most worth
        catching here - so this issues a challenge from the stored material and
        verifies it authoritatively, exactly as the gates will.
        """
        self.create()
        presence = models.PresenceSession.objects.get()
        self.assertEqual(len(bytes(presence.root_secret)), keys.SEED_LEN)
        self.assertEqual(len(bytes(presence.signing_seed)), keys.SEED_LEN)
        self.assertNotEqual(bytes(presence.root_secret), bytes(keys.SEED_LEN))
        material = presence.session_keys()
        self.assertEqual(material.public().key_id.hex(), presence.signing_key_id)
        issued = challenge.issue(
            material,
            session_start=presence.chain_start_unix,
            at=presence.chain_start_unix + 1,
        )
        recovered = challenge.verify_authoritative(
            issued.payload,
            session_keys=material,
            session_start=presence.chain_start_unix,
            at=presence.chain_start_unix + 1,
        )
        self.assertEqual(recovered.challenge, issued.challenge)

    def test_two_sessions_do_not_share_key_material(self):
        """Session keys are per-session or the whole chain is one shared secret."""
        self.create()
        self.create()
        secrets = {
            bytes(row.root_secret) for row in models.PresenceSession.objects.all()
        }
        self.assertEqual(len(secrets), 2)

    def test_the_chain_counts_from_the_sessions_own_start(self):
        """A session scheduled ahead counts steps from then, not from now."""
        ahead = timezone.now() + timedelta(hours=3)
        self.create(start_time=ahead.isoformat())
        presence = models.PresenceSession.objects.get()
        self.assertEqual(
            presence.chain_start_unix, int(presence.session.start_time.timestamp()),
        )

    def test_opening_twice_returns_the_same_row_and_the_same_secrets(self):
        """Idempotent by lookup: a second row would carry a second root secret.

        Every challenge already displayed and every proof already queued is bound to
        the first one, so `open` returning a fresh row would invalidate a lesson in
        progress. Asserted on the secrets rather than only on the primary key,
        because a row reused with rotated material would be just as broken.
        """
        self.create()
        session = models.AttendanceSession.objects.get()
        first = models.PresenceSession.objects.get()
        again = models.PresenceSession.open(session)
        self.assertEqual(models.PresenceSession.objects.count(), 1)
        self.assertEqual(again.pk, first.pk)
        self.assertEqual(bytes(again.root_secret), bytes(first.root_secret))
        self.assertEqual(bytes(again.signing_seed), bytes(first.signing_seed))

    def test_a_failure_to_open_leaves_no_half_created_session(self):
        """Both halves or neither.

        A session without its presence row would display challenges nobody can
        verify and answer every proof with 404 - and it would do so silently, which
        is worse than failing the request the teacher can retry.
        """
        with mock.patch.object(
            models.PresenceSession, 'open', side_effect=RuntimeError('no keys'),
        ):
            with self.assertRaises(RuntimeError):
                self.create()
        self.assertEqual(models.AttendanceSession.objects.count(), 0)
        self.assertEqual(models.PresenceSession.objects.count(), 0)


# --- The pinned artifact ------------------------------------------------------

def write_artifact(version, **overrides):
    """A real artifact file on disk, since `load` reads the filesystem.

    Built from the shipped one so it stays valid as parameters are added, with the
    named substitutions applied. Callers must clean it up: the config directory has
    a hygiene test asserting it holds nothing but versioned JSON, and a leftover
    file would fail it.
    """
    values = dict(config.active().values)
    values.update(overrides)
    path = config.artifact_path(version)
    path.write_text(
        json.dumps({
            'version': version,
            'calibration': config.UNCALIBRATED,
            'notes': 'Written by tests_presence_wiring. Not a deployable artifact.',
            'parameters': values,
        }, indent=2, sort_keys=True),
        encoding='utf-8',
    )
    return path


class PinnedArtifactTests(EndpointFixture):
    """A proof is judged by the artifact in force during the lesson.

    The mechanism is made visible by making two artifacts disagree about the outcome.
    A bare authenticated proof on this build scores 2595 millinats and the shipped
    artifact calls PRESENT at 2500, so an artifact whose bar is 3000 turns exactly
    the same bytes into SECONDARY. If pinning were not wired these tests would
    report `present` and name today's version.
    """

    PINNED = 'test-pinned-9999.01'

    def pin(self, **overrides):
        path = write_artifact(self.PINNED, **overrides)
        self.addCleanup(path.unlink, True)
        self.presence.config_version = self.PINNED
        self.presence.save(update_fields=['config_version'])

    def test_a_stricter_pinned_threshold_decides_the_proof(self):
        self.pin(**{'decide.present_millinats': 3000})
        answer = self.accept()
        self.assertEqual(answer.data['status'], 'secondary')
        self.assertEqual(
            models.PresenceDecision.objects.get().config_version, self.PINNED,
        )

    def test_the_same_proof_is_present_under_the_active_artifact(self):
        """The control. Without it the test above could be passing for any reason."""
        answer = self.accept()
        self.assertEqual(answer.data['status'], 'present')
        self.assertEqual(
            models.PresenceDecision.objects.get().config_version,
            config.active().version,
        )

    def test_a_refusal_also_names_the_pinned_artifact(self):
        """A refusal has no score to carry the version, so it takes it from policy."""
        self.pin()
        answer = self.post(self.signed(), signature=bytes(64))
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(
            models.PresenceDecision.objects.get().config_version, self.PINNED,
        )

    def test_a_pinned_offline_allowance_is_not_shortened_afterwards(self):
        """Windows are pinned too, not only thresholds.

        A proof built inside the allowance in force during the lesson must not be
        expired by an allowance shortened since. The session is moved five days
        back, the artifact pinned to the declared maximum allowance, and the proof
        submitted from well outside the shipped 24 hours.
        """
        five_days = 5 * 24 * 3600
        self.pin(**{
            'proof.max_offline_hours': 168,
            'proof.nonce_retention_hours': 336,
        })
        self.start = self.start - five_days
        self.presence.chain_start_unix = self.start
        self.presence.save(update_fields=['chain_start_unix'])
        self.session.start_time = self.session.start_time - timedelta(days=5)
        self.session.end_time = self.session.start_time + timedelta(days=30)
        self.session.save(update_fields=['start_time', 'end_time'])
        answer = self.post(self.signed(seq=1))
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(answer.data['status'], 'present')

    def test_the_shipped_allowance_would_have_refused_that_proof(self):
        """The control for the test above: five days is outside 24 hours."""
        five_days = 5 * 24 * 3600
        self.start = self.start - five_days
        self.presence.chain_start_unix = self.start
        self.presence.save(update_fields=['chain_start_unix'])
        self.session.start_time = self.session.start_time - timedelta(days=5)
        self.session.end_time = self.session.start_time + timedelta(days=30)
        self.session.save(update_fields=['start_time', 'end_time'])
        answer = self.post(self.signed(seq=1))
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(answer.data['status'], 'not_verified')

    def test_an_unloadable_pinned_artifact_is_a_server_fault_not_a_verdict(self):
        """No verdict, no row, no burned nonce - so the queued proof survives.

        Artifacts are added and never edited precisely so this cannot happen in
        ordinary use. If it happens anyway the honest answer is that the server
        cannot decide, not a refusal filed against a student for an operational
        mistake nobody made on their handset.
        """
        self.presence.config_version = 'never-shipped-0000.00'
        self.presence.save(update_fields=['config_version'])
        answer = self.post(self.signed())
        self.assertEqual(answer.status_code, 503, answer.data)
        self.assertNothingRecorded(answer)
        self.assertIn('never-shipped-0000.00', answer.data['error'])

    def test_the_same_proof_succeeds_once_the_artifact_is_restored(self):
        """The 503 has to be recoverable or it is only a slower refusal."""
        submitted = self.signed()
        self.presence.config_version = self.PINNED
        self.presence.save(update_fields=['config_version'])
        self.assertEqual(self.post(submitted).status_code, 503)
        path = write_artifact(self.PINNED)
        self.addCleanup(path.unlink, True)
        self.assertEqual(self.post(submitted).status_code, 200)


# --- Challenge issuance -------------------------------------------------------

class ChallengeIssuanceTests(EndpointFixture):
    """The teacher's screen reads the current challenge; nobody else can.

    `EndpointFixture` is reused for its real keys and its live session rather than
    for its student: most of these tests re-authenticate as the teacher, and the two
    that do not are the ones asserting a student cannot read this at all.
    """

    def setUp(self):
        super().setUp()
        self.url = reverse(
            'presence_session_challenge', args=[self.session.session_id],
        )

    def as_teacher(self, who=None):
        self.client.force_authenticate(user=who or self.teacher)

    def get(self):
        return self.client.get(self.url)

    def test_the_owning_teacher_gets_the_current_challenge(self):
        self.as_teacher()
        answer = self.get()
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(answer.data['config_version'], config.active().version)
        self.assertEqual(
            answer.data['protocol_version'], challenge.PROTOCOL_VERSION,
        )

    def test_the_payload_verifies_authoritatively_against_the_session(self):
        """The bytes on the screen are the bytes the server will re-derive.

        Verified with the session's own root secret, which is the check the gates
        run: signature, session binding, step structure and derivation from the
        chain. A payload that failed this would be a QR nobody could use.
        """
        self.as_teacher()
        payload = base64.b64decode(self.get().data['payload'])
        recovered = challenge.verify_authoritative(
            payload,
            session_keys=self.keys,
            session_start=self.start,
            at=int(timezone.now().timestamp()),
        )
        self.assertEqual(recovered.session_id, self.session.session_id.bytes)
        self.assertEqual(recovered.challenge, self.value_for(recovered.seq))

    def test_a_student_could_verify_it_with_only_the_public_key(self):
        """The check a handset runs offline before building a proof around it."""
        self.as_teacher()
        payload = base64.b64decode(self.get().data['payload'])
        challenge.verify_public(
            payload,
            verify_key=self.keys.public(),
            session_id=self.session.session_id.bytes,
            at=int(timezone.now().timestamp()),
            session_start=self.start,
        )

    def test_the_display_code_is_the_challenge_and_not_a_second_secret(self):
        """One value, two renderings. A code derived elsewhere would be a new hole."""
        self.as_teacher()
        answer = self.get().data
        parsed = challenge.parse(base64.b64decode(answer['payload']))
        self.assertEqual(answer['display_code'], parsed.display_code())

    def test_two_reads_inside_one_step_return_identical_bytes(self):
        """Issuance is a pure function of the session and the step.

        This is what lets the screen redraw only on rotation, and what lets the
        server re-derive what was displayed without having recorded it.
        """
        self.as_teacher()
        self.assertEqual(self.get().data['payload'], self.get().data['payload'])

    def test_reading_the_challenge_writes_nothing(self):
        """A GET that wrote evidence rows would turn a refresh into a finding."""
        self.as_teacher()
        before = self.counts()
        self.get()
        self.get()
        self.assertEqual(self.counts(), before)

    def test_no_key_material_appears_in_the_response(self):
        """The response is built from `Challenge`, which holds no secret at all.

        Asserted on the serialized bytes rather than on the field list, because the
        failure this guards against is a future field added carelessly - and a
        rendered response is the only place that shows up.
        """
        self.as_teacher()
        rendered = json.dumps(self.get().data)
        for secret in (
            bytes(self.presence.root_secret),
            bytes(self.presence.signing_seed),
            self.keys.epoch_key(challenge.epoch_of(self.seq, self.timing)),
        ):
            self.assertNotIn(secret.hex(), rendered)
            self.assertNotIn(base64.b64encode(secret).decode('ascii'), rendered)

    def test_a_student_may_not_read_the_challenge(self):
        """The one permission that carries the room.

        The QR exists so that seeing it requires being in the room looking at the
        screen. An endpoint serving the same bytes to any authenticated account
        would hand the student in the corridor exactly what the room was supposed to
        gate, and no amount of signing downstream recovers that.
        """
        answer = self.get()
        self.assertEqual(answer.status_code, 403, answer.data)
        self.assertNotIn('payload', answer.data)

    def test_another_teacher_gets_a_flat_not_found(self):
        """Not 403: distinguishing them would enumerate whose sessions exist."""
        other = models.User.objects.create_user(
            username='other_teacher', email='other_teacher@example.com',
            password='x', role='teacher',
        )
        self.as_teacher(other)
        answer = self.get()
        self.assertEqual(answer.status_code, 404, answer.data)
        self.assertNotIn('payload', answer.data)

    def test_an_ended_session_says_so_instead_of_issuing(self):
        """Arithmetically there is still a challenge. It would be useless.

        The session-open gate refuses any step whose window begins after the close,
        so every proof built from it would be refused and the student would read
        that refusal as their own failure.
        """
        self.as_teacher()
        self.presence.close()
        answer = self.get()
        self.assertEqual(answer.status_code, 409, answer.data)
        self.assertNotIn('payload', answer.data)

    def test_a_session_scheduled_ahead_is_not_yet_valid(self):
        """A teacher opening the screen early gets told that, not an error page."""
        self.as_teacher()
        self.presence.chain_start_unix = self.start + 3600
        self.presence.save(update_fields=['chain_start_unix'])
        answer = self.get()
        self.assertEqual(answer.status_code, 409, answer.data)
        self.assertEqual(answer.data['code'], challenge.NOT_YET_VALID)

    def test_an_unloadable_artifact_is_a_server_fault_here_too(self):
        """Issuing under a substitute artifact would display an unverifiable code."""
        self.as_teacher()
        self.presence.config_version = 'never-shipped-0000.00'
        self.presence.save(update_fields=['config_version'])
        self.assertEqual(self.get().status_code, 503)

    def test_a_missing_session_is_a_flat_not_found(self):
        self.as_teacher()
        self.url = reverse('presence_session_challenge', args=[uuid.uuid4()])
        self.assertEqual(self.get().status_code, 404)

    def test_the_refresh_instant_is_the_next_step_boundary(self):
        """Sent as an instant so the screen never holds a copy of a tuned parameter.

        And `expires_at` is later than it: a challenge outlives its step
        deliberately, so a scan straddling a rotation is not punished for the timing
        of the rotation.
        """
        self.as_teacher()
        answer = self.get().data
        self.assertEqual(
            answer['refresh_after'], answer['issued_at'] + self.timing.step_seconds,
        )
        self.assertGreater(answer['expires_at'], answer['refresh_after'])

    def test_the_challenge_it_issues_is_one_a_proof_can_be_built_on(self):
        """End to end, through the two endpoints a lesson actually uses.

        The screen is read, a proof is built from the challenge that came back, and
        the proof is submitted. This is the Phase 1 claim in one test: what the
        teacher's display shows and what the server re-derives are the same thing.
        """
        self.as_teacher()
        parsed = challenge.parse(base64.b64decode(self.get().data['payload']))
        self.client.force_authenticate(user=self.student)
        self.url = reverse('presence_submit_proof')
        answer = self.post(self.signed(seq=parsed.seq, value=parsed.challenge))
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(answer.data['status'], 'present')


# --- The deploy-time system checks --------------------------------------------

class SystemCheckTests(SimpleTestCase):
    """`manage.py check` refuses a configuration that cannot do its job.

    These run before every `runserver` and `migrate` and already run in CI, which
    makes them the cheapest place to catch a misconfiguration that would otherwise
    surface one 503 at a time in production.
    """

    def tearDown(self):
        config.set_active(None)

    def with_values(self, **overrides):
        values = dict(config.load(config.DEFAULT_VERSION).values)
        values.update(overrides)
        config.set_active(config.Artifact(
            version='check-test',
            calibration=config.UNCALIBRATED,
            notes='built by SystemCheckTests',
            values=MappingProxyType(values),
        ))

    def test_the_shipped_configuration_passes_both_checks(self):
        self.assertEqual(checks.presence_config_loads(None), [])
        self.assertEqual(checks.presence_config_is_consistent(None), [])

    def test_an_unshippable_version_is_an_error_that_names_what_exists(self):
        config.set_active(None)
        with mock.patch.dict(os.environ, {config.ENV_VERSION: 'not-a-version'}):
            found = checks.presence_config_loads(None)
        self.assertEqual([error.id for error in found], ['attendance.E001'])
        self.assertIn(config.DEFAULT_VERSION, found[0].hint)

    def test_an_artifact_that_cannot_name_itself_is_an_error(self):
        """A decision that cannot name its parameters cannot be re-derived."""
        config.set_active(config.Artifact(
            version='', calibration=config.UNCALIBRATED, notes='',
            values=MappingProxyType({}),
        ))
        self.assertEqual(
            [error.id for error in checks.presence_config_loads(None)],
            ['attendance.E002'],
        )

    def test_a_retention_shorter_than_the_offline_allowance_is_an_error(self):
        """The failure this exists for: silent in production, not loud.

        A nonce forgotten while a proof carrying it is still acceptable is a replay
        window, and nothing at runtime raises - the ledger simply has no record of a
        proof it should have refused.
        """
        self.with_values(**{
            'proof.max_offline_hours': 48, 'proof.nonce_retention_hours': 24,
        })
        found = checks.presence_config_is_consistent(None)
        self.assertEqual([error.id for error in found], ['attendance.E003'])
        self.assertIn('replay', found[0].msg)

    def test_an_unreachable_operating_point_is_an_error(self):
        """A PRESENT bar above the sum of every weight refuses everyone forever."""
        self.with_values(**{'decide.present_millinats': 20000})
        self.assertEqual(
            [error.id for error in checks.presence_config_is_consistent(None)],
            ['attendance.E003'],
        )

    def test_an_inverted_review_band_is_an_error(self):
        self.with_values(**{
            'decide.present_millinats': 1000, 'decide.secondary_millinats': 2000,
        })
        self.assertEqual(
            [error.id for error in checks.presence_config_is_consistent(None)],
            ['attendance.E003'],
        )

    def test_two_inconsistencies_are_reported_as_two_errors(self):
        """An operator fixing one should not have to deploy to discover the next."""
        self.with_values(**{
            'proof.max_offline_hours': 48, 'proof.nonce_retention_hours': 24,
            'decide.present_millinats': 1000, 'decide.secondary_millinats': 2000,
        })
        self.assertEqual(len(checks.presence_config_is_consistent(None)), 2)

    def test_being_uncalibrated_is_not_a_check_failure(self):
        """A stated decision, tested so it cannot drift into a silenced check.

        Shipping uncalibrated is the honest state of this build. A check that failed
        on it would block every deploy or be permanently silenced, and a permanently
        silenced check is noise. `calibration` is reported on every decision instead.
        """
        self.assertEqual(config.active().calibration, config.UNCALIBRATED)
        self.assertEqual(checks.presence_config_loads(None), [])
        self.assertEqual(checks.presence_config_is_consistent(None), [])

    def test_a_broken_version_is_reported_once_and_not_twice(self):
        """One misconfiguration must not look like two problems."""
        config.set_active(None)
        with mock.patch.dict(os.environ, {config.ENV_VERSION: 'not-a-version'}):
            self.assertEqual(len(checks.presence_config_loads(None)), 1)
            self.assertEqual(checks.presence_config_is_consistent(None), [])
