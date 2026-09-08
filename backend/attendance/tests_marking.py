"""
Regression tests for the attendance marking path.

`tests.py` covers the analytics engine. This module covers the endpoints that
actually create attendance records - registration, QR marking, offline sync,
pattern verification, announcement targeting and integrity persistence. None of
them had a single test before, which is how a NameError in `verify_image` shipped
and stayed live.

Each test pins one specific defect closed. A failure here means a hole that was
open in the deployed system is open again:

* self-service registration must never mint a Django-admin account;
* a client-supplied offline timestamp must never reach `marked_at` unchecked, and
  must never be in the future;
* a late offline session sync must never mark unmarked students present;
* `verify_image` must return success on a match;
* zero sessions must never produce a 100% attendance rate;
* reading a dashboard must never write integrity-flag rows.
"""
import json
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .models import (
    AttendanceFlag,
    AttendanceRecord,
    AttendanceSession,
    Class,
    Enrollment,
)
from .tests import AnalyticsFixtureMixin

User = get_user_model()

REGISTER_URL = '/api/v1/auth/register/'
VERIFY_IMAGE_URL = '/api/v1/sessions/verify-image/'
SYNC_SESSION_URL = '/api/v1/sessions/sync-offline-session/'
SYNC_PATTERN_URL = '/api/v1/sessions/sync-offline-pattern/'
ANNOUNCEMENTS_URL = '/api/v1/announcements/'
OVERVIEW_URL = '/api/v1/analytics/teacher/overview/'
SCAN_URL = '/api/v1/analytics/teacher/flags/scan/'


def mark_url(session):
    return f'/api/v1/sessions/{session.session_id}/mark/'


def an_image(name='shot.png'):
    """Something for `request.FILES` to find.

    The bytes are never decoded: every test that reaches the vision pipeline
    patches it, because these tests are about the marking path, not about Gemini.
    """
    return SimpleUploadedFile(name, b'not-a-real-png', content_type='image/png')


def reasons_of(record):
    """`verification_reasons` is a JSON list string, or None when clean."""
    if not record.verification_reasons:
        return []
    return json.loads(record.verification_reasons)


# Windows samples the system clock coarsely and interpolates, so two successive
# timezone.now() calls can differ by a microsecond in either direction. These
# assertions are about "server time, not the time the client claimed", where the
# claim is minutes or hours away - so a tolerance that swallows clock jitter
# costs the test nothing and stops it flaking.
CLOCK_JITTER = timedelta(milliseconds=50)


def assert_server_timed(case, record, before, claimed=None):
    """`marked_at` came from the server clock, not from the client's claim."""
    case.assertGreaterEqual(record.marked_at, before - CLOCK_JITTER)
    case.assertLessEqual(record.marked_at, timezone.now() + CLOCK_JITTER)
    if claimed is not None:
        case.assertNotEqual(record.marked_at, claimed)


class MarkingFixtureMixin(AnalyticsFixtureMixin):
    """Adds the session helpers the marking endpoints need."""

    def _active_session(self, *, minutes_ago=10, duration=60, klass=None,
                        class_type='qr'):
        start = self.now - timedelta(minutes=minutes_ago)
        return AttendanceSession.objects.create(
            class_obj=klass or self.klass,
            teacher=self.teacher,
            class_type=class_type,
            start_time=start,
            duration_minutes=duration,
            end_time=start + timedelta(minutes=duration),
            qr_code_data='{}',
            status='active',
        )

    def _completed_session(self, *, hours_ago=2, duration=60, klass=None):
        """Ended in the past, still inside the 24h offline sync window."""
        start = self.now - timedelta(hours=hours_ago)
        return AttendanceSession.objects.create(
            class_obj=klass or self.klass,
            teacher=self.teacher,
            class_type='qr',
            start_time=start,
            duration_minutes=duration,
            end_time=start + timedelta(minutes=duration),
            qr_code_data='{}',
            status='completed',
        )


class RegistrationPrivilegeTests(TestCase):
    """
    The register endpoint is AllowAny. Whatever it accepts, the internet can ask
    for. It used to accept `role='admin'`, and `role` was the only thing standing
    between an anonymous POST and a Django-admin account.
    """

    def setUp(self):
        self.client = APIClient()

    def _payload(self, **over):
        body = {
            'username': 'newcomer',
            'email': 'newcomer@example.com',
            'role': 'student',
            'password': 'pw12345!',
            'password2': 'pw12345!',
        }
        body.update(over)
        return body

    def test_admin_role_is_refused_and_creates_nothing(self):
        res = self.client.post(REGISTER_URL, self._payload(role='admin'))
        self.assertEqual(res.status_code, 400)
        self.assertIn('role', res.data)
        self.assertFalse(User.objects.filter(email='newcomer@example.com').exists())

    def test_unknown_role_is_refused(self):
        res = self.client.post(REGISTER_URL, self._payload(role='superuser'))
        self.assertEqual(res.status_code, 400)
        self.assertFalse(User.objects.filter(email='newcomer@example.com').exists())

    def test_self_service_roles_are_created_without_staff_rights(self):
        for role in ('student', 'teacher'):
            with self.subTest(role=role):
                email = f'{role}@example.com'
                res = self.client.post(REGISTER_URL, self._payload(
                    username=f'new_{role}', email=email, role=role,
                ))
                self.assertEqual(res.status_code, 201, res.data)
                user = User.objects.get(email=email)
                self.assertEqual(user.role, role)
                self.assertFalse(user.is_staff)
                self.assertFalse(user.is_superuser)

    def test_is_staff_in_the_payload_is_ignored(self):
        """`is_staff` is read-only on the serializer; asking for it must do nothing."""
        res = self.client.post(REGISTER_URL, self._payload(
            is_staff=True, is_superuser=True,
        ))
        self.assertEqual(res.status_code, 201, res.data)
        user = User.objects.get(email='newcomer@example.com')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)


class OfflineMarkTimestampTests(MarkingFixtureMixin, TestCase):
    """
    `marked_at` used to be whatever the client said it was.

    It feeds punctuality, latency and the post-session-mark integrity detector,
    so a client that can set it can both backdate its own attendance and steer
    the detector that would have caught it. The claim is now honoured only when
    it is consistent with the session it claims to belong to.
    """

    def setUp(self):
        self.build_fixture()
        self.session = self._completed_session(hours_ago=2, duration=60)
        self.client = APIClient()
        self.client.force_authenticate(self.alice)

    def _sync(self, timestamp, student=None):
        if student is not None:
            self.client.force_authenticate(student)
        return self.client.post(mark_url(self.session), {
            'is_offline_sync': True,
            'timestamp': timestamp,
        }, format='json')

    def _record(self, student=None):
        return AttendanceRecord.objects.get(
            session=self.session, student=student or self.alice,
        )

    def test_a_claim_inside_the_session_window_is_honoured(self):
        claimed = self.session.start_time + timedelta(minutes=3)
        res = self._sync(claimed.isoformat())
        self.assertEqual(res.status_code, 201, res.data)
        rec = self._record()
        self.assertEqual(rec.status, 'present')
        self.assertAlmostEqual(
            (rec.marked_at - claimed).total_seconds(), 0, delta=1,
        )
        self.assertEqual(reasons_of(rec), [])

    def test_a_claim_after_the_session_ended_falls_back_to_server_time(self):
        claimed = self.session.end_time + timedelta(minutes=30)
        res = self._sync(claimed.isoformat())
        self.assertEqual(res.status_code, 201, res.data)
        rec = self._record()
        self.assertGreater(rec.marked_at, claimed)
        self.assertIn('offline_timestamp_after_session_end', reasons_of(rec))

    def test_a_claim_before_the_session_started_falls_back_to_server_time(self):
        claimed = self.session.start_time - timedelta(hours=1)
        res = self._sync(claimed.isoformat())
        self.assertEqual(res.status_code, 201, res.data)
        rec = self._record()
        self.assertGreater(rec.marked_at, claimed)
        self.assertIn('offline_timestamp_before_session_start', reasons_of(rec))

    def test_a_future_claim_falls_back_to_server_time(self):
        claimed = timezone.now() + timedelta(hours=3)
        res = self._sync(claimed.isoformat())
        self.assertEqual(res.status_code, 201, res.data)
        rec = self._record()
        self.assertLess(rec.marked_at, claimed)
        self.assertIn('offline_timestamp_in_future', reasons_of(rec))

    def test_an_unparseable_claim_falls_back_to_server_time(self):
        before = timezone.now()
        res = self._sync('yesterday-ish')
        self.assertEqual(res.status_code, 201, res.data)
        rec = self._record()
        assert_server_timed(self, rec, before)
        self.assertIn('offline_timestamp_unparseable', reasons_of(rec))

    def test_the_online_path_ignores_a_supplied_timestamp(self):
        """Only offline syncs may claim a time at all."""
        live = self._active_session(minutes_ago=10, duration=60)
        claimed = live.start_time + timedelta(minutes=1)
        before = timezone.now()
        res = self.client.post(mark_url(live), {
            'timestamp': claimed.isoformat(),
        }, format='json')
        self.assertEqual(res.status_code, 201, res.data)
        rec = AttendanceRecord.objects.get(session=live, student=self.alice)
        assert_server_timed(self, rec, before, claimed)
        self.assertEqual(reasons_of(rec), [])

    def test_overwriting_an_absent_record_records_a_rejected_claim(self):
        """The absent-to-present branch is a second write path, and it was the
        one that skipped the check."""
        AttendanceRecord.objects.create(
            session=self.session, student=self.alice, status='absent',
        )
        claimed = self.session.end_time + timedelta(minutes=30)
        before = timezone.now()
        res = self._sync(claimed.isoformat())
        self.assertEqual(res.status_code, 200, res.data)
        rec = self._record()
        self.assertEqual(rec.status, 'present')
        assert_server_timed(self, rec, before, claimed)
        self.assertIn('offline_timestamp_after_session_end', reasons_of(rec))


class OfflineSessionSyncTests(MarkingFixtureMixin, TestCase):
    """
    The teacher-side offline sync used to fail open.

    `default_status = 'present' if is_expired else 'absent'` meant that syncing a
    session more than 24 hours late marked every unmarked enrolled student
    present. A missing mark is the absence of evidence, not evidence of presence,
    and this was the largest hole on the marking path.
    """

    def setUp(self):
        self.build_fixture()
        self.client = APIClient()
        self.client.force_authenticate(self.teacher)

    def _sync(self, *, hours_ago, duration=60, session_id=None):
        start = self.now - timedelta(hours=hours_ago)
        return self.client.post(SYNC_SESSION_URL, {
            'session_id': session_id or str(uuid.uuid4()),
            'class_id': self.klass.id,
            'class_type': 'qr',
            'duration_minutes': duration,
            'start_time': start.isoformat(),
            'end_time': (start + timedelta(minutes=duration)).isoformat(),
        }, format='json')

    def test_a_late_sync_marks_unmarked_students_absent_not_present(self):
        res = self._sync(hours_ago=30)
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data['marked_absent'], 3)

        session = AttendanceSession.objects.order_by('-created_at').first()
        statuses = set(
            AttendanceRecord.objects.filter(session=session)
            .values_list('status', flat=True)
        )
        self.assertEqual(statuses, {'absent'})

    def test_a_late_sync_says_the_absences_may_be_incomplete(self):
        """Students can no longer sync their own marks past 24h, so the roster is
        provisional. Saying so is the honest alternative to marking them present."""
        res = self._sync(hours_ago=30)
        self.assertIn('warning', res.data)
        self.assertIn('24 hours', res.data['warning'])

    def test_a_recent_sync_also_marks_absent_but_carries_no_warning(self):
        res = self._sync(hours_ago=2)
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data['marked_absent'], 3)
        self.assertNotIn('warning', res.data)

    def test_re_syncing_the_same_session_does_not_duplicate_records(self):
        sid = str(uuid.uuid4())
        self.assertEqual(self._sync(hours_ago=2, session_id=sid).status_code, 201)
        before = AttendanceRecord.objects.count()

        res = self._sync(hours_ago=2, session_id=sid)
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data['message'], 'Session already synced')
        self.assertEqual(AttendanceRecord.objects.count(), before)

    def test_students_cannot_sync_sessions(self):
        self.client.force_authenticate(self.alice)
        res = self._sync(hours_ago=2)
        self.assertEqual(res.status_code, 403)


class VerifyImageTests(MarkingFixtureMixin, TestCase):
    """
    `verify_image` had a NameError on its success path.

    `if scan_time:` referenced a name that function never assigned, and it ran
    after the AttendanceRecord was already created. The bare `except` turned it
    into HTTP 400 with a traceback string, so every successful verification looked
    like a failure to the client while the present record was already committed.

    The regression guard is the absence of the `trace` key: it only appears when
    the view raised.
    """

    def setUp(self):
        self.build_fixture()
        self.session = self._active_session(minutes_ago=5, duration=60)
        self.client = APIClient()
        self.client.force_authenticate(self.alice)

    def _verify(self, *, focal='2.0'):
        return self.client.post(VERIFY_IMAGE_URL, {
            'session_id': str(self.session.session_id),
            'focal_distance': focal,
            'student_image': an_image(),
        }, format='multipart')

    def test_a_match_returns_success_and_no_traceback(self):
        with patch('attendance.verification.verify_offline_code',
                   return_value=(True, 0.91, ['code_match'])):
            res = self._verify()

        self.assertEqual(res.status_code, 201, res.data)
        self.assertNotIn('trace', res.data)
        self.assertEqual(res.data['status'], 'pass')
        self.assertAlmostEqual(res.data['score'], 0.91)

        rec = AttendanceRecord.objects.get(session=self.session, student=self.alice)
        self.assertEqual(rec.status, 'present')
        self.assertAlmostEqual(rec.verification_score, 0.91)
        self.assertEqual(reasons_of(rec), ['code_match'])

    def test_marked_at_is_the_server_clock_not_a_client_claim(self):
        before = timezone.now()
        with patch('attendance.verification.verify_offline_code',
                   return_value=(True, 0.9, [])):
            res = self.client.post(VERIFY_IMAGE_URL, {
                'session_id': str(self.session.session_id),
                'focal_distance': '2.0',
                'student_image': an_image(),
                'timestamp': (self.now - timedelta(days=3)).isoformat(),
            }, format='multipart')

        self.assertEqual(res.status_code, 201, res.data)
        rec = AttendanceRecord.objects.get(session=self.session, student=self.alice)
        assert_server_timed(self, rec, before)

    def test_a_non_match_is_held_for_review_not_marked_present(self):
        with patch('attendance.verification.verify_offline_code',
                   return_value=(False, 0.2, ['code_mismatch'])):
            res = self._verify()

        self.assertEqual(res.status_code, 400)
        self.assertNotIn('trace', res.data)
        self.assertEqual(res.data['status'], 'fail')

        rec = AttendanceRecord.objects.get(session=self.session, student=self.alice)
        self.assertEqual(rec.status, 'pending_review')

    def test_a_failed_attempt_can_be_retried(self):
        with patch('attendance.verification.verify_offline_code',
                   return_value=(False, 0.2, ['code_mismatch'])):
            self._verify()
        with patch('attendance.verification.verify_offline_code',
                   return_value=(True, 0.95, ['code_match'])):
            res = self._verify()

        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(
            AttendanceRecord.objects.filter(
                session=self.session, student=self.alice,
            ).count(),
            1,
        )
        rec = AttendanceRecord.objects.get(session=self.session, student=self.alice)
        self.assertEqual(rec.status, 'present')

    def test_a_photo_taken_too_close_is_refused_before_any_record_exists(self):
        with patch('attendance.verification.verify_offline_code') as vc:
            res = self._verify(focal='0.1')

        self.assertEqual(res.status_code, 400)
        vc.assert_not_called()
        self.assertFalse(
            AttendanceRecord.objects.filter(session=self.session).exists()
        )

    def test_an_ended_session_cannot_be_verified_against(self):
        ended = self._completed_session(hours_ago=3)
        res = self.client.post(VERIFY_IMAGE_URL, {
            'session_id': str(ended.session_id),
            'focal_distance': '2.0',
            'student_image': an_image(),
        }, format='multipart')
        self.assertEqual(res.status_code, 400)
        self.assertFalse(AttendanceRecord.objects.filter(session=ended).exists())


class AnnouncementTargetingTests(MarkingFixtureMixin, TestCase):
    """
    The low-attendance announcement used to fabricate a rate.

    `rate = 100.0` when `total_sessions == 0` is the 0/0 = 100% the analytics
    engine was rewritten to eliminate, still live in this path. An unknown rate
    cannot be compared to a threshold, so a student in a class that has never met
    is simply not targeted.
    """

    def setUp(self):
        self.build_fixture()
        self.client = APIClient()
        self.client.force_authenticate(self.teacher)

    def _announce(self, klass, threshold):
        return self.client.post(ANNOUNCEMENTS_URL, {
            'title': 'Attendance warning',
            'content': 'Your attendance is below the requirement.',
            'target_type': 'low_attendance',
            'target_class': klass.id,
            'min_attendance_threshold': threshold,
        }, format='json')

    def _recipients(self, res):
        from .models import Announcement
        return set(
            Announcement.objects.get(id=res.data['id'])
            .recipients.values_list('username', flat=True)
        )

    def test_only_students_below_the_threshold_are_targeted(self):
        """alice 4/4, bob 2/4, carol 0/4 against a 75% requirement."""
        res = self._announce(self.klass, 75)
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(self._recipients(res), {'bob', 'carol'})

    def test_a_class_with_no_sessions_targets_nobody(self):
        empty = Class.objects.create(
            class_code='CS999', class_name='Not Started Yet', semester='5',
            teacher=self.teacher, term=self.term,
        )
        Enrollment.objects.create(class_obj=empty, student=self.alice)
        Enrollment.objects.create(class_obj=empty, student=self.bob)

        res = self._announce(empty, 75)
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(self._recipients(res), set())

    def test_an_unknown_rate_is_not_treated_as_a_perfect_one(self):
        """The specific value the old code invented.

        Below 100 the fabricated 100.0 and a skipped student happen to agree, so
        a threshold above 100 is the only place the invented number was visible:
        it made every student of a class that never met eligible for a
        low-attendance warning. `min_attendance_threshold` has no upper bound, so
        this is reachable input, not a hypothetical.
        """
        empty = Class.objects.create(
            class_code='CS998', class_name='Also Not Started', semester='5',
            teacher=self.teacher, term=self.term,
        )
        Enrollment.objects.create(class_obj=empty, student=self.carol)

        res = self._announce(empty, 101)
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(self._recipients(res), set())

    def test_students_cannot_create_announcements(self):
        self.client.force_authenticate(self.alice)
        res = self._announce(self.klass, 75)
        self.assertEqual(res.status_code, 403)


class SyncOfflinePatternTests(MarkingFixtureMixin, TestCase):
    """
    The student-side pattern sync accepted a future scan time.

    The 24-hour window check computes `now - session.start_time`, so a future
    claim produced a negative delta and passed. Combined with the session lookup
    by `start_time <= scan_time <= end_time`, a client could pre-mark a scheduled
    session it had not attended. The guard now rejects the future claim before the
    session is ever looked up.
    """

    def setUp(self):
        self.build_fixture()
        self.client = APIClient()
        self.client.force_authenticate(self.alice)

    def _sync(self, when):
        return self.client.post(SYNC_PATTERN_URL, {
            'timestamp': when.isoformat(),
            'student_image': an_image(),
        }, format='multipart')

    def test_a_future_scan_time_is_refused(self):
        future = timezone.now() + timedelta(hours=2)
        res = self._sync(future)
        self.assertEqual(res.status_code, 400)
        self.assertIn('future', res.data['error'])

    def test_a_future_scan_time_is_refused_before_the_session_lookup(self):
        """A scheduled pattern session the student has not attended yet.

        The guard must fire on the timestamp alone: reaching the lookup is what
        used to let a queued mark land on a session that had not happened.
        """
        start = self.now + timedelta(hours=1)
        scheduled = AttendanceSession.objects.create(
            class_obj=self.klass, teacher=self.teacher, class_type='pattern',
            start_time=start, duration_minutes=60,
            end_time=start + timedelta(minutes=60),
            qr_code_data='{}', pattern_code='42', status='active',
        )
        res = self._sync(start + timedelta(minutes=5))
        self.assertEqual(res.status_code, 400)
        self.assertIn('future', res.data['error'])
        self.assertFalse(
            AttendanceRecord.objects.filter(session=scheduled).exists()
        )

    def test_a_past_scan_time_with_no_matching_session_is_a_lookup_failure(self):
        """Proves the 400 above came from the guard and not from the lookup."""
        res = self._sync(self.now - timedelta(days=2))
        self.assertEqual(res.status_code, 404)


class IntegrityPersistenceTests(MarkingFixtureMixin, TestCase):
    """
    Reading the dashboard used to write evidence rows.

    `persist` defaulted to on, so a teacher GET on the analytics overview created
    AttendanceFlag records as a side effect: refreshing the tab manufactured
    "newly detected" counts, and how many signals looked new depended on who had
    opened the page last. Persistence is now an explicit POST.
    """

    def setUp(self):
        self.build_fixture()
        # One unambiguous signal for the detectors to find: a mark timestamped
        # twenty minutes after its session ended. detect_post_session_marks is
        # purely deterministic, so this does not depend on any threshold.
        session = self.sessions[0]
        AttendanceRecord.objects.filter(
            session=session, student=self.alice,
        ).update(marked_at=session.end_time + timedelta(minutes=20))
        self.client = APIClient()
        self.client.force_authenticate(self.teacher)

    def test_reading_the_overview_writes_nothing(self):
        res = self.client.get(OVERVIEW_URL)
        self.assertEqual(res.status_code, 200, res.data)
        self.assertIs(res.data['meta']['flags_persisted'], False)
        self.assertEqual(AttendanceFlag.objects.count(), 0)

    def test_repeated_reads_still_write_nothing(self):
        for _ in range(3):
            self.client.get(OVERVIEW_URL)
        self.assertEqual(AttendanceFlag.objects.count(), 0)

    def test_the_scan_endpoint_persists_what_it_finds(self):
        res = self.client.post(SCAN_URL)
        self.assertEqual(res.status_code, 200, res.data)
        self.assertIs(res.data['meta']['flags_persisted'], True)
        self.assertGreaterEqual(res.data['newly_detected'], 1)
        self.assertTrue(
            AttendanceFlag.objects.filter(flag_type='post_session_mark').exists()
        )

    def test_a_second_scan_reports_the_signal_as_already_known(self):
        first = self.client.post(SCAN_URL)
        created = AttendanceFlag.objects.count()

        second = self.client.post(SCAN_URL)
        self.assertEqual(second.status_code, 200, second.data)
        self.assertEqual(second.data['newly_detected'], 0)
        self.assertGreaterEqual(
            second.data['previously_known'], first.data['newly_detected'],
        )
        self.assertEqual(AttendanceFlag.objects.count(), created)

    def test_students_cannot_run_a_scan(self):
        self.client.force_authenticate(self.alice)
        res = self.client.post(SCAN_URL)
        self.assertEqual(res.status_code, 403)
        self.assertEqual(AttendanceFlag.objects.count(), 0)

    def test_the_scan_endpoint_is_not_reachable_by_get(self):
        """The verb is the guarantee. A GET must not be able to persist."""
        res = self.client.get(SCAN_URL)
        self.assertEqual(res.status_code, 405)
        self.assertEqual(AttendanceFlag.objects.count(), 0)


class AssetLinksTests(TestCase):
    """
    /.well-known/assetlinks.json used to serve a hardcoded package name and a
    hardcoded SHA-256 fingerprint. The fingerprint matched no key this project
    could produce - release builds were signed with the machine-local debug
    keystore - so App Links verification was asserting a certificate nobody held.
    Both values now come from settings, and an unconfigured fingerprint list is
    served as empty rather than as a wrong value.
    """

    URL = '/.well-known/assetlinks.json'

    def setUp(self):
        self.client = APIClient()

    def test_no_literals_remain_in_the_view(self):
        import inspect
        from . import views
        source = inspect.getsource(views.assetlinks_json)
        self.assertNotIn('com.example.attendance_app', source)
        self.assertNotIn('87:17:E3', source)

    def test_it_reflects_configuration(self):
        fp = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'
        with self.settings(ANDROID_APP_PACKAGE='com.example.test',
                           ANDROID_CERT_FINGERPRINTS=[fp]):
            res = self.client.get(self.URL)
        self.assertEqual(res.status_code, 200)
        target = res.json()[0]['target']
        self.assertEqual(target['namespace'], 'android_app')
        self.assertEqual(target['package_name'], 'com.example.test')
        self.assertEqual(target['sha256_cert_fingerprints'], [fp])

    def test_an_unconfigured_fingerprint_list_is_served_empty(self):
        """Honest failure beats a confident wrong answer: App Links verification
        should fail, not appear to succeed against the wrong certificate."""
        with self.settings(ANDROID_CERT_FINGERPRINTS=[]):
            res = self.client.get(self.URL)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()[0]['target']['sha256_cert_fingerprints'], [])


class SeedGuardTests(TestCase):
    """
    seed.py ran on every production boot (startup.sh and the Dockerfile CMD both
    called it) and its `set_password` is unconditional, so each restart reset
    admin@example.com to a password that was then printed to the App Service log
    stream - against a publicly routed /admin/. It now refuses to run unless
    invited, and there is no default password to fall back on.
    """

    def _seed_module(self):
        import importlib.util
        import pathlib
        path = pathlib.Path(__file__).resolve().parent.parent / 'seed.py'
        self.assertTrue(path.exists(), path)
        return path.read_text(encoding='utf-8')

    def test_there_is_no_literal_default_password(self):
        source = self._seed_module()
        self.assertNotIn('password123', source)

    def test_it_refuses_outside_debug_without_an_explicit_opt_in(self):
        source = self._seed_module()
        self.assertIn('SEED_ALLOW_PRODUCTION', source)
        self.assertIn('settings.DEBUG', source)

    def test_it_no_longer_echoes_the_password(self):
        source = self._seed_module()
        self.assertNotIn('admin@example.com / {default_password}', source)

    def test_the_guards_actually_fire(self):
        """Behaviour, not just the presence of a string. Both guards run before
        any database access, so this is safe to invoke against the dev database:
        it exits before it would write anything."""
        import os
        import pathlib
        import subprocess
        import sys

        backend = pathlib.Path(__file__).resolve().parent.parent

        def run(**overrides):
            env = dict(os.environ)
            env['PYTHONPATH'] = ''
            env.pop('SEED_ALLOW_PRODUCTION', None)
            env.pop('SEED_PASSWORD', None)
            env.update(overrides)
            return subprocess.run(
                [sys.executable, 'seed.py'],
                cwd=str(backend), env=env,
                capture_output=True, text=True, timeout=180,
            )

        off = run(DJANGO_DEBUG='False')
        self.assertNotEqual(off.returncode, 0, off.stdout)
        self.assertIn('SEED_ALLOW_PRODUCTION', off.stdout + off.stderr)

        no_pw = run(DJANGO_DEBUG='True')
        self.assertNotEqual(no_pw.returncode, 0, no_pw.stdout)
        self.assertIn('no password supplied', no_pw.stdout + no_pw.stderr)


class EndSessionPresenceCloseTests(MarkingFixtureMixin, TestCase):
    """
    Ending a session must close its presence half. Nothing called
    `PresenceSession.close()`, which made two documented properties untrue at once:
    the session-open gate refuses a proof whose step window begins after
    `closed_at`, and with `closed_at` never set that gate could not fire in
    production; and the raw radio observations behind each decision were kept
    indefinitely, which is the permanent movement record the privacy rules forbid.
    """

    def setUp(self):
        self.build_fixture()
        self.client = APIClient()
        self.client.force_authenticate(self.teacher)
        self.session = self._active_session()
        self.presence = self._presence_for(self.session)

    def _presence_for(self, session):
        from .presence import config, keys as key_mod
        from .models import PresenceSession
        session_keys = key_mod.SessionKeys.generate(session.session_id.bytes)
        return PresenceSession.objects.create(
            session=session,
            protocol_version='1',
            config_version=config.active().version,
            root_secret=session_keys.root_secret,
            signing_seed=session_keys.signing.seed,
            signing_key_id=session_keys.public().key_id.hex(),
            chain_start_unix=int(session.start_time.timestamp()),
        )

    def _observe(self, presence=None):
        from .models import PresenceObservation
        target = presence or self.presence
        return PresenceObservation.objects.create(
            presence_session=target,
            student=self.alice,
            kind='origin',
            step=3,
            observed_at_claim=target.chain_start_unix + 20,
            payload={'note': 'a sighting'},
        )

    def _end(self, session=None):
        target = session or self.session
        return self.client.post(f'/api/v1/sessions/{target.session_id}/end/')

    def test_ending_a_session_closes_the_presence_row(self):
        self.assertIsNone(self.presence.closed_at)
        response = self._end()
        self.assertEqual(response.status_code, 200, response.data)
        self.presence.refresh_from_db()
        self.assertIsNotNone(self.presence.closed_at)

    def test_ending_a_session_purges_its_observations(self):
        self._observe()
        self._observe()
        self._end()
        self.presence.refresh_from_db()
        self.assertEqual(self.presence.observations.count(), 0)
        self.assertIsNotNone(self.presence.observations_purged_at)

    def test_the_close_time_matches_the_session_end_and_is_not_merely_now(self):
        """So a proof's step window is compared against the lesson, not the request.

        A teacher who ends a session late would otherwise extend the window every
        proof is judged against by however long they took to tap the button.
        """
        self._end()
        self.session.refresh_from_db()
        self.presence.refresh_from_db()
        self.assertEqual(self.presence.closed_at, self.session.end_time)

    def test_a_session_with_no_presence_row_still_ends(self):
        """The presence path is opt-in. Most sessions have no presence row at all,
        and ending one must not depend on a related object that was never created."""
        plain = self._active_session()
        response = self._end(plain)
        self.assertEqual(response.status_code, 200, response.data)
        plain.refresh_from_db()
        self.assertEqual(plain.status, 'completed')

    def test_ending_an_already_completed_session_closes_presence_too(self):
        """The offline-sync branch returns early. It used to skip the close
        entirely, so a session that reached 'completed' by that route kept its
        observations and left its gate inert for good."""
        self._observe()
        self.session.status = 'completed'
        self.session.save(update_fields=['status'])
        response = self._end()
        self.assertEqual(response.status_code, 200, response.data)
        self.presence.refresh_from_db()
        self.assertIsNotNone(self.presence.closed_at)
        self.assertEqual(self.presence.observations.count(), 0)

    def test_ending_a_session_prunes_expired_replay_entries(self):
        """Nothing pruned the ledger, so it grew for the life of the deployment.

        A permanent record of every submission is not what the retention rules
        allow, and an index that only ever grows is not what a term of lessons
        should leave behind.
        """
        from .models import ReplayEntry
        from .presence import replay
        now = int(timezone.now().timestamp())
        stale = ReplayEntry.objects.create(
            digest='a' * 64, session_id='b' * 32, device_key_id='c' * 16,
            nonce='d' * 32, step=1,
            received_at=replay.retention_horizon(now) - 60,
        )
        fresh = ReplayEntry.objects.create(
            digest='e' * 64, session_id='b' * 32, device_key_id='c' * 16,
            nonce='f' * 32, step=2, received_at=now - 60,
        )
        self._end()
        self.assertFalse(ReplayEntry.objects.filter(pk=stale.pk).exists())
        self.assertTrue(ReplayEntry.objects.filter(pk=fresh.pk).exists())

    def test_pruning_never_reaches_inside_the_offline_allowance(self):
        """The horizon must sit beyond the window a proof may still arrive in.

        Forgetting a nonce while a proof carrying it could still be accepted is a
        replay window rather than housekeeping, so this pins the ordering the
        config registry cross-checks rather than trusting it stays that way.
        """
        from .presence import replay
        bounds = replay.Bounds.active()
        self.assertGreater(
            bounds.nonce_retention_seconds, bounds.max_offline_seconds,
        )
