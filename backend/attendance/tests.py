from datetime import timedelta

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from .models import AttendanceRecord, AttendanceSession, Class, Enrollment, User
from .secure_attendance import issue_epoch


@override_settings(ATTENDANCE_SIGNING_SECRET='test-attendance-secret')
class SecureAttendanceApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.teacher = User.objects.create_user(
            username='teacher', email='teacher@example.com', password='pw', role='teacher')
        self.student = User.objects.create_user(
            username='student', email='student@example.com', password='pw', role='student')
        self.class_obj = Class.objects.create(
            class_code='SEC-1', class_name='Security', semester='1', teacher=self.teacher)
        Enrollment.objects.create(class_obj=self.class_obj, student=self.student)
        self.session = AttendanceSession.objects.create(
            class_obj=self.class_obj, teacher=self.teacher, duration_minutes=30,
            end_time=timezone.now() + timedelta(minutes=30), qr_code_data='{}')

    def register(self, user, device_id):
        self.client.force_authenticate(user)
        return self.client.post(reverse('register_device'), {
            'device_id': device_id, 'device_name': 'test device'}, format='json')

    def payload(self, **overrides):
        epoch = issue_epoch(self.session)
        data = {
            'qr_payload': epoch['qr_payload'], 'captcha': epoch['captcha'],
            'device_id': 'student-device-0001',
            'gyroscope': {'available': True, 'sampleCount': 40, 'durationMs': 5000,
                          'maxGapMs': 200, 'interaction': 0.5},
            'accelerometer': {'available': True, 'sampleCount': 40, 'durationMs': 5000,
                              'maxGapMs': 200, 'interaction': 1.0},
        }
        data.update(overrides)
        return data

    def test_all_checks_pass_marks_present_and_is_idempotent(self):
        self.assertEqual(self.register(self.student, 'student-device-0001').status_code, 201)
        self.client.force_authenticate(self.student)
        url = reverse('mark_attendance', kwargs={'session_id': self.session.session_id})
        response = self.client.post(url, self.payload(), format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['final_status'], 'verified')
        self.assertEqual(response.data['status'], 'present')
        duplicate = self.client.post(url, self.payload(), format='json')
        self.assertEqual(duplicate.status_code, 200)
        self.assertEqual(AttendanceRecord.objects.count(), 1)

    def test_any_failed_check_requires_teacher_review(self):
        self.register(self.student, 'student-device-0001')
        self.client.force_authenticate(self.student)
        response = self.client.post(
            reverse('mark_attendance', kwargs={'session_id': self.session.session_id}),
            self.payload(captcha='9999', gyroscope={
                'available': True, 'sampleCount': 2, 'durationMs': 5000,
                'maxGapMs': 200, 'interaction': 0.0}), format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['status'], 'pending_review')
        self.assertEqual(response.data['final_status'], 'teacher_review_required')
        self.assertEqual(response.data['verification']['captcha_result'], 'fail')
        self.assertEqual(response.data['verification']['gyroscope_result'], 'fail')

    def test_device_limits_are_enforced(self):
        self.assertEqual(self.register(self.student, 'student-device-0001').status_code, 201)
        self.assertEqual(self.register(self.student, 'student-device-0002').status_code, 403)
        self.assertEqual(self.register(self.teacher, 'teacher-device-001').status_code, 201)
        self.assertEqual(self.register(self.teacher, 'teacher-device-002').status_code, 201)
        self.assertEqual(self.register(self.teacher, 'teacher-device-003').status_code, 403)

    def test_teacher_can_resolve_review(self):
        self.register(self.student, 'student-device-0001')
        self.client.force_authenticate(self.student)
        response = self.client.post(
            reverse('mark_attendance', kwargs={'session_id': self.session.session_id}),
            self.payload(accelerometer={'available': False}), format='json')
        record = AttendanceRecord.objects.get()
        self.client.force_authenticate(self.teacher)
        resolved = self.client.post(
            reverse('resolve_review', kwargs={'record_id': record.id}),
            {'decision': 'present'}, format='json')
        self.assertEqual(resolved.status_code, 200)
        self.assertEqual(resolved.data['final_status'], 'teacher_cross_verified')
        record.refresh_from_db()
        self.assertEqual(record.status, 'present')
