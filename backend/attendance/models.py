from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
import uuid

class User(AbstractUser):
    ROLE_CHOICES = (
        ('student', 'Student'),
        ('teacher', 'Teacher'),
        ('admin', 'Admin')
    )
    email = models.EmailField(unique=True, blank=False)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='student')

    USERNAME_FIELD = 'email'  # Use email for authentication instead of username
    REQUIRED_FIELDS = ['username']  # Username becomes optional field

    def __str__(self):
        return f"{self.username} ({self.role})"
    
    class Meta:
        db_table = 'users'


class StudentProfile(models.Model):
    """Table for student roll numbers and student specific data"""
    student = models.OneToOneField(
        User, 
        on_delete=models.CASCADE,
        primary_key=True,  # Keep this as the only primary key
        related_name='student_profile',
        limit_choices_to={'role': 'student'}
    )

    class Meta:
        db_table = 'student_profiles'  # Table name in PostgreSQL

    def __str__(self):
        return f"{self.student.username}"

    
class AcademicTerm(models.Model):
    """
    Institutional academic term (semester/trimester).

    Exists so that analytics never has to hardcode the attendance requirement,
    the academic year, or the term boundaries. Every analytics computation is
    scoped to a term, which makes "remaining sessions" and therefore every
    forecast an honest number instead of a guess.
    """
    name = models.CharField(max_length=100)                  # e.g. "Semester 5"
    academic_year = models.CharField(max_length=20)          # e.g. "2025-2026"
    start_date = models.DateField()
    end_date = models.DateField()
    required_attendance_pct = models.FloatField(default=75.0)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'academic_terms'
        ordering = ['-start_date']
        unique_together = ('name', 'academic_year')

    def __str__(self):
        return f"{self.name} ({self.academic_year})"

    @property
    def total_weeks(self):
        return max(1, ((self.end_date - self.start_date).days + 1) // 7)

    def weeks_remaining(self, as_of=None):
        """Whole weeks left in the term from `as_of` (date), floored at 0."""
        from django.utils import timezone as _tz
        ref = as_of or _tz.localdate()
        if ref >= self.end_date:
            return 0
        return max(0, (self.end_date - ref).days / 7.0)

    @classmethod
    def current(cls):
        """Active term, else the term containing today, else the latest term."""
        from django.utils import timezone as _tz
        today = _tz.localdate()
        term = cls.objects.filter(is_active=True).first()
        if term:
            return term
        term = cls.objects.filter(start_date__lte=today, end_date__gte=today).first()
        if term:
            return term
        return cls.objects.first()


class Class(models.Model):
    """Table for class/course information"""
    class_code = models.CharField(max_length=20, unique=True)
    class_name = models.CharField(max_length=200)
    semester = models.CharField(max_length=50)
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='classes_taught', limit_choices_to={'role': 'teacher'})
    term = models.ForeignKey(
        AcademicTerm,
        on_delete=models.SET_NULL,
        related_name='classes',
        null=True,
        blank=True,
    )
    # Planned total sessions for the term. When null, analytics infers the
    # cadence from observed session frequency instead of inventing a constant.
    expected_sessions_total = models.PositiveIntegerField(null=True, blank=True)
    sessions_per_week = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    class Meta:
        db_table = 'classes'  # Table name in PostgreSQL
        verbose_name_plural = 'Classes'
        ordering = ['class_code']

    def __str__(self):
        return f"{self.class_code} - {self.class_name}"
    
    @property
    def teacher_name(self):
        return self.teacher.username or self.teacher.get_full_name()
    
    @property
    def student_count(self):
        return self.enrollments.count()
    
class Enrollment(models.Model):
    """Table for student enrollments in classes"""
    class_obj = models.ForeignKey(Class, on_delete=models.CASCADE, related_name='enrollments')
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='enrolled_classes', limit_choices_to={'role': 'student'})
    enrolled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'enrollments'  # Table name in PostgreSQL
        unique_together = ('class_obj', 'student')
        ordering = ['class_obj', 'student']
        indexes = [
            models.Index(fields=['student', 'class_obj'], name='enr_student_class_idx'),
            models.Index(fields=['enrolled_at'], name='enr_enrolled_at_idx'),
        ]


    def __str__(self):
        return f"{self.student.username} enrolled in {self.class_obj.class_code}"


# AttendanceSession
class AttendanceSession(models.Model):
    """Table for attendance sessions with QR codes"""
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('completed', 'Completed'),
    )
    
    CLASS_TYPE_CHOICES = (
        ('qr', 'QR'),
        ('pattern', 'Pattern'),
    )
    

    session_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    class_obj = models.ForeignKey(Class, on_delete=models.CASCADE, related_name='sessions')
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_sessions')
    
    class_type = models.CharField(max_length=10, choices=CLASS_TYPE_CHOICES, default='qr')

    pattern_code = models.CharField(max_length=50, blank=True, null=True)
    instruction_card = models.TextField(blank=True, null=True)
    shape_data = models.JSONField(blank=True, null=True)
    
    from django.utils import timezone
    start_time = models.DateTimeField(default=timezone.now)
    duration_minutes = models.IntegerField()  # Duration in minutes
    end_time = models.DateTimeField()  # Calculated: start_time + duration
    
    qr_code_data = models.TextField()  # JSON string with session info
    reference_image = models.ImageField(
        upload_to='session_references/%Y/%m/%d/',
        blank=True,
        null=True,
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'attendance_sessions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['class_obj', 'start_time'], name='sess_class_start_idx'),
            models.Index(fields=['status', 'start_time'], name='sess_status_start_idx'),
            models.Index(fields=['teacher', 'start_time'], name='sess_teacher_start_idx'),
        ]


    def __str__(self):
        return f"{self.class_obj.class_code} - {self.start_time.strftime('%Y-%m-%d %H:%M')}"
    
    @property
    def is_active(self):
        """Check if session is still active"""
        from django.utils import timezone
        return self.status == 'active' and timezone.now() < self.end_time


# Attendance Record
class AttendanceRecord(models.Model):
    """Table for individual attendance records"""
    session = models.ForeignKey(AttendanceSession, on_delete=models.CASCADE, related_name='records')
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='attendance_records')
    
    marked_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=20,
        choices=(('present', 'Present'), ('absent', 'Absent'), ('pending_review', 'Pending Review')),
        default='present'
    )
    
    verification_score = models.FloatField(null=True, blank=True)
    verification_reasons = models.TextField(null=True, blank=True)  # Store JSON string of reasons
    
    class Meta:
        db_table = 'attendance_records'
        unique_together = ('session', 'student')
        ordering = ['marked_at']
        indexes = [
            models.Index(fields=['student', 'session'], name='rec_student_session_idx'),
            models.Index(fields=['marked_at'], name='rec_marked_at_idx'),
            models.Index(fields=['status'], name='rec_status_idx'),
        ]

    def __str__(self):
        return f"{self.student.username} - {self.session.class_obj.class_code} - {self.status}"

    @property
    def latency_seconds(self):
        """
        Seconds between session start and the moment the mark landed.

        This is the raw signal behind all punctuality analytics. Negative values
        (marked before the scheduled start) are clamped to 0.
        """
        if not self.marked_at or not self.session_id:
            return None
        delta = (self.marked_at - self.session.start_time).total_seconds()
        return max(0.0, delta)



class Announcement(models.Model):
    TARGET_TYPE_CHOICES = (
        ('class', 'Class'),
        ('individual', 'Individual'),
        ('low_attendance', 'Low Attendance'),
    )

    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_announcements', limit_choices_to={'role': 'teacher'})
    title = models.CharField(max_length=200)
    content = models.TextField()
    
    target_type = models.CharField(max_length=20, choices=TARGET_TYPE_CHOICES, default='class')
    target_class = models.ForeignKey(Class, on_delete=models.CASCADE, related_name='announcements', null=True, blank=True)
    min_attendance_threshold = models.IntegerField(null=True, blank=True)
    
    is_urgent = models.BooleanField(default=False)
    recipients = models.ManyToManyField(User, related_name='announcements_received')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'announcements'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} by {self.sender.username}"


class AttendanceFlag(models.Model):
    """
    A persisted, auditable integrity anomaly.

    Anomalies are stored rather than recomputed-and-discarded so that a teacher's
    review decision survives, and so that any figure shown in the Integrity tab
    can be traced back to concrete evidence.
    """
    FLAG_TYPE_CHOICES = (
        ('low_verification', 'Low Verification Score'),
        ('burst_marking', 'Burst Marking (possible proxy cluster)'),
        ('session_collision', 'Session Collision (two places at once)'),
        ('late_outlier', 'Latency Outlier'),
        ('post_session_mark', 'Marked After Session End'),
        ('cohort_drop', 'Cohort Attendance Drop'),
        # Presence layer outcomes. Deliberately coarse: a flag is something a
        # teacher reviews, so it names what happened to the student, not which of
        # the protocol's refusal codes fired. The specific reason codes go in
        # `evidence`, where an admin can read them and a student cannot - printing
        # the detection mechanics into a teacher-facing label would teach the
        # attack as fast as it explained the flag.
        ('presence_secondary', 'Presence: Secondary Verification Needed'),
        ('presence_suspicious', 'Presence: Suspicious Evidence'),
        ('presence_refused', 'Presence: Proof Refused'),
        # Reachable only when an operating point is raised above the arithmetic
        # floor of an admissible proof. On the shipped artifact a proof that would
        # score this low has already been refused instead.
        ('presence_not_verified', 'Presence: Not Verified'),
    )
    SEVERITY_CHOICES = (
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
    )
    STATUS_CHOICES = (
        ('open', 'Open'),
        ('resolved', 'Resolved'),
        ('dismissed', 'Dismissed'),
    )

    session = models.ForeignKey(
        AttendanceSession, on_delete=models.CASCADE,
        related_name='flags', null=True, blank=True,
    )
    class_obj = models.ForeignKey(
        Class, on_delete=models.CASCADE, related_name='flags', null=True, blank=True,
    )
    student = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='attendance_flags', null=True, blank=True,
    )
    flag_type = models.CharField(max_length=32, choices=FLAG_TYPE_CHOICES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='warning')
    # Anomaly strength, 0..1. Higher means more confident it is a real anomaly.
    score = models.FloatField(default=0.0)
    # Machine-readable proof: the counts, timestamps and deltas that triggered it.
    evidence = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='open')
    resolution_note = models.TextField(blank=True, null=True)
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        related_name='resolved_flags', null=True, blank=True,
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'attendance_flags'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'severity'], name='flag_status_sev_idx'),
            models.Index(fields=['class_obj', 'status'], name='flag_class_status_idx'),
            models.Index(fields=['student', 'status'], name='flag_student_status_idx'),
        ]
        # One live flag per (session, student, type); recompute updates in place.
        unique_together = ('session', 'student', 'flag_type')

    def __str__(self):
        who = self.student.username if self.student_id else 'cohort'
        return f"[{self.severity}] {self.flag_type} - {who}"


class InterventionLog(models.Model):
    """
    Closes the loop on low-attendance announcements.

    For each nudged student we snapshot attendance before the message, then
    recompute it after, and compare against a matched control group. This is what
    turns the dashboard into a measurable intervention system rather than a
    passive report.
    """
    OUTCOME_CHOICES = (
        ('pending', 'Pending (insufficient follow-up sessions)'),
        ('improved', 'Improved'),
        ('unchanged', 'Unchanged'),
        ('declined', 'Declined'),
    )

    announcement = models.ForeignKey(
        Announcement, on_delete=models.CASCADE, related_name='interventions',
    )
    student = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='interventions_received',
    )
    class_obj = models.ForeignKey(
        Class, on_delete=models.CASCADE, related_name='interventions', null=True, blank=True,
    )
    sent_at = models.DateTimeField()

    baseline_pct = models.FloatField(null=True, blank=True)
    baseline_sessions = models.PositiveIntegerField(default=0)
    followup_pct = models.FloatField(null=True, blank=True)
    followup_sessions = models.PositiveIntegerField(default=0)
    delta_points = models.FloatField(null=True, blank=True)
    # Same-class, same-risk-band students who were NOT messaged. Isolates the
    # message effect from whatever the whole cohort was doing anyway.
    control_delta_points = models.FloatField(null=True, blank=True)
    outcome = models.CharField(max_length=12, choices=OUTCOME_CHOICES, default='pending')
    computed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'intervention_logs'
        ordering = ['-sent_at']
        unique_together = ('announcement', 'student')
        indexes = [
            models.Index(fields=['student', 'sent_at'], name='iv_student_sent_idx'),
            models.Index(fields=['class_obj', 'outcome'], name='iv_class_outcome_idx'),
        ]

    def __str__(self):
        return f"{self.student.username} <- {self.announcement.title} ({self.outcome})"




# ============================================================================
# Presence layer
#
# Storage for the classroom presence verification protocol. The decision logic
# itself lives in `attendance/presence/` and is deliberately database-free, so
# that a proof can be re-derived by anything holding the same bytes and the same
# config artifact. These models are where those bytes are kept, not where they
# are judged.
#
# Every table below is prefixed `presence_`. That is not cosmetic. This repo's
# history contains an abandoned migration lineage (commits bec7805, aed5a86)
# whose tables `registered_devices`, `attendance_verifications` and
# `attendance_audit_events` are still physically present in at least one
# developer database while having no model on this branch. An unprefixed
# `registered_devices` would therefore migrate cleanly on a fresh checkout and
# fail with "table already exists" on that machine only - the worst class of bug
# to inherit. Prefixing sidesteps it without dropping tables that hold rows
# somebody may still want.
#
# Two conventions worth reading once:
#
#   Binary identifiers are stored as lowercase hex in CharFields, not as
#   BinaryField. Backends disagree about what they hand back - psycopg returns
#   memoryview, SQLite returns bytes - and this subsystem compares digests and
#   nonces for equality, which is precisely where that disagreement turns into a
#   replay defence that silently never matches. Hex is unambiguous, indexable on
#   every backend, and greppable in a log. BinaryField is used only for opaque
#   blobs nobody compares: key material and signed payloads.
#
#   Absent evidence is absent, never negative. A null room, a missing room
#   profile or an unregistered anchor set means the spatial block contributes
#   nothing to a score. It must never be recorded in a way that reads as
#   evidence against a student, because a student cannot be responsible for a
#   room nobody has calibrated.
# ============================================================================

_HEX_16 = RegexValidator(r'^[0-9a-f]{16}$', 'expected 16 lowercase hex characters (8 bytes)')
_HEX_32 = RegexValidator(r'^[0-9a-f]{32}$', 'expected 32 lowercase hex characters (16 bytes)')
_HEX_64 = RegexValidator(r'^[0-9a-f]{64}$', 'expected 64 lowercase hex characters (32 bytes)')


class Room(models.Model):
    """A physical teaching space.

    The spatial entity the product has been missing: `Class` is the subject and
    `AttendanceSession` is the period, so until now nothing recorded *where* a
    lesson happened. Rooms exist ahead of the hardware that would make them
    load-bearing - no anchors are deployed on this scope - so a session with no
    room is ordinary and must stay ordinary.
    """
    code = models.CharField(max_length=32, unique=True)
    name = models.CharField(max_length=120, blank=True)
    building = models.CharField(max_length=120, blank=True)
    floor = models.CharField(max_length=16, blank=True)
    # Recorded in metres. The pilot room in the design notes is 15x20 ft; storing
    # metres keeps one unit in the database and leaves display conversion to the
    # client, which already has a unit preference.
    length_meters = models.FloatField(null=True, blank=True)
    width_meters = models.FloatField(null=True, blank=True)
    capacity = models.PositiveIntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_rooms'
        ordering = ['code']
        indexes = [
            models.Index(fields=['building', 'floor'], name='room_bldg_floor_idx'),
        ]

    def __str__(self):
        return self.code if not self.name else f"{self.code} - {self.name}"


class RoomProfile(models.Model):
    """One versioned RF calibration of one room.

    Versioned rather than mutable because a decision must remain explainable
    after the room is re-surveyed: a proof records which profile judged it, and
    re-calibrating must not retroactively rewrite what a past decision meant.

    Nothing here is a universal threshold. Every distribution is per room and per
    position within that room, which is the whole reason this table exists rather
    than a global RSSI constant - the same handset reads differently at the back
    of one room than at the back of another, and a shared cutoff would be a
    guess dressed as a measurement.
    """
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='profiles')
    calibration_version = models.CharField(max_length=64)
    # Anchor label -> declared position, as surveyed. Kept alongside the live
    # Anchor rows so a past decision can be re-read even after an anchor moves.
    anchor_map = models.JSONField(default=dict, blank=True)
    # Position label -> per-anchor RSSI distribution (median, MAD, sample count).
    # Includes the negative positions - corridor, outside the window, the
    # adjacent room - because a fingerprint that only knows what "inside" looks
    # like cannot tell you that something is outside.
    position_stats = models.JSONField(default=dict, blank=True)
    expected_variance_db = models.FloatField(null=True, blank=True)
    tolerance_db = models.FloatField(null=True, blank=True)
    # 0..1 self-assessment of the survey: how much of the room was covered, how
    # many samples per position. Low confidence must reduce the weight of spatial
    # evidence, never the standing of the student measured against it.
    confidence = models.FloatField(null=True, blank=True)
    survey_positions = models.PositiveIntegerField(default=0)
    negative_positions = models.PositiveIntegerField(default=0)
    calibrated_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, related_name='room_calibrations',
        null=True, blank=True,
    )
    calibrated_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_room_profiles'
        ordering = ['room', '-created_at']
        unique_together = ('room', 'calibration_version')
        constraints = [
            # One profile may be the live one for a room. Activation is an
            # explicit act, so a half-finished survey cannot start judging.
            models.UniqueConstraint(
                fields=['room'], condition=models.Q(is_active=True),
                name='presence_one_active_profile_per_room',
            ),
        ]

    def __str__(self):
        state = 'active' if self.is_active else 'draft'
        return f"{self.room.code} @ {self.calibration_version} ({state})"


class Anchor(models.Model):
    """A fixed BLE beacon at a known position in a room.

    Anchors broadcast a rotating ephemeral identifier derived from
    `ephemeral_key`, never a stable one: a stable beacon id turns any passer-by
    with a scanner into a room-occupancy sensor, and a student walking a corridor
    is not consenting to be logged. The key is a secret at rest for the same
    reason a session root secret is - holding it lets you impersonate the anchor.

    No anchors are deployed on this scope. The table exists so the spatial
    evidence block has somewhere to land without a schema change later.
    """
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='anchors')
    label = models.CharField(max_length=32)
    position_x_m = models.FloatField(null=True, blank=True)
    position_y_m = models.FloatField(null=True, blank=True)
    height_m = models.FloatField(null=True, blank=True)
    ephemeral_key = models.BinaryField(max_length=32)
    rotation_seconds = models.PositiveIntegerField(default=900)
    battery_pct = models.PositiveIntegerField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_anchors'
        ordering = ['room', 'label']
        unique_together = ('room', 'label')
        indexes = [
            models.Index(fields=['is_active', 'last_seen_at'], name='anchor_live_seen_idx'),
        ]

    def __str__(self):
        return f"{self.room.code}/{self.label}"


# The wire vocabularies live in the protocol package, so the database reads them
# from there rather than restating them. A status integer means the same thing in
# a signed proof, in a decision row and in an API response, and it cannot drift
# apart across the three by anyone editing only one of them. Labels are local -
# they are display text, and a missing one degrades to a title-cased name rather
# than blocking a migration.
from .presence import codec as _codec
from .presence import proof as _proof

_PLATFORM_LABELS = {'unknown': 'Unknown', 'android': 'Android', 'ios': 'iOS', 'web': 'Web'}
_STATUS_LABELS = {
    'unknown': 'Unknown',
    'present': 'Present',
    'secondary': 'Secondary verification',
    'not_verified': 'Not verified',
    'suspicious': 'Suspicious',
}
_BIOMETRIC_LABELS = {
    'absent': 'Not attempted (unsupported or not required)',
    'success': 'Success',
    'failed': 'Failed',
    'cancelled': 'Cancelled by student',
}


def _choices(names, labels):
    return tuple(
        (value, labels.get(name, name.replace('_', ' ').title()))
        for value, name in sorted(names.items())
    )


PLATFORM_CHOICES = _choices(_proof.PLATFORM_NAMES, _PLATFORM_LABELS)
PRESENCE_STATUS_CHOICES = _choices(_proof.STATUS_NAMES, _STATUS_LABELS)
BIOMETRIC_CHOICES = _choices(_proof.BIOMETRIC_NAMES, _BIOMETRIC_LABELS)


class RegisteredDevice(models.Model):
    """The binding between a student account and one handset.

    Before this table, a login was the whole of a student's identity, so lending
    credentials lent attendance. A device holds an Ed25519 private key it
    generated itself and never transmits; the server keeps only the public half,
    which means the server can check a proof and cannot forge one.

    At most one device is active per student, enforced in the database rather
    than in a view. Allowing two would quietly restore the attack the table
    exists to close: one handset in the room and one in a pocket elsewhere, both
    signing validly. Replacing a phone is therefore an explicit revoke-then-
    register, and the revoked row stays for audit instead of being deleted.

    `capabilities` is the bitfield the handset reported about itself. It is used
    to explain what evidence was even possible on that device - a phone with no
    biometric hardware is not a suspicious phone - and never as evidence of
    anything. A device claiming a capability it lacks gains nothing, because the
    evidence itself is what scores, not the claim to be able to produce it.
    """
    student = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='presence_devices',
    )
    # keys.key_id_for(public_key): the first 8 bytes of a domain-separated hash.
    # Denormalised from the public key so a proof can be routed to its device with
    # one indexed lookup on the identifier the proof actually carries.
    key_id = models.CharField(max_length=16, unique=True, validators=[_HEX_16])
    public_key = models.CharField(max_length=64, unique=True, validators=[_HEX_64])
    platform = models.SmallIntegerField(choices=PLATFORM_CHOICES, default=0)
    capabilities = models.PositiveIntegerField(default=0)
    # Per-model RSSI offset set, for the deferred spatial work. Empty is normal.
    device_profile_version = models.CharField(max_length=64, blank=True)
    label = models.CharField(max_length=120, blank=True)

    is_active = models.BooleanField(default=True)
    registered_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, related_name='presence_devices_revoked',
        null=True, blank=True,
    )
    revocation_reason = models.TextField(blank=True)

    class Meta:
        db_table = 'presence_registered_devices'
        ordering = ['student', '-registered_at']
        constraints = [
            models.UniqueConstraint(
                fields=['student'], condition=models.Q(is_active=True),
                name='presence_one_active_device_per_student',
            ),
        ]
        indexes = [
            models.Index(fields=['student', 'is_active'], name='dev_student_live_idx'),
            models.Index(fields=['platform', 'is_active'], name='dev_platform_live_idx'),
        ]

    def __str__(self):
        state = 'active' if self.is_active else 'revoked'
        return f"{self.student.username} / {self.key_id} ({state})"

    @property
    def capability_names(self):
        """Which declared capabilities this device reported, as sorted names.

        Reads the bit definitions from the protocol package so a new capability
        becomes visible here the moment it is defined there.
        """
        found = []
        for name in dir(_proof):
            if not name.startswith('CAP_'):
                continue
            bit = getattr(_proof, name)
            if isinstance(bit, int) and not isinstance(bit, bool) and self.capabilities & bit:
                found.append(name[len('CAP_'):].lower())
        return sorted(found)

    def public_key_bytes(self):
        return bytes.fromhex(self.public_key)


class PresenceSession(models.Model):
    """The presence half of one teacher-controlled session.

    Holds the two secrets that make an offline rolling challenge possible: a root
    secret the epoch keys are derived from, and the seed of the Ed25519 key that
    signs each challenge. Both are held by the teacher's handset too, which is
    what lets a teacher run a lesson with no connectivity at all.

    Stating the consequence rather than leaving it implied: a database compromise
    lets an attacker mint challenges for a session. It does not let them sign a
    proof as any student, because device private keys never leave their handsets.
    That asymmetry is deliberate and it is why the two key hierarchies are
    separate; it belongs in the threat model, not in a comment nobody reads.

    `config_version` is pinned when the session opens. A proof submitted three
    days later is judged by the parameters that were live when the lesson ran,
    not by whatever has been activated since - otherwise re-tuning the fusion
    model would silently re-decide history.
    """
    session = models.OneToOneField(
        AttendanceSession, on_delete=models.CASCADE, related_name='presence',
    )
    room = models.ForeignKey(
        Room, on_delete=models.SET_NULL, related_name='sessions', null=True, blank=True,
    )
    # The calibration in force. Null is the normal case on this scope: no anchors
    # are deployed, so the spatial evidence block is simply empty.
    room_profile = models.ForeignKey(
        RoomProfile, on_delete=models.SET_NULL, related_name='sessions',
        null=True, blank=True,
    )
    protocol_version = models.CharField(max_length=32)
    config_version = models.CharField(max_length=64)

    root_secret = models.BinaryField(max_length=32)
    signing_seed = models.BinaryField(max_length=32)
    signing_key_id = models.CharField(max_length=16, validators=[_HEX_16])
    # Unix seconds the challenge chain counts steps from. Stored rather than read
    # off `session.start_time` because the chain must not shift if a teacher edits
    # the scheduled start: every already-issued challenge is bound to this origin.
    chain_start_unix = models.BigIntegerField()

    created_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    observations_purged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'presence_sessions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['room', 'created_at'], name='psess_room_created_idx'),
            models.Index(fields=['closed_at'], name='psess_closed_idx'),
        ]

    def __str__(self):
        where = self.room.code if self.room_id else 'no room'
        return f"presence({self.session_id}) @ {where}"

    def __repr__(self):
        # Explicit, because the default repr of a model with secret columns is one
        # careless log line away from printing them.
        return "<PresenceSession session=%s root_secret=<redacted> signing_seed=<redacted>>" % (
            self.session_id,
        )

    @classmethod
    def open(cls, session, *, room=None, room_profile=None):
        """Open the presence layer for one attendance session.

        Idempotent by lookup rather than by `get_or_create`, because the row owns
        the session's key material: a second row would carry a second root secret,
        and every challenge already displayed and every proof already queued against
        them would stop verifying. A session that already has one gets it back.

        The configuration version is pinned here and not read again at submission
        time. A proof queued offline on Monday and synced on Wednesday is judged by
        the parameters that were in force during the lesson, not by whatever has been
        activated since - otherwise re-tuning one threshold would silently re-decide
        history, and `PresenceDecision.config_version` would name an artifact that
        did not produce the verdict.

        `chain_start_unix` is taken from the session's own start rather than from now,
        so the challenge chain and the lesson count from the same instant even when a
        teacher schedules a session ahead.
        """
        from .presence import challenge as _challenge
        from .presence import config as _config
        from .presence import keys as _keys
        existing = cls.objects.filter(session=session).first()
        if existing is not None:
            return existing
        material = _keys.SessionKeys.generate(session.session_id.bytes)
        return cls.objects.create(
            session=session,
            room=room,
            room_profile=room_profile,
            protocol_version=str(_challenge.PROTOCOL_VERSION),
            config_version=_config.active().version,
            root_secret=material.root_secret,
            signing_seed=material.signing.seed,
            signing_key_id=material.public().key_id.hex(),
            chain_start_unix=int(session.start_time.timestamp()),
        )

    def artifact(self):
        """The configuration artifact this session was opened under.

        Raises `config.ConfigError` if that version is no longer on disk, and the
        proof endpoint answers that as a server fault rather than as a verdict: an
        artifact somebody removed is not evidence about a student. Artifacts are
        added and never edited precisely so this cannot happen in ordinary use.
        """
        from .presence import config as _config
        return _config.load(self.config_version)

    def session_keys(self):
        """Rebuild the protocol key material for this session.

        Coerces out of whatever the backend handed back: psycopg returns
        memoryview for a BYTEA column and SQLite returns bytes, and the key
        loader is strict about lengths, so the conversion happens here once
        instead of at every call site.
        """
        from .presence import keys as _keys
        return _keys.SessionKeys.load(
            session_id=self.session.session_id.bytes,
            root_secret=bytes(self.root_secret),
            signing_seed=bytes(self.signing_seed),
        )

    def close(self, when=None):
        """Close this presence session and drop its raw observations.

        Idempotent, and deliberately does both things in one call, because the
        two are one guarantee rather than two: `closed_at` is what the session-open
        gate reads to refuse a step whose window begins after the lesson ended, and
        the purge is what keeps the observations behind an audited decision from
        outliving the lesson they were gathered in. Wiring one without the other is
        how a documented property becomes an untrue one - a session that never
        closes leaves the gate inert and the rows in place.

        Returns the number of observations deleted.
        """
        from django.utils import timezone
        if self.closed_at is None:
            self.closed_at = when or timezone.now()
            self.save(update_fields=['closed_at'])
        return self.purge_observations()

    def purge_observations(self):
        """Delete the raw per-observation evidence for this session.

        Called when a session closes. The decisions and their reason codes
        survive; the radio observations behind them do not, because keeping them
        would accumulate into exactly the permanent movement database this system
        must not become. What a room looked like at 10:15 on a Tuesday is not
        something a student agreed to have kept.
        """
        from django.utils import timezone
        deleted, _ = self.observations.all().delete()
        self.observations_purged_at = timezone.now()
        self.save(update_fields=['observations_purged_at'])
        return deleted


class SessionEpoch(models.Model):
    """Chain state for one epoch of one session's rolling challenge.

    An epoch is a window of steps sharing one derived key, so that a key
    recovered from a compromised teacher handset or a screen recording yields
    that window's challenges and no others, in either direction. This row records
    which steps were actually issued, which is what lets the server answer "was
    this challenge ever real?" for a proof that arrives days later, without
    having to trust the proof's own account of itself.
    """
    presence_session = models.ForeignKey(
        PresenceSession, on_delete=models.CASCADE, related_name='epochs',
    )
    epoch = models.PositiveIntegerField()
    first_step = models.PositiveIntegerField()
    last_step = models.PositiveIntegerField()
    issued_count = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_session_epochs'
        ordering = ['presence_session', 'epoch']
        unique_together = ('presence_session', 'epoch')
        indexes = [
            models.Index(fields=['expires_at'], name='epoch_expires_idx'),
        ]

    def __str__(self):
        return f"epoch {self.epoch} steps {self.first_step}..{self.last_step}"


class PresenceObservation(models.Model):
    """One radio observation inside a session's observation window.

    Short-lived by design: these rows are deleted when the session closes
    (`PresenceSession.purge_observations`). They exist to make a decision
    auditable while the lesson is still reviewable, not to build a history of
    where students have been.

    Nothing identifying goes in `payload`. A relay sighting carries a
    relay-scoped pseudonym, an anchor sighting carries a rotating ephemeral id,
    and neither resolves to a person outside this session. The student column is
    the association that matters and it is a foreign key here, in a table with a
    deletion date, rather than something recoverable from a broadcast.
    """
    KIND_CHOICES = (
        ('origin', 'Direct teacher origin sighting'),
        ('relay', 'Relayed sighting'),
        ('anchor', 'Anchor sighting'),
        ('ranging', 'Precision ranging measurement'),
    )

    presence_session = models.ForeignKey(
        PresenceSession, on_delete=models.CASCADE, related_name='observations',
    )
    student = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='presence_observations',
        null=True, blank=True,
    )
    device = models.ForeignKey(
        RegisteredDevice, on_delete=models.SET_NULL, related_name='observations',
        null=True, blank=True,
    )
    kind = models.CharField(max_length=12, choices=KIND_CHOICES)
    step = models.PositiveIntegerField()
    # As reported by the handset. Server-derived timing lives on the proof, so the
    # two never get confused: this is what the device said, that is what we know.
    observed_at_claim = models.BigIntegerField()
    payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_observations'
        ordering = ['presence_session', 'step']
        indexes = [
            models.Index(fields=['presence_session', 'student'], name='obs_sess_student_idx'),
            models.Index(fields=['kind', 'step'], name='obs_kind_step_idx'),
        ]

    def __str__(self):
        return f"{self.kind}@{self.step}"


class ReplayEntry(models.Model):
    """The durable half of replay defence: proofs already seen.

    `MemoryLedger` in the protocol package forgets everything on restart, and a
    restart would re-open every nonce it had been remembering. This table is the
    deployment's answer to that, and the unique constraints are the point of it -
    uniqueness is enforced by the database, not by a read-then-write in a view,
    because two copies of the same proof arriving at once is the ordinary case for
    an offline queue that just found signal, not an exotic one.

    It stores no proof body. A digest, the device, its nonce and the step it
    referenced are everything replay defence needs, so the table can be pruned on
    schedule without anybody having to decide what to do about evidence inside it.
    """
    digest = models.CharField(max_length=64, unique=True, validators=[_HEX_64])
    session_id = models.CharField(max_length=32, validators=[_HEX_32])
    device_key_id = models.CharField(max_length=16, validators=[_HEX_16])
    nonce = models.CharField(max_length=32, validators=[_HEX_32])
    step = models.PositiveIntegerField()
    received_at = models.BigIntegerField()

    class Meta:
        db_table = 'presence_replay_entries'
        ordering = ['-received_at']
        constraints = [
            models.UniqueConstraint(
                fields=['device_key_id', 'nonce'],
                name='presence_device_nonce_once',
            ),
        ]
        indexes = [
            # Serves highest_step(session, device) directly.
            models.Index(
                fields=['session_id', 'device_key_id', 'step'],
                name='replay_high_step_idx',
            ),
            models.Index(fields=['received_at'], name='replay_received_idx'),
        ]

    def __str__(self):
        return f"{self.device_key_id}:{self.nonce} step {self.step}"


class StepHighWater(models.Model):
    """The furthest challenge step each device has had accepted in each session.

    Separate from `ReplayEntry`, and never pruned, for a reason that is easy to
    get wrong: entries expire on a retention schedule, and if the high-water mark
    were derived from them, pruning would forget how far a device had got and
    re-open the step regression the mark exists to refuse. This is one small
    integer per device per session, and a session is finite, so keeping it costs
    almost nothing while losing it costs a defence.

    The in-memory ledger in the protocol package makes the same choice, and it has
    to: an adapter that diverges here would pass its own tests and fail in the
    field only after the first prune.
    """
    session_id = models.CharField(max_length=32, validators=[_HEX_32])
    device_key_id = models.CharField(max_length=16, validators=[_HEX_16])
    step = models.PositiveIntegerField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'presence_step_high_water'
        constraints = [
            models.UniqueConstraint(
                fields=['session_id', 'device_key_id'],
                name='presence_high_water_once_per_device_session',
            ),
        ]

    def __str__(self):
        return f"{self.session_id}/{self.device_key_id} -> {self.step}"



class AttendanceProof(models.Model):
    """A signed offline attendance proof exactly as the handset submitted it.

    `proof_bytes` is stored verbatim and never re-encoded. Re-serialising it would
    make the stored signature unverifiable the first time anything about the
    encoder changed, and a proof nobody can re-check later is not evidence, just a
    record of having once believed something.

    The line this table draws, and the whole reason the columns are grouped the
    way they are: fields inside the signature are things the device *attested*,
    and can be relied on to the extent the device's key is trusted. Fields
    prefixed `claimed_` are the device's own conclusions - what status it thought
    it deserved, how confident it was, how many hops it counted - and those are
    recorded because a lie is evidence too, then recomputed from scratch on the
    server. Nothing in this table decides anything.
    """
    VALIDATION_CHOICES = (
        ('received', 'Received, not yet judged'),
        ('accepted', 'Re-derived and judged'),
        ('refused', 'Refused before scoring'),
        ('duplicate', 'Already submitted (idempotent retry)'),
    )

    presence_session = models.ForeignKey(
        PresenceSession, on_delete=models.CASCADE, related_name='proofs',
    )
    student = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='presence_proofs',
    )
    # Null when the proof named a key this deployment does not know. That is a
    # refusal, not a mystery: the row is kept so the refusal can be explained.
    device = models.ForeignKey(
        RegisteredDevice, on_delete=models.SET_NULL, related_name='proofs',
        null=True, blank=True,
    )
    # The attendance mark this proof produced, when it produced one. A refused or
    # unverified proof has no record, which is the difference between "we decided
    # against marking you" and "we marked you and are unsure".
    #
    # Many-to-one and not one-to-one, which was a modelling slip worth naming: the
    # constraint that a mark has exactly one proof is false. A student who was
    # recorded for review and later submits a proof that clears outright has two
    # proofs bearing on one mark, and so does anyone whose queue drains twice with
    # a fresh nonce each time. Under a unique index the second of those was an
    # IntegrityError on an ordinary action; the only ways to keep the index were to
    # blank the earlier proof's pointer or to stop recording the later one, and both
    # throw away the lineage the column exists for. `PresenceDecision.record` was
    # already shaped this way, so this also stops two tables describing the same
    # relationship with two different cardinalities.
    record = models.ForeignKey(
        AttendanceRecord, on_delete=models.SET_NULL, related_name='proofs',
        null=True, blank=True,
    )

    # Unique among *accepted* proofs only, which is a correction rather than a
    # loosening. A refused submission burns no nonce - that is deliberate, so the
    # genuine copy of a proof somebody replayed with a bad signature still works -
    # and a plain unique index on this column took that guarantee away again one
    # layer up: the first refused row made every later attempt at the same body
    # collide, so a single corrupted signature on a flaky link would answer a
    # student's own honest retry with the refusal forever, marking them absent for a
    # lesson they attended with no route back but a teacher override. Attempts are
    # therefore rows, one per attempt, and the constraint keeps saying the thing
    # that actually matters: one body is marked present at most once. The replay
    # ledger says that too, from the other side and against a different table.
    digest = models.CharField(max_length=64, validators=[_HEX_64])
    nonce = models.CharField(max_length=32, validators=[_HEX_32])
    step = models.PositiveIntegerField()
    proof_bytes = models.BinaryField()

    # --- inside the signature: attested by the device -----------------------
    biometric = models.SmallIntegerField(choices=BIOMETRIC_CHOICES, default=0)
    platform = models.SmallIntegerField(choices=PLATFORM_CHOICES, default=0)
    capabilities = models.PositiveIntegerField(default=0)
    captured_at_claim = models.BigIntegerField()

    # --- the device's own conclusions: recorded, never trusted --------------
    claimed_status = models.SmallIntegerField(choices=PRESENCE_STATUS_CHOICES, default=0)
    claimed_confidence_milli = models.PositiveIntegerField(null=True, blank=True)
    claimed_hop_count = models.PositiveIntegerField(null=True, blank=True)

    # --- server-derived: facts, not claims ----------------------------------
    received_at = models.BigIntegerField()
    # Receipt time minus the step the challenge belongs to. Derived from the
    # challenge chain rather than from any timestamp the handset supplied, which
    # is what makes it a measurement of how long the proof sat in a queue instead
    # of an assertion about it.
    queued_seconds = models.IntegerField(null=True, blank=True)
    validation_state = models.CharField(
        max_length=12, choices=VALIDATION_CHOICES, default='received',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_proofs'
        ordering = ['-received_at']
        constraints = [
            models.UniqueConstraint(
                fields=['digest'],
                condition=models.Q(validation_state='accepted'),
                name='presence_proof_digest_accepted_once',
            ),
        ]
        indexes = [
            models.Index(
                fields=['presence_session', 'student'], name='proof_sess_student_idx',
            ),
            models.Index(fields=['validation_state'], name='proof_state_idx'),
            models.Index(fields=['device', 'step'], name='proof_device_step_idx'),
            # The retry lookup: one digest, one student, one session. Indexed
            # because it now runs against a column that is no longer unique.
            models.Index(fields=['digest'], name='proof_digest_idx'),
        ]

    def __str__(self):
        return f"proof {self.digest[:12]} ({self.validation_state})"

    def __repr__(self):
        return "<AttendanceProof digest=%s state=%s proof_bytes=<%d bytes>>" % (
            self.digest, self.validation_state, len(bytes(self.proof_bytes or b'')),
        )


class RelayChainRecord(models.Model):
    """A submitted chain of custody, retained for audit.

    A chain is a sequence of signatures, each over the previous link's hash and a
    relay-scoped pseudonym, so it shows that a proof travelled through devices
    that were themselves inside the session's trust domain. It is evidence of
    participation in that domain and it is not, on its own, proof of being in the
    room: relays can be near a doorway, and a chain says nothing about metres.
    That distinction is the reason this is one input among several rather than the
    answer.

    Pseudonyms only. A chain that carried permanent student identities would
    broadcast a class roster to anyone with a scanner, so the relay identifiers
    here resolve to people only through this session, in this database.

    No chains are produced on this scope - the relay layer is designed and
    unbuilt - so the expected state of this table for now is empty.
    """
    proof = models.OneToOneField(
        AttendanceProof, on_delete=models.CASCADE, related_name='chain',
    )
    hop_count = models.PositiveIntegerField(default=0)
    chain_bytes = models.BinaryField()
    verified = models.BooleanField(default=False)
    # A gate reason code when verification refused the chain, blank when it held.
    refusal_code = models.CharField(max_length=64, blank=True)
    # Per-hop pseudonyms in order, as submitted. Session-scoped strings.
    hop_pseudonyms = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_relay_chains'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['verified', 'hop_count'], name='chain_ok_hops_idx'),
        ]

    def __str__(self):
        return f"chain of {self.hop_count} hop(s), {'verified' if self.verified else 'refused'}"


# Same reasoning as the wire vocabularies above: the calibration honesty states
# are defined by the config layer, and restating them here would let a database
# claim "field validated" that the loader has never heard of.
from .presence import config as _presence_config

CALIBRATION_CHOICES = tuple(
    (state, state.replace('_', ' ').capitalize())
    for state in sorted(_presence_config.CALIBRATION_STATES)
)


class PresenceDecision(models.Model):
    """The verdict, and enough of its working to defend it later.

    Written once from `presence.decide.Decision.describe()` and then left alone. A
    teacher may disagree with it - that is what `ManualOverride` is for - but the
    machine's own account of what it concluded and why is never edited, because a
    decision that can be quietly rewritten is not an audit trail.

    `audit` holds the whole `describe()` dictionary verbatim, including the policy
    thresholds and the fused block scores. The individual columns are a projection
    of that same dictionary, denormalised so the analytics layer and the teacher
    console can filter without unpacking JSON per row. The duplication is
    deliberate and one-directional: the snapshot is the source, the columns index
    it.

    On the version columns: there is no separate model version, because on this
    design the fusion model's identity *is* the config artifact that prices its
    evidence and sets its operating points. A second column naming the same fact
    would only be somewhere for the two to disagree.
    """
    proof = models.OneToOneField(
        AttendanceProof, on_delete=models.CASCADE, related_name='decision',
    )
    record = models.ForeignKey(
        AttendanceRecord, on_delete=models.SET_NULL, related_name='presence_decisions',
        null=True, blank=True,
    )

    status = models.SmallIntegerField(choices=PRESENCE_STATUS_CHOICES)
    # Log-odds accumulated across evidence blocks, in thousandths of a natural log
    # unit. An integer because the whole scoring path is integer arithmetic: a
    # decision must land on the same side of a threshold on every machine that
    # re-derives it, and floating point does not promise that.
    millinats = models.IntegerField()
    # Null whenever the score may only be ordered, not read as a probability.
    # That is the normal case while the model is uncalibrated: a number that looks
    # like 0.95 invites being read as "95% likely present", and it is not that
    # until field data says so. Nulling it is cheaper than explaining it away.
    confidence_milli = models.PositiveIntegerField(null=True, blank=True)
    ordering_only = models.BooleanField(default=True)
    ordering_reason = models.CharField(max_length=120, blank=True)

    # How much of the evidence the model can price was actually available, and how
    # much of what this handset could have supplied it did supply. Two different
    # questions: the first is about the deployment, the second about the device.
    coverage_pct = models.FloatField(null=True, blank=True)
    supplied_pct = models.FloatField(null=True, blank=True)

    reasons = models.JSONField(default=list, blank=True)
    evidence_present = models.JSONField(default=list, blank=True)
    evidence_missing = models.JSONField(default=dict, blank=True)

    refused = models.BooleanField(default=False)
    gate_code = models.CharField(max_length=64, blank=True)

    calibration = models.CharField(max_length=32, choices=CALIBRATION_CHOICES)
    config_version = models.CharField(max_length=64)
    # The canonical encoding the proof was signed under. A wire-format change must
    # be visible on every row it touched, because it changes what the bytes meant.
    codec_version = models.CharField(max_length=32, blank=True)
    room_profile_version = models.CharField(max_length=64, blank=True)

    # `decide.Decision.describe()`, verbatim.
    audit = models.JSONField(default=dict, blank=True)
    decided_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_decisions'
        ordering = ['-decided_at']
        indexes = [
            models.Index(fields=['status', 'decided_at'], name='dec_status_time_idx'),
            models.Index(fields=['refused', 'gate_code'], name='dec_refused_code_idx'),
            models.Index(fields=['config_version'], name='dec_config_idx'),
        ]

    def __str__(self):
        return f"{self.status_name} ({self.millinats} millinats)"

    @property
    def status_name(self):
        return _proof.STATUS_NAMES.get(self.status, 'unknown')

    @classmethod
    def from_decision(cls, decision, *, proof_row, record=None, room_profile_version=''):
        """Project a `decide.Decision` onto a row, in one place.

        Written here rather than in the view because the columns are an index into
        `audit` and nothing more: every one of them is a copy of a value in the
        snapshot, kept as a column so a review queue can be ordered and filtered
        without opening the JSON. Two callers projecting a decision by hand would
        eventually disagree with each other, and the disagreement would look like a
        decision that changed its mind after the fact.

        `codec_version` records the wire format the proof was encoded under. There is
        deliberately no separate `model_version`: the fusion model's identity *is*
        its config artifact, so a second name for the same fact is only somewhere for
        the two to drift apart.
        """
        return cls.objects.create(
            proof=proof_row,
            record=record,
            status=decision.status,
            millinats=decision.millinats,
            confidence_milli=decision.confidence_milli,
            ordering_only=decision.ordering_only,
            ordering_reason=decision.ordering_reason or '',
            coverage_pct=decision.coverage_pct,
            supplied_pct=decision.supplied_pct,
            reasons=list(decision.reasons),
            evidence_present=list(decision.evidence_present),
            evidence_missing=dict(decision.evidence_missing),
            refused=decision.refused,
            gate_code=decision.gate_code or '',
            calibration=decision.calibration,
            config_version=decision.config_version,
            codec_version=_codec.CODEC_VERSION,
            room_profile_version=room_profile_version,
            audit=decision.describe(),
        )


class ManualOverride(models.Model):
    """A human overruling the machine, recorded as an addition and never a rewrite.

    The teacher is the session authority and must be able to mark a student
    present when the system got it wrong - a flat battery, a handset with no
    biometric hardware, a student who was plainly sitting there. What must not
    happen is the original decision disappearing, because then nobody can tell a
    system that works from a system that is overridden into looking like it works.

    So this table is append-only in practice: it stores who acted, when, why, what
    the machine had concluded, and what they changed it to, plus the full decision
    snapshot as it stood at the moment of the override. A high override rate is
    itself a finding, and it is only measurable because the original survives.
    """
    decision = models.ForeignKey(
        PresenceDecision, on_delete=models.CASCADE, related_name='overrides',
    )
    record = models.ForeignKey(
        AttendanceRecord, on_delete=models.SET_NULL, related_name='presence_overrides',
        null=True, blank=True,
    )
    actor = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name='presence_overrides_made',
    )
    original_status = models.SmallIntegerField(choices=PRESENCE_STATUS_CHOICES)
    new_status = models.SmallIntegerField(choices=PRESENCE_STATUS_CHOICES)
    # Required. An override with no stated reason is indistinguishable from a
    # mistake, and the person best placed to say why is the one doing it.
    reason = models.TextField()
    # The machine decision as it stood, copied here so it survives even if the
    # decision row is later deleted by a cascade nobody anticipated.
    original_decision = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_manual_overrides'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['actor', 'created_at'], name='ovr_actor_time_idx'),
            models.Index(fields=['new_status'], name='ovr_new_status_idx'),
        ]

    def __str__(self):
        return f"{self.actor.username}: {self.original_status} -> {self.new_status}"


class ConfigVersion(models.Model):
    """The registry of parameter artifacts that have been allowed to decide.

    Thresholds and evidence weights live in versioned artifacts rather than
    scattered through the code, so that changing what counts as present is a
    reviewable act with a name and a date attached. This table is where that act
    is recorded: the artifact as activated, the digest of it, the cross-check
    results that let it through, and who let it through.

    `calibration` is the honesty field and it is not decoration. An artifact
    fitted on simulator output says so, and keeps saying so on every decision it
    produces, until real field data replaces it. A confidence figure from an
    uncalibrated artifact orders proofs; it does not estimate a probability.
    """
    version = models.CharField(max_length=64, unique=True)
    artifact = models.JSONField(default=dict)
    digest = models.CharField(max_length=64, validators=[_HEX_64])
    calibration = models.CharField(max_length=32, choices=CALIBRATION_CHOICES)
    # What `config.cross_check()` said when this artifact was activated: the
    # reachability and ordering checks that stop an artifact whose present
    # threshold no admissible proof could ever reach.
    activation_checks = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)

    is_active = models.BooleanField(default=False)
    activated_at = models.DateTimeField(null=True, blank=True)
    activated_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, related_name='presence_configs_activated',
        null=True, blank=True,
    )
    retired_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'presence_config_versions'
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['is_active'], condition=models.Q(is_active=True),
                name='presence_one_active_config',
            ),
        ]

    def __str__(self):
        state = 'active' if self.is_active else 'inactive'
        return f"{self.version} [{self.calibration}] ({state})"
