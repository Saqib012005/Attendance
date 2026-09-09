# Attendance Management System

A comprehensive attendance tracking system built with **Django REST Framework** (Backend) and **Flutter** (Frontend), using **PostgreSQL** database and **Docker** for containerization.

##  Features

###  Teacher Features
- Create and manage classes, enrollments and academic terms
- Generate QR codes for attendance sessions
- Real-time session monitoring with countdown timer
- Manual and bulk attendance correction
- Layered analytics: standing, trends, at-risk triage, schedule patterns
- Integrity flags for anomalous marking patterns
- Announcements to a class or a cohort

###  Student Features
- Scan QR codes to mark attendance
- Visual pattern verification when a session requires it
- View enrolled classes and attendance history
- Personal analytics with an attendance forecast

###  Admin Features
- Manage users, classes and semesters through a dedicated API surface
- Institution-level statistics

###  Authentication & Authorization
- JWT-based authentication
- Role-based access control (Student, Teacher, Admin)
- Secure password hashing

###  Offline support
- Queued marking, pattern verification and whole-session sync from the client,
  drained when connectivity returns

###  Presence verification (in progress)
A signed, single-use, offline-capable attendance proof that the server re-derives
rather than trusts - replacing a QR payload where possessing the session UUID was
enough to be marked present. It is **not** proof that a student was physically in
the room, and the difference matters. See
[Presence verification](#presence-verification) below for what it does and does
not establish.

---

##  Tech Stack

### Backend
- **Framework**: Django 5.2.7
- **API**: Django REST Framework 3.16.1
- **Database**: PostgreSQL 15 (SQLite for local development and tests)
- **Authentication**: JWT (djangorestframework-simplejwt)
- **QR Code**: qrcode 7.4.2 + Pillow 10.4.0
- **Cryptography**: `cryptography` 50.0.0 (Ed25519, HMAC-SHA256, HKDF) and
  `cbor2` 6.1.4 for the canonical encoding of anything that gets signed. No
  primitive is implemented here; the presence layer is a thin wrapper over that
  library.
- **Vision**: `google-genai` + OpenCV (headless) for the pattern-verification
  reference check
- **Analytics**: standard library only. `attendance/analytics/` deliberately
  avoids numpy/scipy/pandas on the decision path so a figure can be re-derived
  anywhere.

### Frontend
- **Framework**: Flutter 3.x
- **State Management**: mostly `StatefulWidget`; `provider` and `flutter_riverpod`
  are both present in `pubspec.yaml`, which is an inconsistency to resolve rather
  than a design
- **HTTP Client**: Dio
- **Storage**: Flutter Secure Storage; `sqflite` for the offline queues
- **QR Code**: `qr_flutter` (teacher) and `mobile_scanner` (student)

### DevOps
- **Containerization**: Docker & Docker Compose (`python:3.11-slim`)
- **Database Management**: pgAdmin 4
- **Version Control**: Git
- **CI/CD**: GitHub Actions -> Azure App Service. The backend workflow
  (`.github/workflows/main_presence.yml`) runs `manage.py check`, a
  `makemigrations --check` and the full test suite, and **gates build and deploy
  on all three**. Nothing deploys from a pull request or from a branch other than
  `main`.

---

## Prerequisites

Before you begin, ensure you have the following installed:

| Tool | Version | Download Link |
|------|---------|---------------|
| **Git** | Latest | [Download](https://git-scm.com/downloads) |
| **Docker Desktop** | Latest | [Download](https://www.docker.com/products/docker-desktop) |
| **Flutter SDK** | 3.0+ | [Download](https://flutter.dev/docs/get-started/install) |
| **Code Editor** | VS Code recommended | [Download](https://code.visualstudio.com/) |

### Verify Installations

```bash
# Check Git
git --version

# Check Docker
docker --version
docker-compose --version

# Check Flutter
flutter doctor
```

---

##  Quick Start Guide

### **Step 1: Clone the Repository**

```bash
git clone https://github.com/Sujan-Bhat/attendance.git
cd attendance
```

### **Step 2: Backend Setup**

#### 2.1 Create Environment File

```bash
cp backend/.env.example backend/.env
```

#### 2.2 Configure `.env` File

`backend/.env.example` documents every variable that is actually read, with the
generator commands for the two that need generating. The minimum for local work
is a secret key - **Django refuses to start without one**, by design:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

```ini
SECRET_KEY=<the value you just generated>
DATABASE_URL=postgres://postgres:postgres@db:5432/attend_db
DJANGO_DEBUG=True
```

Omit `DATABASE_URL` entirely to use SQLite at `backend/db.sqlite3` instead, which
is what the test suite does. See [Security Notes](#security-notes) for what must
be set before a deployment serves real traffic.


#### 2.3 Start Docker Services

```bash
# Build and start containers
docker-compose up -d --build

# Verify containers are running
docker-compose ps
```

**Expected Output:**
```
NAME                COMMAND                  STATUS              PORTS
attendance-db-1     "docker-entrypoint.s…"   Up (healthy)        0.0.0.0:5433->5432/tcp
attendance-web-1    "bash -c 'python man…"   Up                  0.0.0.0:8000->8000/tcp
attendance-pgadmin  "/entrypoint.sh"         Up                  0.0.0.0:5050->80/tcp
```

#### 2.4 Run Database Migrations

```bash
docker-compose exec web python manage.py makemigrations
docker-compose exec web python manage.py migrate
```

#### 2.5 Create Admin User

```bash
docker-compose exec web python manage.py createsuperuser
```

It prompts for **email first**, because `USERNAME_FIELD` on the user model is
`email`; `username` is a separate required field. Choose your own email rather
than `admin@example.com` - that address belongs to the seed script, which resets
its password every time it runs.

#### 2.6 Verify Backend

Open in browser:
- **API Ping**: http://localhost:8000/api/v1/ping/
- **Admin Panel**: http://localhost:8000/admin/
- **pgAdmin**: http://localhost:5050/

---

### **Step 3: Frontend Setup**

#### 3.1 Navigate to Flutter Project

```bash
cd frontend/attendance_app
```

#### 3.2 Install Dependencies

```bash
flutter pub get
```

#### 3.3 Run Flutter App

```bash
# Web Browser
flutter run -d chrome

# Android Emulator
flutter run -d android

# iOS Simulator (Mac only)
flutter run -d ios
```

---

##  Project Structure

```
attendance/
│
├── backend/                          # Django Backend
│   ├── attend_backend/              # Project Configuration
│   │   ├── settings.py              # Django settings
│   │   ├── urls.py                  # Main URL routing
│   │   └── wsgi.py                  # WSGI config
│   │
│   ├── attendance/                   # Main Application
│   │   ├── models.py                # Database models
│   │   │   ├── User                 # Custom user model
│   │   │   ├── StudentProfile       # Student details
│   │   │   ├── AcademicTerm         # Term dates + required attendance %
│   │   │   ├── Class                # Class/Course model
│   │   │   ├── Enrollment           # Student enrollments
│   │   │   ├── AttendanceSession    # QR session model
│   │   │   ├── AttendanceRecord     # Attendance entries
│   │   │   ├── Announcement         # Teacher -> class/cohort messages
│   │   │   ├── AttendanceFlag       # Integrity + presence findings
│   │   │   ├── InterventionLog      # Follow-up on an at-risk student
│   │   │   └── presence_*           # See "Presence verification" below
│   │   │
│   │   ├── serializers.py           # API serializers
│   │   ├── views.py                 # Core API endpoints
│   │   ├── admin_views.py           # Admin API surface
│   │   ├── analytics_views.py       # Analytics API surface
│   │   ├── presence_views.py        # Proof submission endpoint
│   │   ├── presence_ledger.py       # Replay ledger, Django-backed
│   │   ├── verification.py          # Pattern challenge + vision check
│   │   ├── analytics/               # Layered analytics engine
│   │   │   ├── context.py           # Term, thresholds, insufficient-data marker
│   │   │   ├── matrix.py            # Expectation set -> attendance matrix
│   │   │   ├── metrics.py           # Stdlib statistics (no numpy on this path)
│   │   │   ├── forecast.py          # Seeded Monte Carlo projection
│   │   │   ├── risk.py, health.py   # Risk bands, cohort health
│   │   │   ├── patterns.py          # Schedule patterns
│   │   │   ├── integrity.py         # Anomaly detection -> AttendanceFlag
│   │   │   └── insights.py          # Narrative layer
│   │   ├── presence/                # Presence protocol + crypto + fusion
│   │   ├── tests*.py                # See "Running the tests" below
│   │   └── migrations/              # Database migrations
│   │
│   ├── requirements.txt             # Python dependencies
│   ├── Dockerfile                   # Docker config
│   └── .env                         # Environment variables
│
├── frontend/attendance_app/          # Flutter Frontend
│   ├── lib/
│   │   ├── main.dart                # App entry point
│   │   │
│   │   ├── config/api_config.dart   # API base URL (see note below)
│   │   ├── core/api_client.dart     # HTTP client + token refresh
│   │   ├── models/analytics_models.dart
│   │   │
│   │   ├── screens/
│   │   │   ├── auth/                # login_screen, signup_screen
│   │   │   ├── dashboard/           # student_dashboard, teacher_dashboard,
│   │   │   │                        #   teacher_dashboard_mobile / _web
│   │   │   ├── common/              # custom_camera_screen
│   │   │   ├── student/             # qr_scanner, pattern_sessions,
│   │   │   │                        #   pattern_verification, my_classes,
│   │   │   │                        #   attendance_history, student_analytics,
│   │   │   │                        #   student_announcements, student_profile
│   │   │   ├── teacher/             # session_create, session_active,
│   │   │   │                        #   my_classes, add_students,
│   │   │   │                        #   teacher_analytics, teacher_announcements,
│   │   │   │                        #   teacher_attendance_history, teacher_profile
│   │   │   └── admin/               # admin_dashboard, manage_students,
│   │   │                            #   manage_teachers, student_list, teacher_list,
│   │   │                            #   semester_classes, admin_class_detail,
│   │   │                            #   reset_login, admin_profile
│   │   │
│   │   ├── services/                # auth, class, session, attendance,
│   │   │                            #   announcement, profile, analytics,
│   │   │                            #   storage, sync (offline queue drain)
│   │   │
│   │   ├── theme/analytics_theme.dart   # Design tokens - see note below
│   │   │
│   │   └── widgets/
│   │       ├── analytics/           # analytics_primitives, analytics_panels,
│   │       │                        #   analytics_animations
│   │       ├── teacher_web_layout.dart, admin_web_layout.dart
│   │       ├── teacher_drawer.dart, student_drawer.dart
│   │       ├── pattern_painter.dart # Draws the visual challenge
│   │       ├── offline_indicator.dart
│   │       └── magical_dashboard_card.dart, enhanced_dashboard_card.dart
│   │
│   └── pubspec.yaml                 # Flutter dependencies
│
└── docker-compose.yml               # Docker orchestration
```

Two notes on the client that will save you an hour each:

**`config/api_config.dart` hardcodes `isProduction = true`,** so a plain
`flutter run` points at the deployed Azure backend, not your local one. To run
against `manage.py runserver`, pass the base URL explicitly - and note the
override replaces the *whole* base, so it has to include `/api/v1`:

```bash
flutter run -d android --dart-define=API_BASE_URL=http://<your-lan-ip>:8000/api/v1
```

The override wins over `isProduction` everywhere, which is why it is the right
tool here rather than editing the constant and risking committing the edit.

**There are two visual languages in this codebase, and only one is the system.**
`theme/analytics_theme.dart` plus `widgets/analytics/` is the tokenised one -
radii 8/12/16/22, white cards on `#F7FAFC`, teal accents, semantic mark and risk
colours, reduced-motion aware, every chart a hand-written `CustomPainter` (there
is no charting package). The Figma-derived dashboard cards
(`enhanced_dashboard_card.dart`, `teacher_dashboard_web.dart`) use their own
radii, 2px saturated borders and pastel gradient fills. New work extends the
tokenised language and defines no colour, radius, shadow or duration of its own.
Note also that `fontFamily: 'Inter'` is named in several files but no font asset
is registered in `pubspec.yaml`, so all of it currently renders as Roboto.

---

## API Documentation

### Base URL
```
http://localhost:8000/api/v1
```

Everything below requires an `Authorization: Bearer <access token>` header except
the endpoints marked *public*. The **Role** column is the check performed
*inside* the view - DRF only enforces "authenticated" at the permission layer, so
an endpoint marked Teacher answers a student with `403`, not `401`.

### Authentication

| Method | Endpoint | Description | Role |
|--------|----------|-------------|------|
| POST | `/auth/register/` | Register a user | *public* |
| POST | `/auth/token/` | Log in, get access + refresh tokens | *public* |
| POST | `/auth/token/refresh/` | Refresh an access token | *public* |
| GET | `/auth/me/` | Current user | Any |
| GET | `/auth/check-student/` | Look up a student by email | Teacher |
| GET | `/ping/` | Liveness probe | *public* |

`/auth/register/` accepts `role` values `student` and `teacher` only; `admin` is
**refused with a 400**, and the serializer forces `is_staff` and `is_superuser`
to false regardless of what the body asked for. An admin account is provisioned
out of band - `createsuperuser`, or an existing admin via `/admin/users/create/`.
Both belts are deliberate: one stops the role, the other stops the privilege, and
a future serializer change that loosens either one still has to get past the
other.

### Class management

| Method | Endpoint | Description | Role |
|--------|----------|-------------|------|
| GET | `/classes/` | List the caller's classes | Teacher |
| POST | `/classes/` | Create a class | Teacher |
| GET / PUT / DELETE | `/classes/{id}/` | Read, update, delete a class | Teacher |
| GET | `/classes/{id}/students/` | Enrolled students | Teacher |
| POST | `/classes/{id}/add-student/` | Enrol a student | Teacher |
| PUT | `/classes/{id}/update-student/{student_id}/` | Edit a student's details | Teacher |
| DELETE | `/classes/{id}/remove-student/{student_id}/` | Unenrol a student | Teacher |
| POST | `/classes/join/` | Join a class by its code | Student |
| GET | `/students/my-classes/` | The caller's enrolments | Student |
| GET | `/students/my-attendance/` | The caller's attendance history | Student |

### Session management

| Method | Endpoint | Description | Role |
|--------|----------|-------------|------|
| POST | `/sessions/create/` | Open a session (QR or pattern mode) | Teacher |
| GET | `/sessions/active/` | The teacher's open sessions | Teacher |
| GET | `/sessions/student-active/` | Open sessions the student may mark in | Student |
| GET | `/sessions/{session_id}/` | Session details | Any enrolled |
| PATCH | `/sessions/{session_id}/edit/` | Edit a session | Teacher |
| POST | `/sessions/{session_id}/end/` | Close a session | Teacher |
| DELETE | `/sessions/{session_id}/delete/` | Cancel a session | Teacher |
| POST | `/sessions/{session_id}/mark/` | Mark attendance | Student |
| POST | `/sessions/{session_id}/upload-reference/` | Upload the teacher reference frame | Teacher |
| POST | `/sessions/verify-image/` | Submit a pattern photo for verification | Student |
| POST | `/sessions/sync-offline-pattern/` | Drain a queued offline pattern mark | Student |
| POST | `/sessions/sync-offline-session/` | Drain a queued offline session | Teacher |

### Attendance correction

Every path here is a teacher editing a record after the fact. A correction is a
legitimate act; a *pattern* of corrections is a signal, which is why the
integrity layer watches these rather than the API forbidding them.

| Method | Endpoint | Description | Role |
|--------|----------|-------------|------|
| GET | `/sessions/{session_id}/attendance/` | Per-student detail for one session | Teacher |
| POST | `/sessions/{session_id}/attendance/update-bulk/` | Bulk status change | Teacher |
| POST | `/sessions/{session_id}/mark-student/` | Mark one student manually | Teacher |
| POST | `/sessions/{session_id}/mark-all-present/` | Mark the whole roster present | Teacher |
| PUT | `/attendance/{record_id}/update/` | Change one record's status | Teacher |
| GET | `/teachers/attendance-history/` | Cross-class history | Teacher |

### Announcements

| Method | Endpoint | Description | Role |
|--------|----------|-------------|------|
| GET | `/announcements/` | Announcements visible to the caller | Any |
| POST | `/announcements/` | Publish an announcement | Teacher |

### Analytics

Read the honesty contract at the top of `attendance/analytics/__init__.py` before
consuming these. A figure that cannot be computed comes back as an explicit
insufficient-evidence marker, never as a plausible-looking number, and every
derived figure traces back to the observations that produced it.

| Method | Endpoint | Description | Role |
|--------|----------|-------------|------|
| GET | `/analytics/teacher/overview/` | Cohort matrix, metrics, health | Teacher |
| GET | `/analytics/teacher/at-risk/` | Ranked at-risk triage list | Teacher |
| GET | `/analytics/teacher/student/{student_id}/` | One student, own classes only | Teacher |
| GET | `/analytics/teacher/flags/` | Integrity flags | Teacher |
| POST | `/analytics/teacher/flags/scan/` | Run the integrity scan (writes flags) | Teacher |
| POST | `/analytics/teacher/flags/{flag_id}/resolve/` | Resolve a flag | Teacher |
| GET | `/analytics/student/overview/` | Own standing, trend, forecast | Student |
| GET | `/analytics/student/calendar/` | Own session calendar | Student |
| GET | `/analytics/student/simulate/` | Projected standing if N more are attended | Student |

The scan endpoint is deliberately `POST`. It persists `AttendanceFlag` rows, and a
`GET` that writes evidence rows turns a page refresh into a finding.

### Admin

Every endpoint here requires `is_staff`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/stats/` | Institution-wide counts |
| GET | `/admin/classes/summary/` | All classes with enrolment counts |
| GET | `/admin/classes/by-semester/{semester}/` | Classes in a semester |
| GET | `/admin/classes/{class_id}/detail/` | One class in full |
| PUT | `/admin/classes/{class_id}/update/` | Edit a class |
| DELETE | `/admin/classes/{class_id}/remove-student/{student_id}/` | Unenrol |
| GET | `/admin/students/by-semester/{semester}/` | Students in a semester |
| PATCH | `/admin/students/{student_id}/update/` | Edit a student |
| GET | `/admin/teachers/` | All teachers |
| PATCH | `/admin/teachers/{teacher_id}/update/` | Edit a teacher |
| GET | `/admin/users/{role}/` | Users by role |
| POST | `/admin/users/create/` | Create a user in any role |
| PATCH | `/admin/users/{user_id}/toggle-access/` | Enable or disable login |
| DELETE | `/admin/users/{user_id}/delete/` | Delete a user |

### Presence

| Method | Endpoint | Description | Role |
|--------|----------|-------------|------|
| POST | `/presence/proofs/` | Submit a signed attendance proof | Student |

One endpoint, because there is only one thing a client is allowed to do: hand over
a signed proof and be told what the **server** concluded from it. The client's own
view of the outcome travels as a claim and is never the verdict. See "Presence
verification" below for what that proof does and does not establish.

---

##  Docker Commands Reference

### Basic Commands

```bash
# Start all services
docker-compose up 

# Stop all services
docker-compose down

# Rebuild and start
docker-compose up -d --build

# View logs
docker-compose logs -f
docker-compose logs -f web    # Backend logs only
docker-compose logs -f db     # Database logs only

# Check container status
docker-compose ps

# Restart a specific service
docker-compose restart web
```

### Database Commands

```bash
# Run migrations
docker-compose exec web python manage.py makemigrations
docker-compose exec web python manage.py migrate

# Check migration status
docker-compose exec web python manage.py showmigrations

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Access Django shell
docker-compose exec web python manage.py shell

# Access PostgreSQL shell
docker-compose exec db psql -U postgres -d attend_db
```

### Cleanup Commands

```bash
# Stop and remove containers
docker-compose down
```



##  Database Schema

Django models are the source of truth; this is the shape, not the DDL. Read
`attendance/models.py` for field types, indexes and constraints.

### Users

```
- id (PK)
- username (unique), email (unique), password (PBKDF2 hash)
- role (student | teacher | admin)
- first_name, last_name, is_active, is_staff, date_joined
```

`StudentProfile` hangs off a student user one-to-one with roll number, semester
and section.

### AcademicTerms

```
- id (PK)
- name, academic_year, start_date, end_date
- required_attendance_pct        # institutional threshold, default 75.0
- is_active
```

The analytics layer takes its threshold from the active term. With **no term
row** it falls back to a documented default and reports
`threshold_source='default'` - the fallback is never presented as policy.

### Classes

```
- id (PK)
- class_code (unique), class_name, semester
- teacher_id (FK -> Users, role=teacher)
- term_id (FK -> AcademicTerms, nullable)
- expected_sessions_total, sessions_per_week   # nullable; drives forecasting
- created_at, updated_at
```

`Enrollment (class_obj, student, enrolled_at)` is the join table.

### AttendanceSessions

```
- id (PK), session_id (UUID, unique)
- class_obj_id (FK -> Classes), teacher_id (FK -> Users)
- class_type (qr | pattern)
- pattern_code, instruction_card, shape_data   # pattern mode only
- reference_image                              # teacher's reference frame
- start_time, duration_minutes, end_time
- qr_code_data (JSON text)
- status (active | expired | completed)
- created_at, updated_at
```

### AttendanceRecords

```
- id (PK)
- session_id (FK -> AttendanceSessions)
- student_id (FK -> Users)
- marked_at            # auto_now_add - a client cannot set this
- status (present | absent | pending_review)
- verification_score, verification_reasons
```

`unique_together (session, student)` is the duplicate-attendance backstop, and
`marked_at` being `auto_now_add` is what makes a backdated offline mark
impossible to write through any code path, not merely rejected by one of them.
`pending_review` is the status behind the amber mark in the UI: a record that
exists and is deliberately not yet counted either way.

### Integrity and follow-up

```
AttendanceFlag        session / class / student, flag_type, severity, score,
                      evidence (JSON), status (open|resolved|dismissed),
                      resolved_by, resolved_at
InterventionLog       announcement -> student, baseline vs follow-up attendance,
                      delta_points, control_delta_points, outcome
Announcement          sender, title, content, target_type, target_class,
                      min_attendance_threshold, is_urgent, recipients (M2M)
```

`AttendanceFlag` is the standing state of a student in a session, not a log: a
repeated finding updates the existing row. `InterventionLog` exists so "we
messaged the at-risk students" can be checked against a control group instead of
assumed to have worked.

### Presence tables

The presence layer adds its own tables, every one of them prefixed
`presence_` in the database. That prefix is not cosmetic: this repository's
history contains an abandoned branch that created `registered_devices`,
`attendance_verifications` and `attendance_audit_events`, and a development
database that followed both lineages still physically holds those tables with no
model in `HEAD`. A new model claiming one of those names would work on every
machine except the ones that mattered.

```
Room, RoomProfile, Anchor      Spatial entities. Specified and migrated; the
                               calibration data behind them does not exist yet,
                               so nothing reads them on this build.
RegisteredDevice               Binds a student to a device public key. Until
                               this existed, nothing tied a login to hardware.
PresenceSession, SessionEpoch  Rolling-challenge chain state per session.
PresenceObservation            Raw per-observation evidence inside the window.
                               Session-scoped and purged on session close.
ReplayEntry, StepHighWater     Nonce/sequence replay ledger.
AttendanceProof                The signed proof as submitted, its digest, and
                               the server's validation state. 1:1 with a record.
RelayChainRecord               The chain of custody as submitted, kept for audit.
PresenceDecision               Verdict, ordering score, reason codes, evidence
                               present/missing, and the config + calibration
                               versions that produced it.
ManualOverride                 Teacher override: actor, timestamp, reason,
                               original decision, new decision. The original
                               machine decision is never erased.
ConfigVersion                  Registry row per activated config artifact.
```

Two of those carry the whole audit argument. `PresenceDecision` records the
versions used, so a verdict can be re-derived later by the same rules that
produced it rather than by whatever the code does today. `ManualOverride` records
the override *alongside* the original rather than in place of it, because a system
whose corrections are indistinguishable from its conclusions cannot be audited at
all.

---

##  Presence verification

### What this replaces

Attendance used to be verified by an **unsigned QR payload**. `qr_code_data` was
plain JSON containing the session UUID, a two-digit "freshness" code and some
session metadata. There was no signature, no nonce, no expiry inside it and no
rolling challenge, so **possession of the session UUID was sufficient to be marked
present**. A screenshot forwarded to a friend in another building worked. The
offline path was worse: it wrote a client-supplied `timestamp` straight into
`marked_at` behind only a 24-hour window check, so a client could backdate its own
attendance; and a session synced more than 24 hours late marked every unmarked
enrolled student **present** by default.

Those holes are closed. What replaces them is a signed proof, and the honest
description of it is narrower than "we verify presence".

### What a proof establishes

Each accepted proof lets the **server** re-derive, from the proof itself, that:

- an **authenticated student account** produced it,
- on a **device bound to that account** by a key the server registered,
- inside an **open session** the teacher controls,
- committing to a **rolling challenge** the server issued, which expires in
  seconds and cannot be replayed, reordered or pre-computed,
- gated by a **local biometric check** whose result arrives as
  SUCCESS / FAILURE / CANCELLED and nothing else,
- with a **capture time consistent** with the challenge it answers,
- **exactly once** - a repeated digest is refused, and the refusal cannot
  overwrite an earlier accepted verdict.

It works with **no network at all**. The client builds and signs the proof
offline, queues it, and the server re-validates on sync. Client-reported
`status`, `confidence` and `hop_count` are recorded as *claims* and never trusted;
the verdict is always recomputed server-side.

### What a proof does NOT establish

**It is not proof that the student was physically in the room.**

A student standing outside the window, with a valid account, their own registered
device, a fresh challenge and a real fingerprint, is marked `PRESENT`. So is one
in the corridor, or the adjacent classroom. Nothing in the current build measures
where a device is; the spatial evidence that would - fixed BLE anchors and a
room-calibrated RF fingerprint - is specified and reserved in the data model, and
**not built**. It needs beacons in the room.

This is a known, accepted, documented gap, not an oversight, and it should survive
into anything said about this feature - including a demo. The improvement is real:
possessing a session UUID is no longer sufficient, forwarding a screenshot no
longer works, backdating is impossible, and a stolen password without the bound
device gets nowhere. That is a different claim from proof of physical presence, and
conflating the two would be the dishonest part.

### The four outcomes

| Verdict | Meaning |
|---|---|
| `PRESENT` | Enough independent evidence, no gate tripped |
| `SECONDARY` | Plausible but thin - ask for a second check, do not accuse |
| `NOT VERIFIED` | Evidence insufficient or absent. **Not** an accusation |
| `SUSPICIOUS` | Something forgery-shaped: bad signature, replayed challenge, unknown device |

`NOT VERIFIED` and `SUSPICIOUS` are deliberately different outcomes. A student on
an old handset that cannot supply some evidence must never land in the same bucket
as a forged signature. Missing evidence lowers confidence toward `SECONDARY`; it
is never treated as evidence *against* the student.

### How a verdict is reached

Two stages, in this order, and the order is the design:

1. **Hard gates.** Unknown or revoked device, unenrolled student, closed session,
   bad signature, expired or replayed challenge, uncommitted observation,
   duplicate proof - each is an immediate refusal with a reason code. These are
   not probabilistic inputs. Folding them into a score is how scoring systems get
   talked past.
2. **Fusion, only for proofs that cleared every gate.** Evidence is collapsed into
   four blocks that are *internally* correlated but roughly independent of each
   other - authentication, network presence, spatial, temporal - and the blocks
   accumulate log-likelihood ratios. Multiplying QR validity by session validity
   by challenge freshness as though they were independent signals would inflate
   confidence by counting one fact three times.

Arithmetic is in **millinats** - thousandths of a natural log-odds unit, as
integers - so a proof lands on the same side of a threshold on every machine that
re-derives it. Floating-point drift in an audit trail is not acceptable.

On this build the `network` and `spatial` blocks are **empty**: there is no BLE
evidence on any platform. The evidence vector reserves them, and a proof records
which evidence was present, which was missing, and *why* it was missing
(`unsupported` for a platform that cannot supply it, `reserved` for a mechanism
that does not exist yet). That distinction is what keeps a future build's numbers
comparable to today's.

### Confidence is an ordering, not a probability

The fusion parameters are **provisional and uncalibrated**. The active artifact is
labelled `2026.09-provisional` with calibration state `uncalibrated`, and it is
fitted on nothing yet - the weights are reasoned defaults, not measurements.

So a confidence figure is an **ordering only**. It ranks two proofs against each
other; it does not mean "95% probability this student was present". The API says
so explicitly: `ordering_only: true` and `confidence_milli: null` travel with
every decision until a calibration pass replaces them, and every decision records
the config and calibration versions that produced it.

**No accuracy figure is claimed.** Not 99%, not any number. Producing one honestly
needs a labelled field dataset across seating positions, handset models, class
densities and times of day, and that dataset does not exist. Until it does, targets
are stated as targets.

### Cryptography

Established primitives only, from the `cryptography` package: **Ed25519**
signatures, **HMAC-SHA256** for the challenge chain, **HKDF** for key derivation.
Nothing is implemented locally. Structs are encoded canonically with **CBOR** so
that the bytes a client signs are the bytes a server verifies, and a cross-language
test signs the same struct in Dart and verifies it in Python to keep it that way.

Key material comes from the environment (`PRESENCE_SIGNING_KEY`, with
`PRESENCE_RETIRED_SIGNING_KEYS` for verify-only keys during a rotation). A key's
identifier is *derived from the key*, so a rotated key gets a new id automatically
and an id inside a signed struct can be checked against the key that supposedly
produced it. Rotation is: add the new key as active, leave the old one retired
until every signature it made has expired, drop it. Nothing is re-signed.

### Privacy

- **No biometric data leaves the device or is stored.** No fingerprints, no face
  templates, no raw images. The protocol accepts one of three words.
- **Nothing broadcasts student identity.** Where relay is eventually built, the
  chain carries relay-scoped pseudonyms, never permanent identifiers, and never PII.
- **No permanent RF tracking database.** `PresenceObservation` rows are
  session-scoped and purged when the session closes. Nothing monitors a device
  outside an active attendance session, and nothing is retained to reconstruct
  where a student has been.
- **A teacher override never erases the machine decision.** It records actor,
  timestamp, reason, the original verdict and the new one, side by side.

### Not Bluetooth Mesh

When the relay layer is built it will be a **custom application-layer protocol over
BLE GATT and advertising**. It is not Bluetooth Mesh, does not implement the Mesh
profile, and claims no compliance with it - Mesh provisioning is far too heavyweight
for a trust domain created and destroyed every fifty minutes, and Android carries no
platform Mesh stack. Relay will be **Android-only and opportunistic**: iOS
background peripheral advertising cannot carry it, Web Bluetooth has no peripheral
role at all, and a meaningful share of Android devices fail at peripheral mode,
advertiser slots or OEM battery management. It can only ever raise confidence, never
be a precondition for `PRESENT`, or a compliant student with the wrong handset
becomes permanently unverifiable.

---

##  Running the tests

```bash
cd backend
SECRET_KEY=dev-only python manage.py test attendance -v 2
```

`SECRET_KEY` must be present in the environment or the settings module refuses to
import - that is the fail-closed behaviour described under Security Notes, and it
applies to the test runner too. Any value works for a test run; use a throwaway
one, never the deployment's.

On Windows, if you have a global `PYTHONPATH` pointing at another Django checkout,
use the helper that clears it for the one command:

```powershell
cd backend
.\dev.ps1 python manage.py test attendance -v 2
```

The whole suite is **914 tests** and takes roughly six minutes, most of it in the
endpoint tests, which sign real Ed25519 proofs rather than mocking the crypto.
Narrow it while iterating:

```bash
python manage.py test attendance.tests_presence_gates -v 2      # one module
python manage.py test attendance.tests_presence_endpoint.DisclosureTests
```

A `UserWarning: No directory at: .../staticfiles/` during the run is expected -
WhiteNoise looking for collected static files that a test run has no reason to
build.

### What is where

| Module | Covers |
|---|---|
| `tests.py` | The layered analytics engine, end to end |
| `tests_marking.py` | The legacy marking path: QR, pattern, offline sync, teacher correction |
| `tests_presence_keys.py` | Key hierarchy, derivation, rotation |
| `tests_presence_codec.py` | Canonical encoding - byte-exact, because signatures depend on it |
| `tests_presence_challenge.py` | Rolling challenge chain, epochs, expiry, accept window |
| `tests_presence_origin.py` | Teacher origin payload build and verify |
| `tests_presence_chain.py` | Relay chain of custody |
| `tests_presence_replay.py` | Nonce, sequence and duplicate rejection |
| `tests_presence_proof.py` | Proof schema, signing, digest |
| `tests_presence_gates.py` | The hard rejects, and their ordering |
| `tests_presence_features.py` | Observation window to sparse evidence vector |
| `tests_presence_fusion.py` | Block decomposition and score accumulation |
| `tests_presence_decide.py` | Verdict, reason codes, refusal handling |
| `tests_presence_models.py` | Constraints the database itself enforces |
| `tests_presence_config.py` | Config artifact validity, and the hygiene check below |
| `tests_presence_endpoint.py` | `POST /presence/proofs/` including authorization and disclosure |

Three of those are load-bearing in a way worth naming, because they test rules
rather than behaviour:

- **`tests_presence_config.HygieneTests`** fails if a tuned numeric threshold
  appears anywhere in the presence code outside `presence/config/`. Thresholds are
  policy; scattering them through modules is how a system ends up with two
  disagreeing definitions of the same limit and no way to tell which one ran.
- **`tests_presence_endpoint.DisclosureTests`** asserts that no answer this
  endpoint gives to a handset names an internal check - and, in the other
  direction, that the two vocabularies are disjoint so the filter is neither
  vacuous nor impossible, and that a decision reason *does* reach the student.
  Without the second half, an endpoint that says nothing at all would pass.
- **`tests_presence_models.py`** tests constraints at the database level, so a
  claim like "one accepted proof per digest" is enforced where two workers racing
  cannot both win, not merely checked in Python where they can.

CI runs `manage.py check`, `makemigrations --check --dry-run` and the full suite
before anything is built or deployed. The migration check is there because a model
edited without its migration passes every test and then fails on deploy against a
database built from migrations.

---

## Contributing

We welcome contributions! 
Please open a pull request for fixes or improvements.
For larger changes, start a discussion first.

Please follow these steps:

### 1. Fork the Repository

Click the "Fork" button on GitHub

### 2. Clone Your Fork

```bash
git clone https://github.com/YOUR_USERNAME/attendance.git
cd attendance
```

### 3. Create a Feature Branch

```bash
git checkout -b feature/amazing-feature
```

### 4. Make Your Changes

- Write clean, documented code
- Follow existing code style
- Add tests for new features

### 5. Commit Your Changes

```bash
git add .
git commit -m "Add: amazing feature description"
```

**Commit Message Convention**:
- `Add:` New feature
- `Fix:` Bug fix
- `Update:` Code improvement
- `Docs:` Documentation changes
- `Test:` Adding tests

### 6. Push to Your Fork

```bash
git push origin feature/amazing-feature
```

### 7. Create Pull Request

Go to the original repository and click "New Pull Request"

## 📱 Mobile App Installation

### Building APK for Android

```bash
cd frontend/attendance_app

# Debug build - works out of the box
flutter build apk --debug
adb install build/app/outputs/flutter-apk/app-debug.apk

# Release build - requires signing material, see below
flutter build apk --release
```

**A release build fails closed without release signing material.** If
`android/key.properties` is absent, Gradle stops with an explicit error rather
than falling back to the debug keystore. That fallback used to be the default, and
it meant every "release" APK was signed with a key whose private half ships with
every Android SDK install and whose fingerprint differs per machine - so the App
Links declaration matched no key anyone held, and nobody else could ever publish
an update.

To build a release: copy `android/key.properties.example` to
`android/key.properties`, generate a keystore, and fill in the four values. The
example file carries the `keytool` invocations. Both the keystore and
`key.properties` are gitignored and must stay that way.

Debug builds are unaffected, and so is `flutter run` - the check waits until
Gradle knows a release task was actually requested.

Point a build at a specific backend with `--dart-define`, which overrides the
`isProduction` constant:

```bash
flutter build apk --release --dart-define=API_BASE_URL=https://your-host/api/v1
```

### Build outputs
- Debug: `build/app/outputs/flutter-apk/app-debug.apk`
- Release: `build/app/outputs/flutter-apk/app-release.apk`
- App bundle (what Play wants): `flutter build appbundle --release` ->
  `build/app/outputs/bundle/release/app-release.aab`

---

## Troubleshooting

### Backend Issues

**Port 8000 already in use:**
```bash
sudo lsof -i :8000
sudo kill -9 <PID>
```

**Database connection failed:**
```bash
docker-compose down
docker-compose up -d db
# Wait 10 seconds, then:
docker-compose up web
```

### Frontend Issues

**Flutter dependencies error:**
```bash
cd frontend/attendance_app
flutter clean
flutter pub get
```

**Android build fails:**
```bash
cd android
./gradlew clean
cd ..
flutter build apk --debug
```

**NDK license error:**
```bash
# Accept Android SDK licenses
yes | sdkmanager --licenses

# Or manually create license file
sudo mkdir -p /usr/lib/android-sdk/licenses
echo "24333f8a63b6825ea9c5514f83c2829b004d1fee" | sudo tee /usr/lib/android-sdk/licenses/android-sdk-license
```

### The three fail-closed errors

These are deliberate stops, not bugs. Each replaced a silent insecure fallback,
so the error message is the feature.

**`ImproperlyConfigured: SECRET_KEY is not set`** - the settings module will not
import without one. It applies to `runserver`, `migrate` and the test runner
alike. For a one-off command, put it in the environment:

```bash
SECRET_KEY=dev-only python manage.py migrate
```

**`Refusing to build a release without release signing material`** - Gradle
stopped because `android/key.properties` is missing. See
[Building APK for Android](#building-apk-for-android). Debug builds and
`flutter run` are unaffected.

**`refusing to seed: ...`** - `seed.py` declined. Either `DJANGO_DEBUG` is false
(and `SEED_ALLOW_PRODUCTION=1` was not set), or no password was supplied. Pass
`--password` or set `SEED_PASSWORD`; there is deliberately no default.

### Two that look like bugs and are not

**The app connects to Azure instead of your local backend.**
`lib/config/api_config.dart` hardcodes `isProduction = true`. Override the base
URL - including the `/api/v1` suffix - rather than editing the constant:

```bash
flutter run -d android --dart-define=API_BASE_URL=http://<your-lan-ip>:8000/api/v1
```

**Wrong Django, or a mysterious import error, on Windows.** A global `PYTHONPATH`
pointing at another Django checkout wins over this project's. `backend/dev.ps1`
clears it for one command:

```powershell
cd backend
.\dev.ps1 python manage.py test attendance
```

### Docker Issues

**Container fails to start:**
```bash
docker-compose down
docker system prune -a  # Warning: removes all unused images
docker-compose up --build
```

**pgAdmin not accessible:**
```bash
# Check pgAdmin logs
docker-compose logs pgadmin

# Restart pgAdmin
docker-compose restart pgadmin
```

---

## Security Notes

### Configuration that must be set before a deployment serves traffic

Several of these used to be advice. They are now enforced, so the failure mode
has moved from "quietly insecure in production" to "refuses to start" - which is
the trade this section is really about.

| Variable | Behaviour if unset | Set it to |
|---|---|---|
| `SECRET_KEY` | **The process refuses to boot.** There is no fallback. | 50+ random characters, unique per deployment |
| `DJANGO_DEBUG` | Defaults **False** | Leave unset in production |
| `ALLOWED_HOSTS` | Defaults to localhost only, so a real host 400s | Your hostname(s), comma-separated. The `*` wildcard is gone |
| `CORS_ALLOW_ALL_ORIGINS` | Defaults **False** | Leave unset. Django serves the Flutter web build itself, so the first-party client is same-origin |
| `CORS_ALLOWED_ORIGINS` / `CSRF_TRUSTED_ORIGINS` | Defaults include localhost dev origins | Your origins, if any third-party client exists |
| `SEED_ON_START` | Seeding is **skipped** | Leave unset. `=1` only for a throwaway environment |
| `ANDROID_CERT_FINGERPRINTS` | Empty, and `/.well-known/assetlinks.json` publishes an empty list | The SHA-256 fingerprint Play App Signing reports |
| `PRESENCE_SIGNING_KEY` | The presence layer cannot sign | A base64url Ed25519 seed, generated per deployment |

Generate a secret key:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

### Why those particular defaults

- **A missing `SECRET_KEY` stops the process.** A default here silently becomes
  the production signing key for sessions and password-reset links, and in a
  public repository that value is readable by anyone. Missing configuration
  should stop a deployment, not be papered over.
- **`ALLOWED_HOSTS` no longer contains `*`.** With the wildcard present Django
  disables Host-header checking entirely, which is what makes cache poisoning and
  poisoned password-reset links possible.
- **`CORS_ALLOW_ALL_ORIGINS` defaults off** because together with
  `CORS_ALLOW_CREDENTIALS = True` - which this project needs - it lets any origin
  make credentialed requests.
- **Seeding is opt-in and triple-guarded.** It previously ran on every container
  start, unconditionally reset `admin@example.com`, and printed the new password
  to the App Service log stream - against a publicly routed `/admin/`. It now
  refuses to run unless `SEED_ON_START=1` invites it, refuses when `DEBUG` is off
  unless `SEED_ALLOW_PRODUCTION=1` insists, and refuses without an explicit
  `--password` / `SEED_PASSWORD`. There is deliberately no default password. **If
  this project was ever deployed before those guards existed, treat
  `admin@example.com` as compromised and rotate it.**
- **Release signing is fail-closed.** `android/app/build.gradle.kts` throws if
  `android/key.properties` is absent, rather than falling back to the debug
  keystore. A release APK signed with a machine-local debug key cannot be
  updated by anyone else, and its fingerprint matches no App Links declaration.
  See `android/key.properties.example`.
- **`SECURE_PROXY_SSL_HEADER`, `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE`**
  switch on automatically when `DEBUG` is false; behind Azure's proxy the header
  is what makes Django see the request as HTTPS.

### Still your responsibility

1. Use a managed database with a strong password; never expose it publicly.
2. Terminate TLS in front of the app and never serve the API over plain HTTP.
3. Keep `.env` and `android/key.properties` out of version control - both are
   already in `.gitignore`, and both should be verified before a first push.
4. Rotate any credential that was ever committed, seeded or shared, including the
   seed superuser described above.

---

## Admin Panel Access

After creating superuser, access:

**Django Admin**: http://localhost:8000/admin/

Available sections:
- **Users**: Manage all users (students, teachers, admins)
- **Classes**: View and manage all classes
- **Enrollments**: Student class enrollments
- **Attendance sessions**: QR code sessions
- **Attendance records**: All marked attendance

---

## API Testing

### Using cURL

Two things trip people up here: registration requires a **`password2`**
confirmation field, and login authenticates by **email**, not username -
`USERNAME_FIELD` on the user model is `email`.

```bash
# Register a student. role must be "student" or "teacher"; "admin" is refused.
curl -X POST http://localhost:8000/api/v1/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "role": "student",
    "password": "securepass123",
    "password2": "securepass123"
  }'

# Log in with the EMAIL, not the username
curl -X POST http://localhost:8000/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "securepass123"
  }'

# The response carries access, refresh and a nested user object
curl -X GET http://localhost:8000/api/v1/auth/me/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Liveness, no auth needed
curl http://localhost:8000/api/v1/ping/
```

`POST /presence/proofs/` is deliberately not shown as a cURL example: its body is
a CBOR-encoded, Ed25519-signed struct, and hand-rolling one to try the endpoint
would mean reimplementing the client's canonical encoder. The test suite is the
worked example - see `tests_presence_endpoint.py`, which builds and signs real
proofs rather than mocking them.

### Using Postman

1. Set base URL `http://localhost:8000/api/v1`.
2. Log in, then put the `access` token in an `Authorization: Bearer` header.
3. Access tokens are short-lived; refresh at `/auth/token/refresh/` rather than
   logging in again.

---

## Mobile App Features

### QR Code Scanning
- Real-time QR code detection
- Automatic attendance marking
- Session validation
- Duplicate scan prevention

### Dashboard
- Attendance history
- Enrolled classes
- Session status
- Profile management

---



## Acknowledgments

- Django REST Framework documentation
- Flutter documentation
- Docker documentation
- QR code libraries contributors



