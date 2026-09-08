"""Proof submission: the one place a signed proof becomes attendance.

Almost everything in this module is a refusal to trust something. The client sends
bytes and a signature; the server re-derives the challenge from its own copy of the
session secret, checks the signature against the key the institution bound to that
student, re-runs the gates, re-extracts the evidence vector, re-fuses it and reaches
its own verdict. The device's own account of its status, confidence and hop count is
stored beside that verdict and never read into it - `decide.decide` cannot see a
claim even if a caller wanted it to, because `Cleared.claims` is not on its argument
list.

Three boundaries this module is responsible for, none of which the protocol package
can enforce on its own:

**The clock is ours.** `received_at` is the server's time. A queued proof's age is
receipt time minus the step its challenge belongs to, which is why backdating is not
available to a client here the way it was on the old marking path.

**A refusal is not a diagnosis a student gets to read.** The stored decision keeps
the exact reason code, because an administrator investigating an incident needs it.
The response carries the outcome and, for the handful of refusals a student can
actually act on, one plain sentence. Returning the whole vocabulary would document
the detection mechanics to the person probing them.

**A retried submission is not a second attempt.** An offline queue whose
acknowledgement was lost will send the same proof again, and that is the ordinary
case rather than an attack. A resubmission of a proof this same student already had
accepted is answered with the stored verdict; nothing new is recorded and no fresh
refusal is invented. A *different* proof reusing a burnt nonce is still refused.

What this endpoint does not do: it does not accept a proof on behalf of somebody
else. A courier carrying a peer's proof out of a room with no signal is the relay
design's business and will need its own authenticated envelope; until that exists,
a proof submitted under an account that does not own the signing device is an
authorization failure of the request and not a verdict about a student, so it
answers 403 and records nothing.
"""
import base64
import uuid

from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from .models import (
    AttendanceFlag,
    AttendanceProof,
    AttendanceRecord,
    Enrollment,
    PresenceDecision,
    PresenceObservation,
    PresenceSession,
    RegisteredDevice,
)
from .presence import (
    challenge as challenge_mod,
    config as config_mod,
    decide,
    features,
    fusion,
    gates,
    keys,
    proof as proof_mod,
    replay,
)
from .presence_ledger import DjangoLedger

# How much attached evidence one request may carry, taken from the wire schema
# rather than chosen here. A proof commits to at most this many observation digests,
# so an upload longer than the commitment cannot be covered by it - the cap is a
# restatement of the protocol's own shape and not a tuned value, which is why it is
# derived instead of written down. Picking a number in this file would have been a
# threshold in a view, and a smaller one would have silently refused evidence a
# compliant client had every right to attach.
MAX_OBSERVATIONS = proof_mod.MAX_OBSERVATIONS


# --- What a student may be told ---------------------------------------------

# The refusals a student can do something about. Each entry is a decision that the
# operational value of saying it outweighs what it reveals, and each is the kind of
# thing a help desk would say anyway. Everything absent from this table answers with
# the generic sentence for its outcome: not to be unhelpful, but because a refusal
# vocabulary returned to whoever is probing it is a map of the checks.
ACTIONABLE = {
    gates.UNKNOWN_DEVICE: 'This device is not registered. Register it and try again.',
    gates.DEVICE_REVOKED: 'This device has been revoked. Register your current device.',
    gates.DEVICE_NOT_ENROLLED: 'You are not enrolled in this class.',
    replay.TOO_OLD: 'This attendance was recorded too long ago to be accepted now.',
}

GENERIC = {
    decide.PRESENT: 'Attendance confirmed.',
    decide.SECONDARY: 'Recorded for review. Your teacher will confirm this one.',
    decide.NOT_VERIFIED: 'Attendance could not be verified. Please try again.',
    decide.SUSPICIOUS: 'Attendance could not be verified. Please speak to your teacher.',
}

# Which decisions become which kind of teacher-facing flag. A refused proof and an
# admitted-but-weak one are different events and are not merged: one says the
# evidence did not survive checking, the other that there was too little of it.
FLAG_FOR_ADMITTED = {
    decide.SECONDARY: ('presence_secondary', 'warning'),
    decide.SUSPICIOUS: ('presence_suspicious', 'critical'),
    decide.NOT_VERIFIED: ('presence_not_verified', 'warning'),
}
FLAG_FOR_REFUSED = {
    decide.SUSPICIOUS: ('presence_suspicious', 'critical'),
    decide.NOT_VERIFIED: ('presence_refused', 'warning'),
}

# What a verdict does to the attendance record itself. Only PRESENT asserts that the
# student attended. SECONDARY says "probably, and a human should look" - which is
# exactly what the existing `pending_review` status already means, so it is reused
# rather than joined by a fourth spelling of the same idea. The two negative
# outcomes deliberately write no record at all: an `absent` row would read as a
# finding that the student was elsewhere, when what happened is that this proof did
# not establish anything. The attempt survives as a decision and a flag, and the
# teacher's override path exists for the case where the student was in fact there.
RECORD_STATUS = {
    decide.PRESENT: 'present',
    decide.SECONDARY: 'pending_review',
}


# --- Helpers -----------------------------------------------------------------

def _bad_request(message):
    """A malformed request, which is a fact about the request and not about a
    student. No decision is recorded and no flag is raised."""
    return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)


def _decode(value, field):
    """Base64 in, bytes out, or a stated refusal. JSON cannot carry raw bytes."""
    if not isinstance(value, str) or not value:
        raise ValueError('%s is required and must be base64 text' % field)
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ValueError('%s is not valid base64' % field)


def _registration_resolver(session):
    """Turn a device key id into what the gates need to know about that binding.

    Three facts, kept apart: whether any device holds the key, whether it was
    revoked, and whether its owner is on this class's roster. Collapsing them would
    make a student who transferred out look like a stolen handset.
    """
    def resolve(device_key_id):
        row = RegisteredDevice.objects.filter(key_id=bytes(device_key_id).hex()).first()
        if row is None:
            return None
        enrolled = Enrollment.objects.filter(
            class_obj=session.class_obj, student=row.student,
        ).exists()
        return gates.Registration(
            verify_key=keys.VerifyKey.from_public_bytes(row.public_key_bytes()),
            revoked=not row.is_active,
            enrolled=enrolled,
        )
    return resolve


def _context(presence):
    """The session as the server knows it: its keys, when it opened, when it closed.

    `closed_at` comes from the presence row rather than from the proof, because
    nothing inside a challenge records that a teacher ended the session early - a
    step past the close is arithmetically perfect and still has to be refused.
    """
    closed_at = None
    if presence.closed_at is not None:
        closed_at = int(presence.closed_at.timestamp())
    return gates.SessionContext(
        session_keys=presence.session_keys(),
        session_start=presence.chain_start_unix,
        closed_at=closed_at,
    )


def _store_proof(presence, student, body, parsed, received_at, queued_seconds, state):
    """The submission as received, kept verbatim.

    `proof_bytes` is the exact body the signature was checked over, so a decision
    can be re-argued later against the bytes that produced it rather than against a
    re-encoding of them. The `claimed_*` columns are the device's own account, stored
    for comparison and read by nothing.
    """
    return AttendanceProof.objects.create(
        presence_session=presence,
        student=student,
        device=RegisteredDevice.objects.filter(
            key_id=parsed.device_key_id.hex(), student=student,
        ).first(),
        digest=parsed.digest().hex(),
        nonce=parsed.nonce.hex(),
        step=parsed.challenge_seq,
        proof_bytes=body,
        biometric=parsed.biometric,
        platform=parsed.platform,
        capabilities=parsed.capabilities,
        captured_at_claim=parsed.captured_at,
        claimed_status=parsed.claims.status,
        claimed_confidence_milli=parsed.claims.confidence_milli,
        claimed_hop_count=parsed.claims.hop_count,
        received_at=received_at,
        queued_seconds=queued_seconds,
        validation_state=state,
    )


def _attach_record(decision, session, student):
    """Create or update the attendance row a verdict justifies, or none.

    `update_or_create` because a student who was recorded for review and later
    submits a proof that clears outright should end up present, and because the
    unique constraint on (session, student) makes any other shape a crash.
    """
    wanted = RECORD_STATUS.get(decision.status)
    if wanted is None:
        return None
    record, _ = AttendanceRecord.objects.update_or_create(
        session=session, student=student,
        defaults={
            'status': wanted,
            # Deliberately not the fused score: `verification_score` is the old
            # 0..1 vision-check field that analytics already reads, and millinats
            # are not a probability. Left alone rather than filled with a number
            # that would be compared against a different scale.
            'verification_reasons': None,
        },
    )
    return record


def _raise_flag(decision, session, student, refused):
    """Put a weak or refused outcome in front of the teacher, once.

    Keyed on (session, student, type) by the existing unique constraint, so a
    handset retrying a broken proof updates one flag instead of filling the review
    queue with copies of itself.

    `score` stays at its default. The integrity engine's scores are calibrated
    anomaly strengths and this is not one of those - a presence flag is an event,
    not a measurement, and inventing a strength for it would put a fabricated number
    in the same column as real ones. A review queue orders these by severity and by
    the millinats in `evidence`.
    """
    table = FLAG_FOR_REFUSED if refused else FLAG_FOR_ADMITTED
    chosen = table.get(decision.status)
    if chosen is None:
        return None
    flag_type, severity = chosen
    flag, _ = AttendanceFlag.objects.update_or_create(
        session=session, student=student, flag_type=flag_type,
        defaults={
            'class_obj': session.class_obj,
            'severity': severity,
            'status': 'open',
            # The specific reason code lives here, where an administrator reads it
            # and a student does not.
            'evidence': {
                'gate_code': decision.gate_code,
                'reasons': list(decision.reasons),
                'millinats': decision.millinats,
                'evidence_present': list(decision.evidence_present),
                'evidence_missing': dict(decision.evidence_missing),
                'config_version': decision.config_version,
                'calibration': decision.calibration,
            },
        },
    )
    return flag


def _payload(proof_row, decision_row, *, duplicate=False):
    """What the student's handset is told, read back from the rows that were written.

    Built from the stored decision rather than the in-memory one on purpose. A
    retried submission has no in-memory decision to describe - only the row from the
    first attempt - and one reply builder means the answer a student reads is by
    construction the verdict the database holds, rather than a parallel account of
    it that could drift away from the record.

    Evidence categories are named because a student is owed an explanation of why a
    verdict came out weak, and because on this build every platform is missing the
    network and spatial evidence - a result screen that hid that would be claiming a
    completeness the system does not have. The refusal vocabulary is not named, for
    the reason `ACTIONABLE` gives: `decide.refuse` reports the gate code as the
    decision's one reason, so on a refusal that list is withheld whole instead of
    filtered, which is the only version of this that cannot leak by omission.
    """
    return {
        'status': proof_mod.STATUS_NAMES[decision_row.status],
        'message': (
            ACTIONABLE.get(decision_row.gate_code) or GENERIC[decision_row.status]
        ),
        'attendance': proof_row.record.status if proof_row.record_id else None,
        'duplicate': duplicate,
        # None whenever the artifact is not field-validated, which it is not. An
        # absent percentage is the honest answer: a score under uncalibrated weights
        # orders candidates and is not a probability.
        'confidence_milli': decision_row.confidence_milli,
        'ordering_only': decision_row.ordering_only,
        'ordering_reason': decision_row.ordering_reason,
        'reasons': [] if decision_row.refused else list(decision_row.reasons),
        'evidence_present': list(decision_row.evidence_present),
        'evidence_missing': dict(decision_row.evidence_missing),
        'config_version': decision_row.config_version,
        'calibration': decision_row.calibration,
    }


def _store_observations(presence, student, device, cleared):
    """Keep the attached evidence that verified, for as long as the session lasts.

    Written here and nowhere else, and deliberately short-lived: these rows go when
    `PresenceSession.purge_observations` runs at close, because a permanent record
    of which radios a student's handset could hear at 10:15 on a Tuesday is the
    movement database this design must not accumulate (§85).

    Nothing that resolves to a person goes into `payload` - a sighting carries a
    rotating ephemeral id and a hop carries a session-scoped pseudonym, and the
    association with the student is the foreign key on a row with a deletion date.

    Evidence that did *not* verify is not stored. `Cleared.dropped` exists so that
    "no relay evidence" and "relay evidence that failed to verify" are never the
    same record, and its home is `RelayChainRecord.refusal_code`, which arrives with
    the relay layer. On this scope no observations are produced at all, so there is
    nothing to drop; inventing a column for it now would be guessing at the shape of
    a payload nobody has defined yet.
    """
    step = cleared.signed.proof.challenge_seq
    rows = [
        PresenceObservation(
            presence_session=presence, student=student, device=device,
            kind=kind, step=step,
            observed_at_claim=item.observed_at, payload=item.describe(),
        )
        for kind, group in (('origin', cleared.sightings), ('relay', cleared.hops))
        for item in group
    ]
    if rows:
        PresenceObservation.objects.bulk_create(rows)
    return len(rows)


def _stored(presence, student, digest):
    """The *accepted* proof and verdict already on file for this digest, or None.

    Scoped to the submitting student as well as the digest so that a lookup can
    never hand one student another's verdict, even though the ownership check above
    should already have made that unreachable. Two independent reasons a request
    cannot read somebody else's decision is the right number.

    Accepted only, and that word is the whole point of the filter. A refusal is a
    verdict on one submission, not on the body it carried: a copy whose signature
    did not verify says nothing about whether a correctly signed copy of the same
    bytes should be admitted, which is exactly why the refused path burns no nonce.
    Treating a stored refusal as the answer here would have taken that back - one
    corrupted signature, and the student's own honest retry is answered with the
    refusal for good. So a refusal never short-circuits a fresh attempt, and the
    thing that stops a body being marked present twice stays where it belongs: the
    replay ledger, and the accepted-only uniqueness constraint beside it.
    """
    row = AttendanceProof.objects.filter(
        presence_session=presence, student=student, digest=digest,
        validation_state='accepted',
    ).select_related('record', 'decision').first()
    if row is None:
        return None
    stored = getattr(row, 'decision', None)
    return None if stored is None else (row, stored)


def _admit(presence, student, body, cleared, decision, received_at):
    """Write everything an accepted proof produces, in one place.

    Order matters once: the attendance row is created before the decision row, so
    the decision can point at the mark it justified. A decision with a null record
    then means exactly one thing - this verdict asserted no attendance - rather than
    two things, one of which is a write that half-finished.
    """
    parsed = cleared.signed.proof
    proof_row = _store_proof(
        presence, student, body, parsed, received_at,
        cleared.receipt.queued_seconds, 'accepted',
    )
    _store_observations(presence, student, proof_row.device, cleared)
    record = _attach_record(decision, presence.session, student)
    if record is not None:
        proof_row.record = record
        proof_row.save(update_fields=['record'])
    decision_row = PresenceDecision.from_decision(
        decision, proof_row=proof_row, record=record,
        room_profile_version=(
            presence.room_profile.calibration_version
            if presence.room_profile_id else ''
        ),
    )
    _raise_flag(decision, presence.session, student, refused=False)
    return proof_row, decision_row


def _refused(presence, student, error, parsed, body, received_at, policy):
    """Record a refusal as a first-class outcome, with no attendance row.

    The submission is kept even though it did not survive the gates. A refusal that
    left no trace would make "nobody tried" and "somebody tried with a forged proof"
    the same state of the database, and the second is the one an investigation needs.

    `parsed` here came from the unverified peek, so its columns are the device's
    unchecked account of itself. That is exactly what they are for: `proof_bytes`
    holds the verbatim submission and the columns index it, so nothing is asserted
    by storing them.

    `queued_seconds` stays null. It is receipt time minus the step the challenge
    belongs to, and a proof refused before its challenge was re-derived has no
    established step - a number computed from the handset's own claim would be a
    measurement in a column reserved for server-derived facts.
    """
    decision = decide.refuse(error, policy=policy)
    proof_row = _store_proof(
        presence, student, body, parsed, received_at, None, 'refused',
    )
    decision_row = PresenceDecision.from_decision(
        decision, proof_row=proof_row,
        room_profile_version=(
            presence.room_profile.calibration_version
            if presence.room_profile_id else ''
        ),
    )
    _raise_flag(decision, presence.session, student, refused=True)
    return proof_row, decision_row


def _answer_refusal(error, presence, student, parsed, body, digest, received_at, policy):
    """Answer a gate refusal: with the stored verdict if there is one, else record it.

    `replay` refuses a repeated digest, and `decide.IDEMPOTENT` is the set of codes
    it says a caller must not record as a fresh verdict - so the first thing tried is
    the verdict already on file, which is how a lost acknowledgement stops being able
    to overwrite a PRESENT with the NOT VERIFIED that a repeated digest would
    otherwise earn. `submit_proof` looks that up before the gates run; this looks it
    up again because two workers draining one queue can both pass that check and meet
    the ledger instead, and only one of them can win there.

    Everything else is recorded as the refusal it is - including a repeated digest
    the ledger remembers but has no accepted proof row for, after a retention prune
    say, where the honest answer is the refusal itself and not a verdict invented to
    look idempotent. Refused attempts are rows, one per attempt: a body resubmitted
    after a failed signature check is a second attempt and is written down as one,
    because a refusal that silently returned the previous refusal would make one
    forged submission and fifty look identical.
    """
    if error.code in decide.IDEMPOTENT:
        already = _stored(presence, student, digest)
        if already is not None:
            return Response(_payload(*already, duplicate=True))
    try:
        with transaction.atomic():
            stored = _refused(
                presence, student, error, parsed, body, received_at, policy,
            )
    except IntegrityError:
        # Left in place for the narrow race it names: another worker committed the
        # *accepted* row for this digest between the lookup above and this insert,
        # and the accepted-only uniqueness constraint is what stops two of those
        # existing. If that is what happened, the answer is that worker's verdict
        # rather than a database error. Anything else re-raises, because a refusal
        # that cannot be written is a defect and not a state to paper over.
        already = _stored(presence, student, digest)
        if already is None:
            raise
        return Response(_payload(*already, duplicate=True))
    return Response(_payload(*stored))


# --- Challenge issuance -------------------------------------------------------

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def session_challenge(request, session_id):
    """The challenge current right now for one session, for its own teacher's screen.

    `GET`, and it writes nothing. `challenge.issue` is a pure function of the session
    keys and the step index, so calling it twice inside one step returns byte-identical
    bytes; there is no nonce to burn and no row to insert. That matters because the
    teacher's screen polls this on every step boundary for the length of a lesson, and
    because a `GET` that wrote evidence rows would turn a page refresh into a finding -
    the mistake the existing integrity-scan endpoint still makes.

    **The teacher who owns the session, and nobody else.** Not students, and not other
    teachers. The QR exists so that seeing it requires being in the room looking at the
    screen; an endpoint that served the same bytes over the network to any authenticated
    account would hand the student in the corridor the one thing the room was supposed
    to gate, and no amount of signing downstream recovers that. This is the tightest
    permission in the layer and it is deliberately tighter than the one on the session's
    own detail view.

    What crosses the wire is the signed payload, the short code, and three instants. Not
    `root_secret`, not `signing_seed`, not the epoch key, not the raw MAC: the response
    is built from the `Challenge` dataclass, which holds none of them, and the session
    keys are constructed, used and dropped inside this function.

    The timing comes from the session's *pinned* artifact rather than the active one.
    `gates` re-derives the challenge under the pinned artifact when the proof arrives,
    and `step_seconds` and `steps_per_epoch` are inputs to which challenge a moment
    maps to - so issuing under a newer artifact would display a code the server would
    then correctly refuse to recognise. Activating a re-tuned artifact mid-lesson must
    not break the lesson.
    """
    if getattr(request.user, 'role', None) != 'teacher':
        return Response(
            {'error': 'Only the teacher running a session may read its challenge.'},
            status=status.HTTP_403_FORBIDDEN,
        )
    presence = PresenceSession.objects.select_related('session').filter(
        session__session_id=session_id, session__teacher=request.user,
    ).first()
    if presence is None:
        # One answer for "no such session", "not your session" and "a session older
        # than this layer". Distinguishing them would let a teacher enumerate which
        # session ids exist and which colleague owns them, and none of the three is
        # actionable differently by the caller.
        return Response(
            {'error': 'No presence session found for this id.'},
            status=status.HTTP_404_NOT_FOUND,
        )
    if presence.closed_at is not None:
        # Arithmetically there is still a challenge for this instant. It would be
        # useless: the session-open gate refuses any step whose window begins after
        # the close, so every proof built from it would be refused, and the student
        # would read that refusal as their own failure. Say the session is over.
        return Response(
            {'error': 'This session has ended.'},
            status=status.HTTP_409_CONFLICT,
        )
    try:
        artifact = presence.artifact()
    except config_mod.ConfigError as exc:
        return Response(
            {'error': 'This session was opened under configuration %r, which this '
                      'server cannot load: %s' % (presence.config_version, exc)},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    timing = challenge_mod.Timing.from_artifact(artifact)
    now = int(timezone.now().timestamp())
    try:
        current = challenge_mod.issue(
            presence.session_keys(),
            session_start=presence.chain_start_unix,
            at=now,
            timing=timing,
        )
    except challenge_mod.ChallengeError as exc:
        # The only reachable one is NOT_YET_VALID, for a session scheduled ahead.
        # A teacher opening the screen early is a normal thing to do and gets told
        # the session has not started, not an error page.
        return Response(
            {'error': str(exc), 'code': exc.code},
            status=status.HTTP_409_CONFLICT,
        )
    return Response({
        'payload': base64.b64encode(current.payload).decode('ascii'),
        'display_code': current.display_code(),
        'issued_at': current.issued_at,
        # When this stops being the current step. Sent as an instant rather than as
        # `step_seconds`, so the screen never has to hold a copy of a tuned parameter
        # to know when to redraw - the value stays in the artifact where it belongs.
        'refresh_after': current.issued_at + timing.step_seconds,
        # Later than `refresh_after` on purpose: a scan that straddles a rotation is
        # still accepted, so the client may keep displaying until here if it must.
        'expires_at': current.expires_at,
        'protocol_version': challenge_mod.PROTOCOL_VERSION,
        'config_version': artifact.version,
    })


# --- The endpoint -------------------------------------------------------------

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def submit_proof(request):
    """Accept one signed proof and answer with the server's own verdict.

    The session is read from inside the signed body, not from the URL. A proof names
    the session it was built for, that name is covered by the signature, and
    `proof.verify` refuses a body whose session does not match the keys it was
    checked against - so a path parameter would add a second source for one fact and
    a way for the two to disagree.

    Everything durable happens inside one transaction. The reason is specific: the
    replay ledger burns this proof's nonce as the last step of `gates.clear`, and a
    crash between that write and the verdict would leave a legitimate student holding
    a proof that can never be submitted again and was never ruled on. Rolling the
    nonce back with the verdict is the only version of this that cannot lock somebody
    out of their own attendance.
    """
    if getattr(request.user, 'role', None) != 'student':
        # Not a verdict. A teacher account posting a proof is a client aimed at the
        # wrong endpoint, and answering it with a decision would file an attendance
        # outcome against somebody who was never claiming to attend.
        return Response(
            {'error': 'Only a student may submit an attendance proof.'},
            status=status.HTTP_403_FORBIDDEN,
        )

    body = request.data if isinstance(request.data, dict) else {}
    try:
        proof_bytes = _decode(body.get('proof'), 'proof')
        signature = _decode(body.get('signature'), 'signature')
        attached = body.get('observations') or []
        if not isinstance(attached, list):
            raise ValueError('observations must be a list of base64 text')
        if len(attached) > MAX_OBSERVATIONS:
            raise ValueError(
                'at most %d observations may be attached to one proof'
                % MAX_OBSERVATIONS
            )
        observations = [
            _decode(item, 'observations[%d]' % index)
            for index, item in enumerate(attached)
        ]
    except ValueError as exc:
        return _bad_request(str(exc))

    try:
        peek = proof_mod.parse(proof_bytes)
    except proof_mod.ProofError as exc:
        # No durable row and no verdict. An unreadable body names no session, and
        # every presence table hangs off one, so there is physically nothing to
        # record this against - and nothing to rule on either: a handset sending
        # bytes this server cannot decode has a client defect, which is not an
        # attendance finding about the person holding it. Answering with a status
        # would also make an unauthenticated-shaped mistake look like a verdict, and
        # let anyone with an account write a decision row per malformed request.
        return _bad_request('proof could not be read: %s' % exc)

    presence = PresenceSession.objects.select_related(
        'session', 'session__class_obj', 'room_profile',
    ).filter(session__session_id=uuid.UUID(bytes=peek.session_id)).first()
    if presence is None:
        # Either no such session or one created before this layer existed. Both are
        # facts about the request; neither says anything about the student.
        return Response(
            {'error': 'No presence session matches this proof.'},
            status=status.HTTP_404_NOT_FOUND,
        )
    session = presence.session

    try:
        # The artifact the lesson ran under, not the one deployed today. Every
        # window, weight and threshold below comes from this one object, so a
        # threshold activated since the lesson cannot re-decide a proof that was
        # queued before it existed.
        artifact = presence.artifact()
    except config_mod.ConfigError as exc:
        # A server fault, answered as one: no durable row, no verdict, no refusal
        # filed against the student, and no nonce burned - the ledger write is the
        # last step of `gates.clear` and this returns before it. The queued proof
        # stays queued and the next attempt succeeds once the artifact is restored,
        # which is the recoverable shape. Deciding under a substitute artifact would
        # be the alternative, and it would produce a verdict nobody could re-derive
        # from the version the record names.
        return Response(
            {'error': 'This session was opened under configuration %r, which this '
                      'server cannot load: %s' % (presence.config_version, exc)},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    timing = challenge_mod.Timing.from_artifact(artifact)
    bounds = replay.Bounds.from_artifact(artifact)
    policy = decide.Policy.load(artifact)
    weights = fusion.Weights.load(artifact)

    key_id = peek.device_key_id.hex()
    owner = RegisteredDevice.objects.filter(key_id=key_id).values_list(
        'student_id', flat=True,
    ).first()
    if owner is not None and owner != request.user.id:
        # A proof signed by somebody else's device, submitted under this account.
        # That is an authorization failure of the request, not a verdict about
        # either student: nothing is recorded, and in particular no refusal is filed
        # against the device's real owner, who may have done nothing at all.
        #
        # Carrying a classmate's proof out of a room with no signal is a real and
        # legitimate case, and it needs the relay design's own authenticated
        # envelope - a courier's own signature over the proof it is carrying. Until
        # that exists this endpoint refuses rather than guesses.
        return Response(
            {'error': 'This proof was signed by a device registered to another '
                      'student. It must be submitted by its owner.'},
            status=status.HTTP_403_FORBIDDEN,
        )
    # An unregistered key is deliberately *not* refused here. It is a real verdict
    # (`gates.UNKNOWN_DEVICE`), the gates raise it, and it belongs in the record.

    student = request.user
    digest = peek.digest().hex()
    already = _stored(presence, student, digest)
    if already is not None:
        # The ordinary case for an offline queue whose acknowledgement was lost, not
        # an attack. The verdict already reached stands: nothing is written, no
        # second attempt is invented, and in particular a stored PRESENT is not
        # overwritten by the refusal a repeated digest would otherwise produce.
        return Response(_payload(*already, duplicate=True))

    received_at = int(timezone.now().timestamp())
    try:
        with transaction.atomic():
            cleared = gates.clear(
                proof_bytes, signature,
                context=_context(presence),
                resolve_device=_registration_resolver(session),
                ledger=DjangoLedger(),
                # The server's clock, which is the whole point. A proof's age is
                # receipt time minus the step its challenge belongs to, so no
                # timestamp a client supplies can move it - the hole the old
                # marking path had, where `marked_at` came from the request body.
                received_at=received_at,
                observations=observations,
                # No relay evidence exists on this scope, so there is no resolver
                # to give. `gates` drops attached hops it cannot check instead of
                # refusing the proof over them, which is what stops a client that
                # attaches something this build cannot verify from being punished
                # for having tried.
                resolve_relay=None,
                # Both snapshots come from this session's pinned artifact rather
                # than from the active one, so a proof built inside the offline
                # allowance that was in force during the lesson cannot be expired
                # by an allowance shortened afterwards.
                timing=timing,
                bounds=bounds,
            )
            decision = decide.decide(
                fusion.fuse(features.extract(cleared), weights=weights),
                # Read from inside the signature, which is the only place a
                # biometric outcome exists at all. `local_auth` reports success or
                # failure and no template ever leaves the handset (§09).
                biometric=cleared.signed.proof.biometric,
                policy=policy,
            )
            admitted = _admit(
                presence, student, proof_bytes, cleared, decision, received_at,
            )
    except gates.GateError as exc:
        return _answer_refusal(
            exc, presence, student, peek, proof_bytes, digest, received_at, policy,
        )
    # 200 for every verdict, including the negative ones. A refused proof is a
    # request the server understood and answered; sending 4xx would tell an offline
    # queue to retry a decision that will never come out differently, and would make
    # "your attendance was not verified" indistinguishable from "your request was
    # malformed" to every client that only reads the status line.
    return Response(_payload(*admitted))
