"""The teacher's device as a broadcast origin, and what a student may record of it.

Two structures, deliberately different in kind.

The **frame** is what goes over the air: a fixed 17-byte layout, not CBOR. BLE
legacy advertising gives about 24 usable bytes inside a manufacturer-data
structure once the flags AD and the length/type headers are paid for, so the wire
format here is a byte layout with no self-description at all. Every field is at a
fixed offset because there is no room for anything else.

The **sighting** is what a student's handset writes down afterwards: the frame's
contents plus a received signal strength and a local clock reading, encoded with
the canonical codec so its digest can be committed to inside a signed proof.

Three things this module does not do, each of them a rule from the brief made
structural rather than remembered.

**It never compares a signal strength to anything.** `rssi_dbm` converts, bounds
and records; there is no threshold in this file and no function that returns a
verdict about distance. A stronger signal is not proof of a nearer device - a
handset in a pocket reads weaker than one held up behind a window - and any
`RSSI > x` test would be exactly the single-signal scheme this layer exists to
replace.

**A valid frame is evidence, not a gate.** RF crosses glass and doorways. A
student in the corridor can hold a genuine, freshly-MACed origin frame, and on
the current scope nothing in this system can tell them apart from a student in
the third row. The frame proves that the teacher's device was broadcasting nearby
and recently; it does not prove a room. The absence of a frame is not negative
evidence either - most handsets on this scope cannot scan at all.

**Nothing identifying is broadcast.** The frame carries a session-scoped opaque
reference and a rotating MAC. It carries no student, no teacher, no device key,
no permanent session identifier. The one linkability cost is stated rather than
hidden: `session_ref` is stable for the life of a session, so a listener can tell
that two frames belong to the same session. That is what makes it usable as a
cheap filter, it lasts one period, and it links to no person.
"""
from dataclasses import dataclass
from typing import Optional

from . import codec, keys
from .challenge import Timing, _timing, epoch_of, step_bounds, step_index
from .keys import SessionKeys

SCHEMA = codec.ORIGIN_SIGHTING

# The over-the-air layout. Offsets, not a schema: there is no space on a BLE
# advertisement for field tags, so position is the only thing carrying meaning.
FRAME_VERSION = 1
VERSION_LEN = 1
SESSION_REF_LEN = SCHEMA.fields[SCHEMA.index("session_ref")].size
COUNTER_LEN = 4
EPHEMERAL_ID_LEN = SCHEMA.fields[SCHEMA.index("ephemeral_id")].size
FRAME_LEN = VERSION_LEN + SESSION_REF_LEN + COUNTER_LEN + EPHEMERAL_ID_LEN

# What a legacy BLE advertisement leaves for a payload, arrived at from the parts
# rather than stated as a total. Spelled out deliberately: a total is a number
# somebody has to trust, whereas the subtraction can be checked against the
# Bluetooth Core specification line by line - and it keeps the config-hygiene
# test honest, since a bare 24 here is indistinguishable to that test from a
# tuned 24 that belongs in an artifact.
ADVERTISEMENT_OCTETS = 31        # AD data in a legacy ADV_IND PDU
FLAGS_AD_LEN = 3                 # length, type, one octet of flags
AD_HEADER_LEN = 1 + 1            # every AD structure: one length octet, one type
COMPANY_ID_LEN = 16 // 8         # a 16-bit identifier assigned by the Bluetooth SIG
ADVERTISEMENT_BUDGET = (
    ADVERTISEMENT_OCTETS - FLAGS_AD_LEN - AD_HEADER_LEN - COMPANY_ID_LEN
)

# A raise rather than an assert: python -O removes assertions, and the one thing
# this check must survive is being run in production. Finding out that a frame
# does not fit an advertisement costs an import here and a field trial there.
if FRAME_LEN > ADVERTISEMENT_BUDGET:
    raise RuntimeError(
        "the origin frame is %d bytes and no longer fits the %d available in a "
        "legacy BLE advertisement" % (FRAME_LEN, ADVERTISEMENT_BUDGET)
    )

COUNTER_MAX = (1 << (COUNTER_LEN * 8)) - 1

# RSSI is negative dBm and the codec carries only unsigned integers, so the wire
# value is dBm + this. The surviving range is one byte wide, which comfortably
# spans every reading a radio actually reports.
RSSI_OFFSET_BASE = 128
RSSI_OFFSET_MIN = 0
RSSI_OFFSET_MAX = 255

MALFORMED = "origin_malformed"
WRONG_SESSION = "origin_wrong_session"
FORGED = "origin_forged"
STALE_COUNTER = "origin_stale_counter"
FUTURE_COUNTER = "origin_future_counter"

REASON_CODES = frozenset({
    MALFORMED, WRONG_SESSION, FORGED, STALE_COUNTER, FUTURE_COUNTER,
})


class OriginError(Exception):
    """A frame or sighting is malformed, unattributable, or out of its window."""

    def __init__(self, code: str, message: str):
        assert code in REASON_CODES, "undeclared reason code %r" % (code,)
        super().__init__(message)
        self.code = code


# --- Derivation -------------------------------------------------------------

# The context passed to HKDF for the session-stable reference. Every other origin
# derivation passes an eight-byte big-endian epoch number, so a three-byte ASCII
# context cannot collide with one however many epochs a session runs for.
REF_CONTEXT = b"ref"


def session_ref(session_keys: SessionKeys) -> bytes:
    """The four-byte tag on every frame of one session.

    A filter, not a name. A handset that has scanned the QR knows this value and
    can discard every frame from the lecture next door without spending a MAC on
    it. It is derived, never truncated from `session_id`: the session id appears
    in URLs and QR payloads, and a broadcast that leaked its first four bytes
    would let anyone in the building tie the two together.
    """
    return keys.derive(
        session_keys.root_secret,
        purpose=keys.PURPOSE_ORIGIN_EPHEMERAL,
        salt=session_keys.session_id,
        context=REF_CONTEXT,
        length=SESSION_REF_LEN,
    )


def origin_key(session_keys: SessionKeys, counter: int, timing: Optional[Timing] = None) -> bytes:
    """The key the rotating identifier runs on, for the epoch the counter is in.

    Per-epoch for the same reason `SessionKeys.epoch_key` is: a teacher handset
    recovered mid-lesson yields the identifiers of that epoch and of no other, in
    either direction.
    """
    epoch = epoch_of(_check_counter(counter), timing)
    return keys.derive(
        session_keys.root_secret,
        purpose=keys.PURPOSE_ORIGIN_EPHEMERAL,
        salt=session_keys.session_id,
        context=epoch.to_bytes(8, "big"),
    )


def mac_input(session_id: bytes, counter: int) -> bytes:
    """Domain-separated, so an origin identifier and a challenge can never coincide.

    They already derive from different HKDF purposes, so this is belt as well as
    braces - but the cost is one label and the failure it forecloses is a struct
    verifying as the wrong kind of thing.
    """
    return (
        keys.DOMAIN
        + b"origin"
        + b"\x00"
        + bytes(session_id)
        + _check_counter(counter).to_bytes(COUNTER_LEN, "big")
    )


def ephemeral_id(
    session_keys: SessionKeys, counter: int, timing: Optional[Timing] = None
) -> bytes:
    """The eight bytes that make a frame attributable to this session's teacher.

    Truncated to eight because that is what fits. Eight bytes of HMAC is not a
    signature and is not meant to be: an attacker who wants to forge one frame
    still needs the session root secret, and an attacker who has the root secret
    can mint challenges too, which is a strictly larger problem recorded in the
    threat model. What truncation costs is the ability to *sign* a frame to a
    third party - which is why relay hops carry Ed25519 signatures and frames
    do not.
    """
    return keys.mac_truncated(
        origin_key(session_keys, counter, timing),
        mac_input(session_keys.session_id, counter),
        EPHEMERAL_ID_LEN,
    )


def _check_counter(counter: int) -> int:
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise OriginError(MALFORMED, "counter must be an integer, got %r" % (counter,))
    if not 0 <= counter <= COUNTER_MAX:
        raise OriginError(
            MALFORMED, "counter %d is outside 0..%d" % (counter, COUNTER_MAX)
        )
    return counter


# --- Signal strength --------------------------------------------------------

def to_offset(dbm: int) -> int:
    """dBm to the unsigned value the codec carries. Recorded, never compared."""
    if not isinstance(dbm, int) or isinstance(dbm, bool):
        raise OriginError(MALFORMED, "rssi must be an integer dBm, got %r" % (dbm,))
    offset = dbm + RSSI_OFFSET_BASE
    if not RSSI_OFFSET_MIN <= offset <= RSSI_OFFSET_MAX:
        raise OriginError(
            MALFORMED,
            "rssi %d dBm falls outside the representable range %d..%d dBm"
            % (dbm, RSSI_OFFSET_MIN - RSSI_OFFSET_BASE, RSSI_OFFSET_MAX - RSSI_OFFSET_BASE),
        )
    return offset


def rssi_dbm(offset: int) -> int:
    """The reading back, in dBm. A number for a model to weigh, not a distance."""
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise OriginError(MALFORMED, "rssi offset must be an integer, got %r" % (offset,))
    if not RSSI_OFFSET_MIN <= offset <= RSSI_OFFSET_MAX:
        raise OriginError(
            MALFORMED, "rssi offset %d is outside 0..%d" % (offset, RSSI_OFFSET_MAX)
        )
    return offset - RSSI_OFFSET_BASE


# --- The frame --------------------------------------------------------------

_REF_AT = VERSION_LEN
_COUNTER_AT = _REF_AT + SESSION_REF_LEN
_ID_AT = _COUNTER_AT + COUNTER_LEN


@dataclass(frozen=True)
class Frame:
    """One advertisement, as a value. Seventeen bytes with nothing spare."""

    session_ref: bytes
    counter: int
    ephemeral_id: bytes
    version: int = FRAME_VERSION

    def pack(self) -> bytes:
        if self.version != FRAME_VERSION:
            raise OriginError(
                MALFORMED,
                "cannot emit frame version %r; this build speaks version %d"
                % (self.version, FRAME_VERSION),
            )
        raw = (
            bytes([FRAME_VERSION])
            + _exactly(self.session_ref, SESSION_REF_LEN, "session_ref")
            + _check_counter(self.counter).to_bytes(COUNTER_LEN, "big")
            + _exactly(self.ephemeral_id, EPHEMERAL_ID_LEN, "ephemeral_id")
        )
        assert len(raw) == FRAME_LEN
        return raw


def _exactly(value: bytes, size: int, what: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise OriginError(MALFORMED, "%s must be bytes, got %r" % (what, type(value).__name__))
    raw = bytes(value)
    if len(raw) != size:
        raise OriginError(
            MALFORMED, "%s is %d bytes, expected %d" % (what, len(raw), size)
        )
    return raw


def build(
    session_keys: SessionKeys, counter: int, timing: Optional[Timing] = None
) -> Frame:
    """What the teacher's device advertises during step `counter`.

    A pure function of (session, counter), like a challenge is: the teacher
    handset and the server compute identical bytes with no exchange between them,
    which is what makes the whole thing work offline.
    """
    return Frame(
        session_ref=session_ref(session_keys),
        counter=_check_counter(counter),
        ephemeral_id=ephemeral_id(session_keys, counter, timing),
    )


def unpack(raw: bytes) -> Frame:
    """Structure only. Says nothing about whether the frame is genuine."""
    if not isinstance(raw, (bytes, bytearray)):
        raise OriginError(MALFORMED, "a frame is bytes, got %r" % (type(raw).__name__,))
    body = bytes(raw)
    if len(body) != FRAME_LEN:
        raise OriginError(
            MALFORMED, "frame is %d bytes, expected %d" % (len(body), FRAME_LEN)
        )
    version = body[0]
    if version != FRAME_VERSION:
        raise OriginError(
            MALFORMED,
            "frame declares version %d; this build speaks version %d"
            % (version, FRAME_VERSION),
        )
    return Frame(
        session_ref=body[_REF_AT:_COUNTER_AT],
        counter=int.from_bytes(body[_COUNTER_AT:_ID_AT], "big"),
        ephemeral_id=body[_ID_AT:],
        version=version,
    )


def counter_bounds(
    session_start: int, counter: int, timing: Optional[Timing] = None
) -> tuple:
    """The window in which a frame carrying this counter could genuinely be on air.

    The same argument `replay.queue_age` runs on: a step-*n* frame cannot exist
    before step *n* begins, because deriving it needs an epoch key and a counter
    that only exist then. So the counter is a time source the client cannot move,
    and it is the one this module trusts. `observed_at`, by contrast, is whatever
    the handset's clock said.
    """
    return step_bounds(session_start, _check_counter(counter), timing)


def verify_frame(
    raw,
    session_keys: SessionKeys,
    *,
    session_start: int,
    at: int,
    timing: Optional[Timing] = None,
) -> Frame:
    """A frame that this session's teacher emitted, recently enough to matter.

    Order: structure, then session, then the counter's window, then the MAC. The
    window comes before the MAC here, which is the opposite of `proof.verify` -
    and for a reason worth stating, because getting it backwards produces
    misleading reason codes. A proof's signature covers every field, so no field
    means anything until it holds. A frame's counter *selects the key* the MAC is
    computed under, so a counter from step ten thousand of a fifty-minute lesson
    would fail the MAC and be reported as a forgery when what actually happened
    is an out-of-range counter.

    What a pass means is narrow: the teacher's device broadcast this, during this
    session, around now. It does not mean the listener was in the room.
    """
    t = _timing(timing)
    frame = raw if isinstance(raw, Frame) else unpack(raw)

    expected_ref = session_ref(session_keys)
    if not keys.equal(frame.session_ref, expected_ref):
        raise OriginError(
            WRONG_SESSION,
            "frame carries session ref %s, this session's is %s"
            % (frame.session_ref.hex(), expected_ref.hex()),
        )

    current = step_index(session_start, at, t)
    if frame.counter > current + t.accept_window_steps:
        raise OriginError(
            FUTURE_COUNTER,
            "frame claims counter %d; this session has only reached %d"
            % (frame.counter, current),
        )
    oldest = current - t.accept_window_steps
    if frame.counter < oldest:
        raise OriginError(
            STALE_COUNTER,
            "frame claims counter %d; nothing older than %d is being accepted, so "
            "this is a recording rather than a broadcast"
            % (frame.counter, oldest),
        )

    expected_id = ephemeral_id(session_keys, frame.counter, t)
    if not keys.equal(frame.ephemeral_id, expected_id):
        raise OriginError(
            FORGED,
            "frame identifier does not match the one this session derives for "
            "counter %d" % (frame.counter,),
        )
    return frame


# --- The sighting -----------------------------------------------------------

# Signals, not reason codes. A signal is something for fusion to weigh; a reason
# code refuses. Nothing in this list refuses anything, and none of it is negative
# evidence on its own - a handset with a badly-set clock is common and innocent.
CLAIM_AHEAD = "origin_claim_ahead_of_counter"
CLAIM_BEHIND = "origin_claim_behind_counter"

SIGNALS = frozenset({CLAIM_AHEAD, CLAIM_BEHIND})


@dataclass(frozen=True)
class Sighting:
    """What one handset wrote down about one frame it received.

    `observed_at` is the handset's own clock and is a claim in exactly the sense
    `proof.captured_at` is. The counter beside it is not: it is MAC-protected by a
    key the handset does not hold. Where the two disagree, the counter is the
    time and the disagreement is a signal.
    """

    frame: Frame
    rssi_offset: int
    observed_at: int

    @property
    def rssi(self) -> int:
        return rssi_dbm(self.rssi_offset)

    def values(self) -> dict:
        return {
            "session_ref": self.frame.session_ref,
            "counter": self.frame.counter,
            "ephemeral_id": self.frame.ephemeral_id,
            "rssi_offset": self.rssi_offset,
            "observed_at": self.observed_at,
        }

    def encode(self) -> bytes:
        return codec.encode(SCHEMA.name, self.values())

    def digest(self) -> bytes:
        """What a proof commits to. The sighting itself need never be uploaded."""
        return codec.digest(SCHEMA.name, self.values())

    def describe(self) -> dict:
        return {
            "session_ref": self.frame.session_ref.hex(),
            "counter": self.frame.counter,
            "ephemeral_id": self.frame.ephemeral_id.hex(),
            "rssi_dbm": self.rssi,
            "claimed_observed_at": self.observed_at,
        }


def record(frame: Frame, *, rssi: int, observed_at: int) -> Sighting:
    """A received frame plus the two things only the receiver knows."""
    if not isinstance(observed_at, int) or isinstance(observed_at, bool):
        raise OriginError(
            MALFORMED, "observed_at must be an integer, got %r" % (observed_at,)
        )
    if not 0 <= observed_at <= codec.UINT_MAX:
        raise OriginError(MALFORMED, "observed_at %d is out of range" % observed_at)
    return Sighting(
        frame=frame, rssi_offset=to_offset(rssi), observed_at=observed_at
    )


def parse_sighting(raw: bytes) -> Sighting:
    """Structure only, and strictly: one sighting has exactly one encoding.

    Strictness is what stops a single observation being re-encoded loosely and
    submitted as a second, independent one - which would let a student in the
    corridor turn one weak reading into a pile of corroboration.
    """
    try:
        values = codec.decode(bytes(raw), SCHEMA.name, strict=True)
    except codec.CodecError as exc:
        raise OriginError(MALFORMED, "not a canonical origin sighting: %s" % (exc,))
    frame = Frame(
        session_ref=values["session_ref"],
        counter=values["counter"],
        ephemeral_id=values["ephemeral_id"],
    )
    _check_counter(frame.counter)
    rssi_dbm(values["rssi_offset"])
    return Sighting(
        frame=frame,
        rssi_offset=values["rssi_offset"],
        observed_at=values["observed_at"],
    )


def signals(
    sighting: Sighting,
    session_start: int,
    timing: Optional[Timing] = None,
) -> tuple:
    """Where the receiver's clock disagrees with the counter it cannot move."""
    t = _timing(timing)
    earliest, latest = counter_bounds(session_start, sighting.frame.counter, t)
    found = []
    if sighting.observed_at > latest + t.clock_skew_seconds:
        found.append(CLAIM_AHEAD)
    if sighting.observed_at < earliest - t.clock_skew_seconds:
        found.append(CLAIM_BEHIND)
    return tuple(found)


def verify_sighting(
    raw,
    session_keys: SessionKeys,
    *,
    session_start: int,
    at: int,
    timing: Optional[Timing] = None,
) -> tuple:
    """A sighting whose frame this session's teacher really emitted.

    Returns the sighting and its signals together, because a caller that got only
    the sighting would have to remember to ask - and the whole point of returning
    signals rather than raising on them is that somebody downstream weighs them.
    """
    t = _timing(timing)
    sighting = raw if isinstance(raw, Sighting) else parse_sighting(raw)
    verify_frame(
        sighting.frame, session_keys, session_start=session_start, at=at, timing=t
    )
    return sighting, signals(sighting, session_start, t)
