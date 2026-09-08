"""The relay chain of custody, and the one thing it cannot do.

A chain is how an origin sighting travels to a handset that could not hear the
teacher directly. The relay writes down what it heard, signs a hop, and passes
the pair on; the next relay chains its own hop to the digest of that one. What
arrives at the server is an ordered, hash-linked run of signatures, and because
each link is a digest of the bytes before it, the run cannot be reordered,
shortened in the middle, or spliced from two chains without the links failing to
match.

**A relay cannot verify the chain it is extending.** This is the load-bearing
limitation of the module and it is a consequence of a privacy rule, not an
oversight. A hop names its relay by a session-scoped pseudonym rather than by a
student, because §43 forbids putting permanent identity on the air; and a relay
holds neither its peers' public keys nor any roster to resolve a pseudonym
against. So a relay can check that the *shape* is intact - indices consecutive,
links matching, depth within bounds - and it can check nothing else. Only the
server, which has the cohort, can check a signature.

Privacy and offline peer verifiability genuinely conflict here, and privacy wins.
The cost is paid honestly: a rogue relay can inject hops, and a chain it poisons
will fail verification at the server. What that costs the student is *evidence*,
never a false accept - relay evidence is an opportunistic bonus and is never a
precondition for PRESENT, so a chain that cannot be verified must degrade a
decision toward SECONDARY and must never push it toward SUSPICIOUS. An
unresolvable pseudonym is indistinguishable from a device whose registration has
not reached this server yet, and treating either as an accusation would punish
the wrong person.

That split is why the API has two entry points rather than one. `parse_chain` is
structural, runs on a handset with no secrets, and is what a relay uses.
`verify_chain` is cryptographic, needs the cohort, and runs on the server.

**Depth is not distance.** Three hops is not three room-lengths; it is three
devices that could hear each other, in whatever geometry they happened to be.
A chain is evidence that a sighting propagated, and propagation stops at no wall
that a radio does not stop at. Nothing in this module concludes that a hop count
means a room, and the parameter that bounds depth is bounded by the geometry of
a classroom rather than by the range of a radio, for exactly that reason.
"""
import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Sequence, Tuple

from . import codec, config, keys, proof

SCHEMA = codec.RELAY_HOP

# Widths, measured from the schema so a schema edit cannot silently disagree with
# the signing preimage. `signature` is cross-checked against the key module's own
# constant: two independent statements of the same fact, and a build that would
# rather fail than sign under a mismatched assumption.
PREV_HASH_LEN = SCHEMA.fields[SCHEMA.index("prev_proof_hash")].size
PSEUDONYM_LEN = SCHEMA.fields[SCHEMA.index("relay_pseudonym")].size
SIGNATURE_LEN = SCHEMA.fields[SCHEMA.index("signature")].size

if SIGNATURE_LEN != keys.SIGNATURE_LEN:
    raise RuntimeError(
        "relay_hop reserves %d bytes for a signature but keys produces %d"
        % (SIGNATURE_LEN, keys.SIGNATURE_LEN)
    )

# The preimage writes its two integers at a fixed width, so no length prefix has
# to be agreed between Python and Dart.
COUNT_WIDTH = 8
COUNT_MAX = (1 << (COUNT_WIDTH * 8)) - 1

LABEL = b"relay-hop"
PREIMAGE_LEN = (
    len(keys.DOMAIN)
    + len(LABEL)
    + 1
    + COUNT_WIDTH
    + PREV_HASH_LEN
    + PSEUDONYM_LEN
    + COUNT_WIDTH
)

# The pseudonym derivation is domain-separated the same way, and separately, so
# no input to one can ever be read as an input to the other.
PSEUDONYM_LABEL = b"relay-pseudonym"


# --- Reasons and signals ---------------------------------------------------

# A reason refuses. A signal is written down for fusion to weigh. The line
# between them is the same one the origin module draws, and it matters most here:
# a chain that fails is a chain whose evidence is unavailable, and unavailable
# evidence is not evidence of wrongdoing.
MALFORMED = "chain_malformed"
BROKEN_LINK = "chain_broken_link"
OUT_OF_ORDER = "chain_out_of_order"
TOO_DEEP = "chain_too_deep"
REPEATED_RELAY = "chain_repeated_relay"
UNKNOWN_RELAY = "chain_unknown_relay"
BAD_SIGNATURE = "chain_bad_signature"

REASON_CODES = frozenset({
    MALFORMED,
    BROKEN_LINK,
    OUT_OF_ORDER,
    TOO_DEEP,
    REPEATED_RELAY,
    UNKNOWN_RELAY,
    BAD_SIGNATURE,
})

# Deliberately absent: any code meaning "no chain". A handset that cannot relay,
# or a student nobody relayed for, produces no chain at all, and that is the
# ordinary case on every platform in this scope. Decision 3 says missing evidence
# lowers confidence and is never negative evidence; the way to make that
# structural rather than remembered is to give the refusal vocabulary no word for
# it.

CLAIM_NON_MONOTONIC = "relay_claim_non_monotonic"
DEPTH_AT_LIMIT = "relay_depth_at_limit"

SIGNALS = frozenset({CLAIM_NON_MONOTONIC, DEPTH_AT_LIMIT})


class ChainError(Exception):
    """A chain that cannot be accepted, with the reason code that says why."""

    def __init__(self, code: str, message: str):
        assert code in REASON_CODES, "undeclared chain reason code %r" % (code,)
        super().__init__(message)
        self.code = code


# --- Bounds ----------------------------------------------------------------

def max_hops() -> int:
    """The deepest chain this deployment accepts, from the active artifact.

    Bounded twice, and the second bound is not decoration. A chain arrives inside
    a proof as observation digests, and the proof schema caps how many of those a
    proof can carry; an artifact that allowed a deeper chain than a proof can
    commit to would produce chains that verify and then cannot be submitted. That
    relation cannot live in `config.cross_check` - config is the bottom layer and
    must import nothing from above it - so it is enforced here, where both facts
    are in scope, and asserted against the shipped artifact by a test.
    """
    limit = config.get("relay.max_hops")
    if limit > proof.MAX_OBSERVATIONS:
        raise ChainError(
            TOO_DEEP,
            "relay.max_hops is %d but a proof can commit to only %d observations"
            % (limit, proof.MAX_OBSERVATIONS),
        )
    return limit


def _exactly(value: Any, size: int, what: str) -> bytes:
    raw = bytes(value)
    if len(raw) != size:
        raise ChainError(
            MALFORMED, "%s must be %d bytes, got %d" % (what, size, len(raw))
        )
    return raw


def _count(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ChainError(MALFORMED, "%s must be an integer, got %r" % (what, value))
    if not 0 <= value <= COUNT_MAX:
        raise ChainError(MALFORMED, "%s out of range: %d" % (what, value))
    return value


# --- Naming a relay without naming a student -------------------------------

def pseudonym(session_id: bytes, device_public_bytes: bytes) -> bytes:
    """The 16 bytes a hop uses to name its relay.

    Session-scoped by construction: the same device relaying in two lessons
    produces two unrelated pseudonyms, so nothing on the air links a device
    across sessions, and nothing links it to a student at all without the cohort.

    It is computable by both ends that need it and by neither end that must not
    have it. A relay can compute its own from the session id it already scanned,
    with no connectivity and no secret it does not hold - which is the requirement
    that rules out deriving this from the session root secret, since a student
    handset never sees that. A server can compute the whole cohort's pseudonyms
    once per session and resolve a hop in constant time afterwards.

    The cost of that symmetry, stated rather than buried: because both inputs are
    public, an adversary who already holds the class's public keys can link a
    pseudonym to a device for that session. It is a hash for opacity on the air,
    not a keyed MAC against a roster-holding adversary. What it does buy is that
    the roster is the thing an attacker must steal - the chain itself gives up
    nothing - and cross-session linkage stays closed regardless. When device
    binding lands and a per-device secret is shared with the server, this becomes
    a keyed MAC under `PURPOSE_DEVICE_BINDING` and that residue closes too; the
    wire format does not change when it does.
    """
    material = (
        keys.DOMAIN
        + PSEUDONYM_LABEL
        + b"\x00"
        + _exactly(session_id, proof.SESSION_ID_LEN, "session id")
        + _exactly(device_public_bytes, keys.PUBLIC_KEY_LEN, "device public key")
    )
    return hashlib.sha256(material).digest()[:PSEUDONYM_LEN]


def cohort_index(
    session_id: bytes, verify_keys: Iterable[keys.VerifyKey]
) -> Dict[bytes, keys.VerifyKey]:
    """Pseudonym to key, for one session's enrolled devices.

    Built once and passed to `verify_chain` as its resolver. A collision here
    would mean two devices sharing a pseudonym, which no honest cohort produces
    and which would make a hop ambiguous, so it is refused rather than resolved
    by whichever key happened to be inserted last.
    """
    index: Dict[bytes, keys.VerifyKey] = {}
    for key in verify_keys:
        tag = pseudonym(session_id, key.public_bytes)
        if tag in index and not keys.equal(index[tag].public_bytes, key.public_bytes):
            raise ChainError(
                REPEATED_RELAY,
                "two enrolled devices share the pseudonym %s" % (tag.hex(),),
            )
        index[tag] = key
    return index


# --- What a hop signs ------------------------------------------------------

def preimage(
    hop_index: int,
    prev_proof_hash: bytes,
    relay_pseudonym: bytes,
    observed_at: int,
) -> bytes:
    """The bytes a relay signs, which are not the bytes a relay sends.

    A hop cannot sign its own encoding: `relay_hop` carries `signature` as a
    field, so signing the struct would require the signature before computing it.
    The signed bytes are therefore a separate preimage over the four fields that
    are settled before a signature exists.

    Every part of it is fixed width. That is what makes it unambiguous - there is
    no separator to escape and no length prefix to disagree about, so two
    different hops cannot produce identical preimage bytes - and it is also what
    makes it portable: a Dart implementation is a concatenation, not a codec.
    The domain prefix keeps it disjoint from every other signature this system
    produces, so a hop signature can never be replayed as a proof signature.
    """
    return (
        keys.DOMAIN
        + LABEL
        + b"\x00"
        + _count(hop_index, "hop index").to_bytes(COUNT_WIDTH, "big")
        + _exactly(prev_proof_hash, PREV_HASH_LEN, "previous hash")
        + _exactly(relay_pseudonym, PSEUDONYM_LEN, "relay pseudonym")
        + _count(observed_at, "observed at").to_bytes(COUNT_WIDTH, "big")
    )


# --- One hop ---------------------------------------------------------------

@dataclass(frozen=True)
class Hop:
    """One relay's signed link in a chain.

    `observed_at` is the relay's own clock and is a claim in exactly the sense
    `proof.captured_at` is: signed, therefore attributable, and never the thing
    that sets a time. The clock this system trusts is the origin counter, which
    is MAC-protected and derived from the session's step index.
    """

    hop_index: int
    prev_proof_hash: bytes
    relay_pseudonym: bytes
    signature: bytes
    observed_at: int

    def values(self) -> Dict[str, Any]:
        return {
            "hop_index": self.hop_index,
            "prev_proof_hash": self.prev_proof_hash,
            "relay_pseudonym": self.relay_pseudonym,
            "signature": self.signature,
            "observed_at": self.observed_at,
        }

    def encode(self) -> bytes:
        return codec.encode(SCHEMA.name, self.values())

    def digest(self) -> bytes:
        """This hop's identity, and the link the next hop chains to."""
        return codec.digest(SCHEMA.name, self.values())

    def preimage(self) -> bytes:
        return preimage(
            self.hop_index,
            self.prev_proof_hash,
            self.relay_pseudonym,
            self.observed_at,
        )

    def describe(self) -> Dict[str, Any]:
        """For logs and audit. Names the claim as a claim, and no key material."""
        return {
            "hop_index": self.hop_index,
            "prev_proof_hash": self.prev_proof_hash.hex(),
            "relay_pseudonym": self.relay_pseudonym.hex(),
            "claimed_observed_at": self.observed_at,
        }


def root_link(encoded_sighting: bytes) -> bytes:
    """What hop zero chains to: the digest of the relay's own origin sighting.

    Decoded before it is hashed, and decoded strictly, so a chain cannot be rooted
    in arbitrary bytes that merely happen to be 32 bytes long once hashed. A chain
    with no origin at its root is a chain about nothing.

    A codec refusal is translated rather than allowed to escape. Every
    rejection this module produces for untrusted bytes carries a declared
    reason code, so a caller that maps refusals to reason codes handles all of
    them; an unwrapped SchemaError here would surface at the API boundary as a
    server error instead of as a rejected proof.
    """
    try:
        codec.decode(
            bytes(encoded_sighting),
            schema_name=codec.ORIGIN_SIGHTING.name,
            strict=True,
        )
    except codec.CodecError as exc:
        raise ChainError(
            MALFORMED, "root is not an origin sighting: %s" % (exc,)
        )
    return codec.digest_bytes(encoded_sighting)


def sign_hop(
    *,
    hop_index: int,
    prev_proof_hash: bytes,
    session_id: bytes,
    observed_at: int,
    signing_key: keys.SigningKey,
) -> Hop:
    """Build and sign one hop. The pseudonym is derived, never supplied.

    Deriving it here rather than accepting it as an argument removes the only way
    a caller could put somebody else's pseudonym in a hop it signs. A device can
    still lie about its clock; it cannot lie about which device it is, because the
    pseudonym and the signature are computed from the same key.
    """
    tag = pseudonym(session_id, signing_key.public().public_bytes)
    body = preimage(hop_index, prev_proof_hash, tag, observed_at)
    return Hop(
        hop_index=_count(hop_index, "hop index"),
        prev_proof_hash=_exactly(prev_proof_hash, PREV_HASH_LEN, "previous hash"),
        relay_pseudonym=tag,
        signature=signing_key.sign(body),
        observed_at=_count(observed_at, "observed at"),
    )


def extend(
    hops: Sequence[Hop],
    *,
    root: bytes,
    session_id: bytes,
    observed_at: int,
    signing_key: keys.SigningKey,
    limit: Optional[int] = None,
) -> Tuple[Hop, ...]:
    """Append one hop to a chain, chained to whatever is currently last.

    `root` is used only for the first hop; after that the link is the previous
    hop's digest, which is what makes the run non-reorderable. The depth bound is
    checked before signing, so a relay that would exceed it declines to forward
    rather than producing a hop the server will refuse - the difference matters on
    a handset, where the second is battery spent on nothing.
    """
    ceiling = max_hops() if limit is None else _count(limit, "hop limit")
    if len(hops) >= ceiling:
        raise ChainError(
            TOO_DEEP,
            "a chain of %d hops is already at the limit of %d" % (len(hops), ceiling),
        )
    previous = tuple(hops)
    link = previous[-1].digest() if previous else _exactly(root, PREV_HASH_LEN, "root")
    return previous + (
        sign_hop(
            hop_index=len(previous),
            prev_proof_hash=link,
            session_id=session_id,
            observed_at=observed_at,
            signing_key=signing_key,
        ),
    )


# --- Structural: what a handset can check -----------------------------------

def parse_hop(raw: bytes) -> Hop:
    """One encoded hop to a Hop, strictly.

    Strict decoding re-encodes and compares, so a hop has exactly one wire form.
    Without that a relay could re-encode a hop it received and submit it as a
    second, independent one, and a chain of length one would count as two.
    """
    try:
        values = codec.decode(bytes(raw), schema_name=SCHEMA.name, strict=True)
    except codec.CodecError as exc:
        raise ChainError(MALFORMED, "hop does not decode: %s" % (exc,))
    return Hop(
        hop_index=values["hop_index"],
        prev_proof_hash=values["prev_proof_hash"],
        relay_pseudonym=values["relay_pseudonym"],
        signature=values["signature"],
        observed_at=values["observed_at"],
    )


def parse_chain(
    encoded: Sequence[bytes],
    *,
    root: Optional[bytes] = None,
    limit: Optional[int] = None,
) -> Tuple[Hop, ...]:
    """Encoded hops to a chain, checking only what needs no secret.

    This is the whole of what a relay can do, and it runs on a handset with no
    connectivity, no cohort and no keys but its own: decode each hop, check the
    indices run 0, 1, 2 … without a gap, check each link is the digest of the hop
    before it, check no device appears twice, check the depth. That is enough to
    reject a chain that has been reordered, truncated in the middle, spliced from
    two others, or looped - and it is not enough to reject a chain a stranger
    forged, because every signature in it is opaque without the cohort.

    `root` is optional for the same reason: a relay that has the origin sighting
    should pass it and get hop zero's link checked too, and a peer that received
    only the chain cannot. Omitting it narrows what the pass means; it does not
    change what a pass is worth, which was never much on its own.
    """
    ceiling = max_hops() if limit is None else _count(limit, "hop limit")
    hops = tuple(parse_hop(raw) for raw in encoded)
    if len(hops) > ceiling:
        raise ChainError(
            TOO_DEEP, "%d hops exceeds the limit of %d" % (len(hops), ceiling)
        )

    seen: Dict[bytes, int] = {}
    expected_link = None if root is None else _exactly(root, PREV_HASH_LEN, "root")
    for position, hop in enumerate(hops):
        if hop.hop_index != position:
            raise ChainError(
                OUT_OF_ORDER,
                "hop at position %d declares index %d" % (position, hop.hop_index),
            )
        if expected_link is not None and not keys.equal(
            hop.prev_proof_hash, expected_link
        ):
            raise ChainError(
                BROKEN_LINK,
                "hop %d chains to %s but the hop before it digests to %s"
                % (position, hop.prev_proof_hash.hex(), expected_link.hex()),
            )
        if hop.relay_pseudonym in seen:
            raise ChainError(
                REPEATED_RELAY,
                "relay at hop %d already appears at hop %d"
                % (position, seen[hop.relay_pseudonym]),
            )
        seen[hop.relay_pseudonym] = position
        expected_link = hop.digest()
    return hops


# --- Cryptographic: what only the server can check --------------------------

def verify_chain(
    encoded: Sequence[bytes],
    *,
    session_id: bytes,
    root: bytes,
    resolve: Callable[[bytes], Optional[keys.VerifyKey]],
    limit: Optional[int] = None,
) -> Tuple[Hop, ...]:
    """A chain, verified, or a refusal naming the hop that failed.

    Structure first, then signatures - so a chain that was reordered is reported
    as reordered rather than as a forgery, which is the difference between an
    integrator finding the bug and hunting one. `root` is mandatory here: on the
    server the origin sighting is always in hand, and a chain whose first link is
    unchecked is a chain that could have been grafted onto a different sighting.

    `resolve` is supplied by the caller and is how this module stays free of the
    database. `cohort_index` builds the usual one. A pseudonym it cannot resolve
    refuses the chain, and that refusal deserves care in how it is read: it means
    a hop was signed by a device this server does not know is enrolled, which a
    rogue relay produces and so does a genuine student whose device registration
    has not synced. The two are indistinguishable from here. So the caller treats
    an unverifiable chain as evidence that is *absent*, degrading toward
    SECONDARY, and never as evidence of wrongdoing.

    A resolver is caller-supplied code, so the key it returns is checked against
    the pseudonym that asked for it rather than trusted. Without that, a resolver
    with an off-by-one would hand back the wrong device's key, the signature would
    fail under it, and a working handset would be reported as a forgery.
    """
    hops = parse_chain(encoded, root=root, limit=limit)
    for hop in hops:
        key = resolve(hop.relay_pseudonym)
        if key is None:
            raise ChainError(
                UNKNOWN_RELAY,
                "hop %d names relay %s, which is not an enrolled device"
                % (hop.hop_index, hop.relay_pseudonym.hex()),
            )
        owned = pseudonym(session_id, key.public_bytes)
        if not keys.equal(owned, hop.relay_pseudonym):
            raise ChainError(
                UNKNOWN_RELAY,
                "hop %d names relay %s but the resolver returned a key whose "
                "pseudonym is %s"
                % (hop.hop_index, hop.relay_pseudonym.hex(), owned.hex()),
            )
        try:
            key.verify(hop.preimage(), hop.signature)
        except keys.SignatureError as exc:
            raise ChainError(
                BAD_SIGNATURE, "hop %d does not verify: %s" % (hop.hop_index, exc)
            )
    return hops


# --- What fusion weighs rather than refuses ---------------------------------

def signals(hops: Sequence[Hop], limit: Optional[int] = None) -> Tuple[str, ...]:
    """Observations about a chain that has already been accepted.

    Neither of these is a reason to refuse anything, and both would be wrong as
    one. A relay whose clock runs backwards relative to the hop before it has
    told us something about its clock, not about its honesty - clocks on handsets
    are wrong constantly and the chain's real ordering is the hash links, which
    were already checked. A chain sitting exactly at the depth limit is worth
    noticing because it is the one depth at which a longer chain would have been
    truncated, so what arrived may not be all there was.
    """
    ceiling = max_hops() if limit is None else _count(limit, "hop limit")
    found = []
    previous = None
    for hop in hops:
        if previous is not None and hop.observed_at < previous:
            found.append(CLAIM_NON_MONOTONIC)
            break
        previous = hop.observed_at
    if hops and len(hops) == ceiling:
        found.append(DEPTH_AT_LIMIT)
    return tuple(found)


def encode_chain(hops: Sequence[Hop]) -> Tuple[bytes, ...]:
    """The chain as it travels: one canonical encoding per hop, in order."""
    return tuple(hop.encode() for hop in hops)


def describe_chain(hops: Sequence[Hop]) -> Dict[str, Any]:
    """A chain for a log or an audit record.

    `depth` is a count of hops and nothing more. It is not a distance, it is not a
    number of metres, and it is not evidence about a room; §63 also keeps it off
    every student-facing surface, where a topology would be both meaningless and
    a disclosure.
    """
    return {
        "depth": len(hops),
        "hops": [hop.describe() for hop in hops],
        "signals": list(signals(hops)) if hops else [],
    }
