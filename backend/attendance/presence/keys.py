"""Key hierarchy, rotation and the two primitives everything else is built from.

Four kinds of key material exist, and the separation between them is the point:

    server signing key      Ed25519, long-lived, rotated by key id. Signs
                            session announcements and server receipts. The root
                            of trust a client checks everything else against.

    session signing key     Ed25519, one per session, held by the teacher's
                            device and by the server. Signs each rolling
                            challenge, so a student can check a challenge is
                            authentic offline without holding any secret that
                            would let them mint one.

    session root secret     32 random bytes, one per session. HKDF input for the
                            epoch keys that drive the challenge chain. Secret,
                            because predicting a challenge is exactly the attack.

    device key              Ed25519, one per registered device, private half
                            generated on the handset and never transmitted. The
                            server only ever holds the public half.

Two consequences worth stating plainly. A student can *verify* a challenge but
never *produce* one: verification needs the session public key, production needs
the root secret. And the server can verify a proof but never forge one, because
it does not hold any device private key.

Nothing here derives key material from `settings.SECRET_KEY`. An earlier attempt
in this repository's history did, which couples session signing to Django's
session and password-reset signing: rotating one silently rotates the other, and
anything that leaks either leaks both. `_reject_secret_key_material` below makes
that specific mistake fail loudly rather than work quietly.

Primitives are Ed25519, HMAC-SHA256 and HKDF-SHA256 from `cryptography`, used as
they come. Signing is over canonical codec bytes with no additional wrapper: the
codec already prefixes every struct with its schema tag and version, so a
signature over an attendance proof cannot be reinterpreted as a signature over a
challenge. That is the domain separation, stated once here rather than
reimplemented per call site - and one fewer detail for the Dart side to get
subtly wrong.
"""
import base64
import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

logger = logging.getLogger(__name__)

# Everything derived here is namespaced under one string, versioned. A change to
# it invalidates every derived key at once, which is the intended blast radius
# for a break in the derivation scheme itself.
DOMAIN = b"campusguard/presence/v1/"

SEED_LEN = 32
PUBLIC_KEY_LEN = 32
SIGNATURE_LEN = 64
KEY_ID_LEN = 8
MAC_LEN = 32

# Named so a caller cannot typo a purpose into a different-but-valid key.
PURPOSE_EPOCH = "epoch"
PURPOSE_ORIGIN_EPHEMERAL = "origin-ephemeral"
PURPOSE_RELAY_PSEUDONYM = "relay-pseudonym"
PURPOSE_DEVICE_BINDING = "device-binding"
PURPOSE_ANCHOR_EPHEMERAL = "anchor-ephemeral"

PURPOSES = frozenset({
    PURPOSE_EPOCH,
    PURPOSE_ORIGIN_EPHEMERAL,
    PURPOSE_RELAY_PSEUDONYM,
    PURPOSE_DEVICE_BINDING,
    PURPOSE_ANCHOR_EPHEMERAL,
})

# Environment names. The active key signs; retired keys only verify, so a
# rotation is: add the new key as active, leave the old one retired until every
# signature it made has expired, then drop it. Nothing has to be re-signed.
ENV_ACTIVE = "PRESENCE_SIGNING_KEY"
ENV_RETIRED = "PRESENCE_RETIRED_SIGNING_KEYS"


class KeyMaterialError(Exception):
    """Key material is missing, malformed, or being used for the wrong thing."""


class SignatureError(Exception):
    """A signature did not verify. Deliberately not a subclass of the above."""


def _b64url_decode(text: str, expect: int, what: str) -> bytes:
    """Unpadded base64url in, exact-length bytes out.

    Unpadded because '=' in an environment variable or a JSON config is a
    persistent source of copy-paste corruption, and a length check catches the
    truncation that would otherwise silently produce a different key.
    """
    padded = text.strip() + "=" * (-len(text.strip()) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise KeyMaterialError("%s is not valid base64url: %s" % (what, exc))
    if len(raw) != expect:
        raise KeyMaterialError(
            "%s decoded to %d bytes, expected exactly %d" % (what, len(raw), expect)
        )
    return raw


def b64url(raw: bytes) -> str:
    """Unpadded base64url, for putting key material into configuration."""
    return base64.urlsafe_b64encode(bytes(raw)).decode("ascii").rstrip("=")


def key_id_for(public_bytes: bytes) -> bytes:
    """A key's identifier is derived from the key, not assigned to it.

    So a rotated key gets a new id automatically, two deployments naming the same
    public key agree on its id without coordinating, and an id in a signed struct
    can be checked against the key that supposedly produced it.
    """
    if len(public_bytes) != PUBLIC_KEY_LEN:
        raise KeyMaterialError(
            "public key is %d bytes, expected %d" % (len(public_bytes), PUBLIC_KEY_LEN)
        )
    return hashlib.sha256(DOMAIN + b"keyid" + bytes(public_bytes)).digest()[:KEY_ID_LEN]


@dataclass(frozen=True)
class VerifyKey:
    """A public key and its derived id. Can check a signature; cannot make one."""

    key_id: bytes
    public_bytes: bytes

    @classmethod
    def from_public_bytes(cls, public_bytes: bytes) -> "VerifyKey":
        raw = bytes(public_bytes)
        return cls(key_id=key_id_for(raw), public_bytes=raw)

    @classmethod
    def from_b64url(cls, text: str) -> "VerifyKey":
        return cls.from_public_bytes(
            _b64url_decode(text, PUBLIC_KEY_LEN, "public key")
        )

    def _key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.public_bytes)

    def verify(self, message: bytes, signature: bytes) -> None:
        """Raise SignatureError unless `signature` is valid over `message`.

        Raising rather than returning False, because `if verify(...)` reads as
        success and an accidentally-ignored return value would accept anything.
        `verifies()` exists for the places that genuinely want a boolean.
        """
        if len(signature) != SIGNATURE_LEN:
            raise SignatureError(
                "signature is %d bytes, expected %d" % (len(signature), SIGNATURE_LEN)
            )
        try:
            self._key().verify(bytes(signature), bytes(message))
        except InvalidSignature:
            raise SignatureError("signature does not verify under key %s" % (
                self.key_id.hex(),
            ))

    def verifies(self, message: bytes, signature: bytes) -> bool:
        try:
            self.verify(message, signature)
        except SignatureError:
            return False
        return True

    def to_b64url(self) -> str:
        return b64url(self.public_bytes)


@dataclass(frozen=True)
class SigningKey:
    """A private key. Holds the seed so it can be persisted or re-derived.

    `__repr__` is overridden because a dataclass would otherwise print the seed
    into a traceback, a log line or a Django debug page.
    """

    key_id: bytes
    seed: bytes

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls.from_seed(secrets.token_bytes(SEED_LEN))

    @classmethod
    def from_seed(cls, seed: bytes) -> "SigningKey":
        raw = bytes(seed)
        if len(raw) != SEED_LEN:
            raise KeyMaterialError(
                "signing seed is %d bytes, expected %d" % (len(raw), SEED_LEN)
            )
        _reject_secret_key_material(raw)
        public = (
            Ed25519PrivateKey.from_private_bytes(raw)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        return cls(key_id=key_id_for(public), seed=raw)

    @classmethod
    def from_b64url(cls, text: str) -> "SigningKey":
        return cls.from_seed(_b64url_decode(text, SEED_LEN, "signing seed"))

    def _key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(self.seed)

    def sign(self, message: bytes) -> bytes:
        """Sign canonical codec bytes.

        The message is expected to be the output of `codec.encode`, whose schema
        tag and version prefix provide domain separation. Nothing is prepended
        here; see the module docstring for why that is deliberate.
        """
        return self._key().sign(bytes(message))

    def public(self) -> VerifyKey:
        return VerifyKey(
            key_id=self.key_id,
            public_bytes=self._key().public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ),
        )

    def seed_b64url(self) -> str:
        """The seed, for writing into configuration. Handle as a secret."""
        return b64url(self.seed)

    def __repr__(self) -> str:
        return "SigningKey(key_id=%s, seed=<redacted>)" % (self.key_id.hex(),)


def _reject_secret_key_material(seed: bytes) -> None:
    """Refuse a seed that is a derivation of Django's SECRET_KEY.

    An ancestor commit in this repository derived signing material from
    SECRET_KEY. That couples presence signing to session cookies and password
    reset tokens: one rotation silently rotates the other, and one leak is two
    leaks. The obvious derivations are checked by value, because the failure mode
    of the coupling is that everything appears to work.
    """
    try:
        from django.conf import settings

        secret = settings.SECRET_KEY
    except Exception:
        return
    if not secret:
        return
    raw = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    candidates = (
        raw[:SEED_LEN],
        raw.ljust(SEED_LEN, b"\x00")[:SEED_LEN],
        hashlib.sha256(raw).digest(),
        hashlib.sha256(DOMAIN + raw).digest(),
    )
    for candidate in candidates:
        if len(candidate) == SEED_LEN and hmac.compare_digest(seed, candidate):
            raise KeyMaterialError(
                "this signing seed is derived from settings.SECRET_KEY. Presence "
                "signing must have its own key: set %s to an independent 32-byte "
                "seed (keys.SigningKey.generate().seed_b64url())." % ENV_ACTIVE
            )


class Keyring:
    """One active signing key and every key still valid for verification.

    Rotation without a flag day: signatures made minutes before a rotation must
    keep verifying until they expire, so retired keys stay verifiable and only
    the active key signs. Dropping a retired key is a separate, later decision -
    made when nothing it signed is still inside its validity window.
    """

    def __init__(self, active: SigningKey, retired: Iterable[VerifyKey] = ()):
        self._active = active
        self._verifiers: Dict[bytes, VerifyKey] = {}
        for key in retired:
            self._verifiers[key.key_id] = key
        # The active key verifies too, and it wins any id collision - which
        # cannot happen, since ids are derived from the keys themselves.
        self._verifiers[active.key_id] = active.public()

    @property
    def active(self) -> SigningKey:
        return self._active

    @property
    def key_ids(self) -> Tuple[bytes, ...]:
        return tuple(sorted(self._verifiers))

    def verifier(self, key_id: bytes) -> VerifyKey:
        try:
            return self._verifiers[bytes(key_id)]
        except KeyError:
            raise KeyMaterialError(
                "no key with id %s is known to this deployment; it may have been "
                "retired and removed, or the signature may be forged"
                % (bytes(key_id).hex(),)
            )

    def sign(self, message: bytes) -> Tuple[bytes, bytes]:
        """Sign with the active key. Returns (key_id, signature).

        The id travels with the signature so a verifier can pick the right key
        without trying all of them, which also keeps a rotation from turning into
        a verification cost that grows with history.
        """
        return self._active.key_id, self._active.sign(message)

    def verify(self, key_id: bytes, message: bytes, signature: bytes) -> None:
        self.verifier(key_id).verify(message, signature)

    @classmethod
    def ephemeral(cls) -> "Keyring":
        """A fresh in-memory keyring. For tests and for local development.

        Nothing it signs survives a process restart, which is the honest
        behaviour for material that was never configured. It is never reachable
        outside DEBUG - see `from_environment`.
        """
        return cls(active=SigningKey.generate())

    @classmethod
    def from_environment(cls, env: Optional[Dict[str, str]] = None) -> "Keyring":
        """Load from the environment, or fail.

        There is no production fallback on purpose. A generated-on-boot key would
        invalidate every signature on every restart and every scale-out, and the
        failure would look like a forged proof rather than a missing key.
        """
        source = os.environ if env is None else env
        active_raw = (source.get(ENV_ACTIVE) or "").strip()
        if not active_raw:
            if _debug_enabled():
                logger.warning(
                    "%s is not set: using an ephemeral presence signing key. "
                    "Signatures will not survive a restart. Set %s for anything "
                    "that has to persist.", ENV_ACTIVE, ENV_ACTIVE,
                )
                return cls.ephemeral()
            raise KeyMaterialError(
                "%s is not set. Generate one with "
                "keys.SigningKey.generate().seed_b64url() and set it in the "
                "environment. There is deliberately no default and no fallback "
                "to SECRET_KEY." % ENV_ACTIVE
            )

        active = SigningKey.from_b64url(active_raw)
        retired = []
        for chunk in (source.get(ENV_RETIRED) or "").split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            # Retired entries are seeds too, not public keys: rotation usually
            # means "stop signing with this", and keeping the seed means an
            # operator can re-activate it if the new key turns out to be wrong.
            retired.append(SigningKey.from_b64url(chunk).public())
        return cls(active=active, retired=retired)


def _debug_enabled() -> bool:
    try:
        from django.conf import settings

        return bool(settings.DEBUG)
    except Exception:
        return False


# --- Derivation -----------------------------------------------------------

def derive(
    secret: bytes,
    *,
    purpose: str,
    length: int = SEED_LEN,
    salt: bytes = b"",
    context: bytes = b"",
) -> bytes:
    """HKDF-SHA256 with a named purpose.

    `purpose` must be one of PURPOSES. An unrecognised string would otherwise
    derive a perfectly valid key that simply is not the one the other side
    derived, and the resulting failure looks like tampering rather than a typo.

    `salt` is the natural per-session value (the session id), `context` the
    per-item value (an epoch number, an anchor reference). Both go into distinct
    HKDF inputs rather than being concatenated by the caller, so no pair of
    different (salt, context) can collide into the same derivation.
    """
    if purpose not in PURPOSES:
        raise KeyMaterialError(
            "unknown derivation purpose %r; add it to PURPOSES if it is real"
            % (purpose,)
        )
    if not 1 <= length <= 64:
        raise KeyMaterialError("derived length %d is outside 1..64" % length)
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
        raise KeyMaterialError("derivation input must be at least 16 bytes")
    info = DOMAIN + purpose.encode("ascii") + b"\x00" + bytes(context)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=bytes(salt),
        info=info,
    ).derive(bytes(secret))


def mac(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256. The full 32 bytes."""
    return hmac.new(bytes(key), bytes(message), hashlib.sha256).digest()


def mac_truncated(key: bytes, message: bytes, length: int) -> bytes:
    """A prefix of the HMAC.

    Truncation is a real reduction in strength and it is deliberate here: a
    challenge has to fit in a QR code a phone can read across a classroom. Eight
    bytes is what the challenge chain uses, for a value that expires in seconds,
    is single-use, and is checked against a server-side sequence window - so a
    forgery attempt is bounded by rate limiting rather than by brute force alone.
    Do not reuse this for anything long-lived.
    """
    if not 1 <= length <= MAC_LEN:
        raise KeyMaterialError("MAC truncation %d is outside 1..%d" % (length, MAC_LEN))
    return mac(key, message)[:length]


def equal(left: bytes, right: bytes) -> bool:
    """Constant-time comparison, for anything an attacker can iterate against."""
    return hmac.compare_digest(bytes(left), bytes(right))


@dataclass(frozen=True)
class SessionKeys:
    """Per-session material: one secret for challenges, one key for signing them.

    Both halves are held by the server and by the teacher's device, which is what
    lets the teacher generate challenges with no connectivity. Both are therefore
    secrets at rest in the database: a database compromise lets an attacker mint
    challenges for a session, though not sign a proof as any student, since
    device private keys never leave their handsets. That asymmetry is the point
    of keeping the two hierarchies separate, and it is recorded in the threat
    model rather than left implied.
    """

    session_id: bytes
    root_secret: bytes
    signing: SigningKey

    @classmethod
    def generate(cls, session_id: bytes) -> "SessionKeys":
        return cls(
            session_id=_check_session_id(session_id),
            root_secret=secrets.token_bytes(SEED_LEN),
            signing=SigningKey.generate(),
        )

    @classmethod
    def load(cls, session_id: bytes, root_secret: bytes, signing_seed: bytes) -> "SessionKeys":
        raw = bytes(root_secret)
        if len(raw) != SEED_LEN:
            raise KeyMaterialError(
                "session root secret is %d bytes, expected %d" % (len(raw), SEED_LEN)
            )
        return cls(
            session_id=_check_session_id(session_id),
            root_secret=raw,
            signing=SigningKey.from_seed(signing_seed),
        )

    def epoch_key(self, epoch: int) -> bytes:
        """The key the challenge chain runs on for one epoch.

        Separate per epoch so that a leaked epoch key - a compromised teacher
        handset mid-lesson, a challenge chain recovered from a screen recording -
        does not yield the challenges of any other epoch, in either direction.
        """
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
            raise KeyMaterialError("epoch must be a non-negative integer")
        return derive(
            self.root_secret,
            purpose=PURPOSE_EPOCH,
            salt=self.session_id,
            context=epoch.to_bytes(8, "big"),
        )

    def public(self) -> VerifyKey:
        """What a student's device needs, and all it needs, to check a challenge."""
        return self.signing.public()

    def __repr__(self) -> str:
        return "SessionKeys(session_id=%s, root_secret=<redacted>, signing=%r)" % (
            self.session_id.hex(),
            self.signing,
        )


def _check_session_id(session_id: bytes) -> bytes:
    raw = bytes(session_id)
    if len(raw) != 16:
        raise KeyMaterialError(
            "session id is %d bytes, expected 16 (a UUID)" % (len(raw),)
        )
    return raw


# --- Process-wide server keyring ------------------------------------------

_keyring: Optional[Keyring] = None


def server_keyring() -> Keyring:
    """The deployment's signing keyring, loaded once."""
    global _keyring
    if _keyring is None:
        _keyring = Keyring.from_environment()
    return _keyring


def set_server_keyring(keyring: Optional[Keyring]) -> None:
    """Install a keyring, or clear the cache with None.

    Tests need a deterministic keyring, and a test that mutated the environment
    and hoped for a reload would depend on import order.
    """
    global _keyring
    _keyring = keyring
