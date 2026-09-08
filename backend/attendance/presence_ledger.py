"""Django-backed replay ledger.

The protocol package under `attendance/presence/` is deliberately free of Django:
a proof must be re-derivable by anything holding the same bytes and the same
config artifact, including a simulator, a script or a future second
implementation, and an import of the ORM would quietly make that untrue. So the
storage adapter lives out here, on the application side of that line, and the
package keeps its abstract `Ledger` with an in-memory implementation for tests.

What this adds over `replay.MemoryLedger` is durability, and durability is not a
nicety here. The in-memory ledger forgets every nonce it was remembering when the
process restarts, and a forgotten nonce is a replay window. A deployment that ran
on it would hand an attacker a fresh chance at every proof it had ever seen with
each redeploy.

Uniqueness is enforced by the database, not by this module. `record` inserts and
lets the constraint refuse, then reads the row back to say which rule was broken.
The alternative - check, then write - is two statements with a gap between them,
and two copies of the same proof arriving in that gap is the ordinary case for an
offline queue that has just found signal, not an exotic one.
"""
from django.db import IntegrityError, transaction

from .models import ReplayEntry, StepHighWater
from .presence import replay


def _hex(raw: bytes) -> str:
    """Bytes to lowercase hex, tolerating whatever the caller had.

    `bytes(...)` first because a value round-tripped through some backends
    arrives as a memoryview, and `memoryview.hex()` exists but `.hex()` on a
    bytearray slice of the wrong length would pass unnoticed. Length is checked by
    the model validators and by the protocol package; this only normalises type.
    """
    return bytes(raw).hex()


def _entry(row: ReplayEntry) -> replay.Entry:
    return replay.Entry(
        digest=bytes.fromhex(row.digest),
        session_id=bytes.fromhex(row.session_id),
        device_key_id=bytes.fromhex(row.device_key_id),
        nonce=bytes.fromhex(row.nonce),
        step=row.step,
        received_at=row.received_at,
    )


class DjangoLedger(replay.Ledger):
    """The deployment's ledger: `presence_replay_entries` plus its high-water table."""

    def seen_digest(self, digest: bytes):
        row = ReplayEntry.objects.filter(digest=_hex(digest)).first()
        return _entry(row) if row else None

    def seen_nonce(self, device_key_id: bytes, nonce: bytes):
        row = ReplayEntry.objects.filter(
            device_key_id=_hex(device_key_id), nonce=_hex(nonce),
        ).first()
        return _entry(row) if row else None

    def highest_step(self, session_id: bytes, device_key_id: bytes):
        row = StepHighWater.objects.filter(
            session_id=_hex(session_id), device_key_id=_hex(device_key_id),
        ).first()
        return row.step if row else None

    def record(self, entry: replay.Entry) -> None:
        """Persist, or raise. The single point at which uniqueness is decided."""
        digest, nonce = _hex(entry.digest), _hex(entry.nonce)
        device = _hex(entry.device_key_id)
        session = _hex(entry.session_id)
        try:
            # Nested atomic so the constraint violation rolls back only this
            # insert. Without it the failure marks the whole surrounding
            # transaction unusable, and the caller's next query - including the
            # two lookups below, which exist to explain the failure - would raise
            # instead of answering.
            with transaction.atomic():
                ReplayEntry.objects.create(
                    digest=digest, session_id=session, device_key_id=device,
                    nonce=nonce, step=entry.step, received_at=entry.received_at,
                )
        except IntegrityError:
            # Same order the in-memory ledger checks in, because the reason code
            # travels back to the client and the two implementations must not
            # disagree about which rule a duplicate broke.
            if ReplayEntry.objects.filter(digest=digest).exists():
                raise replay.ReplayError(
                    replay.DUPLICATE_PROOF,
                    "a proof with digest %s is already recorded" % digest,
                )
            if ReplayEntry.objects.filter(device_key_id=device, nonce=nonce).exists():
                raise replay.ReplayError(
                    replay.NONCE_REUSED,
                    "device %s has already submitted a proof with this nonce" % device,
                )
            raise
        self._raise_high_water(session, device, entry.step)

    @staticmethod
    def _raise_high_water(session: str, device: str, step: int) -> None:
        """Move the mark forward, never back, without holding a lock.

        The `step__lt` filter is what makes this safe under concurrency: two
        proofs landing at once both attempt the update and only the one carrying
        the larger step changes anything, whichever order they arrive in. A
        read-modify-write would let the smaller one win by finishing last.
        """
        row, created = StepHighWater.objects.get_or_create(
            session_id=session, device_key_id=device, defaults={'step': step},
        )
        if not created and step > row.step:
            StepHighWater.objects.filter(pk=row.pk, step__lt=step).update(step=step)

    def prune(self, before: int) -> int:
        """Forget entries received before `before`. Returns how many.

        High-water marks are deliberately left alone. They are one integer per
        device per session, and dropping one would forget how far that device had
        got - which is the step regression this ledger exists to refuse, reopened
        by the very housekeeping meant to keep it tidy.
        """
        deleted, _ = ReplayEntry.objects.filter(received_at__lt=before).delete()
        return deleted

    def __len__(self) -> int:
        return ReplayEntry.objects.count()
