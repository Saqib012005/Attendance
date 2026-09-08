"""Tests for the hard gates.

Five claims are being pinned here, and two of them are claims about what this
module deliberately does *not* do.

**A refusal names the check that failed, not the layer that noticed.** A proof
turned away for a bad signature is recorded as `proof_bad_signature`, not as some
generic gate error, even though `gates.clear` is what raised it. `BorrowedTests`
walks the whole borrowed vocabulary.

**Nothing is written until everything else has passed.** `replay.admit` is the
only writer and it runs last. `OrderingTests` asserts that a proof refused for any
earlier reason leaves the ledger empty, so replaying one malformed copy of a
submission cannot burn the nonce the genuine copy needs.

**Attached evidence can be dropped; it cannot reject.** A rogue device can append
a hop to anyone's chain, so a chain that fails to verify costs the student some
evidence and never the lesson. `DropTests` covers each way that happens.

**A failed biometric is admitted.** It is evidence with a reason code, not a
closed door, and `BiometricTests` fails if that ever becomes a refusal.

**The four fail-closed properties the plan asks for converge here.**
`FailClosedTests` names them one test each - forged chain, replayed challenge,
reordered sequence, truncated signature - because this is the module where all
four become one coded rejection at the API boundary, and because "fails closed"
should be four readable assertions rather than a sentence in a document.
"""
import json
import pathlib
from dataclasses import replace
from types import MappingProxyType

from django.test import SimpleTestCase

from .presence import chain, challenge, codec, config, gates, keys, origin, proof, replay

SESSION_ID = bytes(range(proof.SESSION_ID_LEN))
OTHER_SESSION = bytes(range(proof.SESSION_ID_LEN))[::-1]
ROOT_SECRET = b"gate-root-secret".ljust(keys.SEED_LEN, b".")
SIGNING_SEED = b"gate-signing-seed".ljust(keys.SEED_LEN, b".")

# A fixed instant and a fixed step, so nothing depends on when the suite runs.
START = 1_757_000_000
SEQ = 4

def artifact_with(**overrides):
    """The shipped artifact with substitutions, under a version of its own."""
    values = dict(config.active().values)
    values.update(overrides)
    return config.Artifact(
        version="test-artifact",
        calibration=config.UNCALIBRATED,
        notes="built by tests_presence_gates",
        values=MappingProxyType(values),
    )


class Case(SimpleTestCase):
    def setUp(self):
        self.keys = keys.SessionKeys.load(SESSION_ID, ROOT_SECRET, SIGNING_SEED)
        self.timing = challenge.Timing.active()
        self.bounds = replay.Bounds.active()
        self.device = keys.SigningKey.from_seed(b"gate-device".ljust(keys.SEED_LEN, b"."))
        self.impostor = keys.SigningKey.from_seed(
            b"gate-impostor".ljust(keys.SEED_LEN, b".")
        )
        self.relays = [
            keys.SigningKey.from_seed(bytes([n]) * keys.SEED_LEN) for n in (71, 72)
        ]
        self.stranger = keys.SigningKey.from_seed(bytes([99]) * keys.SEED_LEN)
        self.ledger = replay.MemoryLedger()
        self.context = gates.SessionContext(
            session_keys=self.keys, session_start=START
        )

    def tearDown(self):
        config.set_active(None)

    # --- fixture helpers ----------------------------------------------------

    def source(self):
        return pathlib.Path(gates.__file__).read_text(encoding="utf-8")

    def at(self, seq=SEQ):
        """A plausible instant inside step `seq`."""
        return START + seq * self.timing.step_seconds + 1

    def value_for(self, seq=SEQ, epoch=None):
        found = challenge.epoch_of(seq, self.timing) if epoch is None else epoch
        return challenge.challenge_value(
            self.keys.epoch_key(found), SESSION_ID, found, seq
        )

    def sighting(self, seq=SEQ, *, rssi=-65, at=None, session_keys=None):
        emitter = session_keys or self.keys
        frame = origin.build(emitter, counter=seq, timing=self.timing)
        return origin.record(
            frame, rssi=rssi, observed_at=self.at(seq) if at is None else at
        )

    def hops(self, root, devices=None, *, session_id=SESSION_ID, at=None):
        built = ()
        moment = self.at() if at is None else at
        chosen = self.relays if devices is None else devices
        for index, device in enumerate(chosen):
            built = chain.extend(
                built,
                root=root,
                session_id=session_id,
                observed_at=moment + index,
                signing_key=device,
            )
        return built

    def cohort(self, devices=None):
        chosen = self.relays if devices is None else devices
        return chain.cohort_index(
            SESSION_ID, [d.public() for d in chosen]
        ).get

    def relayed(self, **over):
        """A sighting, a two-hop chain rooted in it, and a proof over both."""
        seen = self.sighting()
        bodies = (seen.encode(),) + chain.encode_chain(
            self.hops(chain.root_link(seen.encode()))
        )
        return bodies, self.signed(observations=bodies, **over)

    def signed(
        self,
        *,
        seq=SEQ,
        epoch=None,
        value=None,
        observations=(),
        device=None,
        session_id=SESSION_ID,
        captured_at=None,
        biometric=None,
        capabilities=None,
        claims=None,
        nonce=None,
    ):
        signer = self.device if device is None else device
        built = proof.build(
            session_id=session_id,
            device_key_id=signer.public().key_id,
            challenge=self.value_for(seq) if value is None else value,
            challenge_epoch=(
                challenge.epoch_of(seq, self.timing) if epoch is None else epoch
            ),
            challenge_seq=seq,
            captured_at=self.at(seq) if captured_at is None else captured_at,
            biometric=proof.BIOMETRIC_SUCCESS if biometric is None else biometric,
            platform=proof.PLATFORM_ANDROID,
            capabilities=(
                proof.CAP_BIOMETRIC | proof.CAP_RELAY
                if capabilities is None
                else capabilities
            ),
            nonce=nonce,
            claims=claims,
            observations=proof.observation_digests(*observations),
        )
        return proof.sign(built, signer)

    def registered(self, device=None, **flags):
        key = (self.device if device is None else device).public()
        return lambda key_id: gates.Registration(verify_key=key, **flags)

    def clear(self, signed, **over):
        settings = dict(
            context=self.context,
            resolve_device=self.registered(),
            ledger=self.ledger,
            received_at=self.at() + 1,
            observations=(),
            resolve_relay=None,
            timing=self.timing,
        )
        settings.update(over)
        signature = settings.pop("signature", signed.signature)
        body = settings.pop("body", signed.body)
        return gates.clear(body, signature, **settings)

    def refused(self, code, signed, **over):
        with self.assertRaises(gates.GateError) as caught:
            self.clear(signed, **over)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception

    def mutated(self, **over):
        """A signed proof carrying a field an honest builder refuses to produce.

        `proof.build` and `proof.parse` share `_check_semantics`, so there is no
        way to reach the gate with one of these except by going around the builder
        - which is exactly what a newer client, or a hostile one, would be doing.
        The dataclass constructor applies no semantics, and `proof.sign` checks
        only that the body names the key doing the signing.
        """
        honest = proof.parse(self.signed().body)
        return proof.sign(replace(honest, **over), self.device)

    def only_drop(self, cleared):
        self.assertEqual(len(cleared.dropped), 1, cleared.describe())
        return cleared.dropped[0]


class AdmissionTests(Case):
    def test_an_honest_proof_with_no_radio_evidence_at_all_clears(self):
        """The ordinary case on this scope: QR, biometric, device key, nothing else.

        Decision 3 in one assertion. Every platform is in degraded mode until the
        BLE phases land, so if a proof carrying no sighting and no chain did not
        clear here, the system would have no users.
        """
        cleared = self.clear(self.signed())
        self.assertEqual(cleared.sightings, ())
        self.assertEqual(cleared.hops, ())
        self.assertEqual(cleared.dropped, ())
        self.assertEqual(cleared.signals, ())
        self.assertEqual(len(self.ledger), 1)

    def test_a_relayed_proof_clears_with_the_depth_the_server_derived(self):
        bodies, signed = self.relayed()
        cleared = self.clear(
            signed, observations=bodies, resolve_relay=self.cohort()
        )
        self.assertEqual(len(cleared.sightings), 1)
        self.assertEqual(len(cleared.hops), len(self.relays))
        self.assertEqual(cleared.dropped, ())
        self.assertEqual(cleared.describe()["relay_depth"], len(self.relays))

    def test_a_proof_that_sat_in_a_queue_for_a_day_still_clears(self):
        """The deliberate absence of an expiry check, asserted rather than trusted.

        A challenge expires in seconds; an offline queue drains in hours. If
        `verify_committed` re-checked expiry, every proof the offline path exists
        to carry would be refused on arrival. The bound that does apply is
        `proof.max_offline_hours`, and it is enforced once, in `replay`.
        """
        step_start = challenge.step_bounds(START, SEQ, self.timing)[0]
        cleared = self.clear(
            self.signed(), received_at=step_start + self.bounds.max_offline_seconds
        )
        self.assertEqual(
            cleared.receipt.queued_seconds, self.bounds.max_offline_seconds
        )

    def test_a_proof_older_than_the_offline_bound_is_refused_once(self):
        step_start = challenge.step_bounds(START, SEQ, self.timing)[0]
        self.refused(
            replay.TOO_OLD,
            self.signed(),
            received_at=step_start + self.bounds.max_offline_seconds + 1,
        )

    def test_the_decision_records_the_configuration_that_produced_it(self):
        """No decision without the parameters behind it, and no timing argument
        needed to get them: omitting `timing` reads the active artifact."""
        config.set_active(artifact_with())
        cleared = self.clear(self.signed(), timing=None)
        self.assertEqual(cleared.config_version, "test-artifact")
        self.assertEqual(cleared.config_version, challenge.Timing.active().version)


class DeviceTests(Case):
    def test_a_proof_from_a_key_nobody_registered_is_refused(self):
        self.refused(
            gates.UNKNOWN_DEVICE, self.signed(), resolve_device=lambda key_id: None
        )

    def test_a_revoked_device_and_an_unenrolled_one_are_told_apart(self):
        """Three facts, three codes, for the reason `Registration` gives: a student
        who transferred class must not read as a stolen device."""
        self.refused(
            gates.DEVICE_REVOKED, self.signed(), resolve_device=self.registered(revoked=True)
        )
        self.refused(
            gates.DEVICE_NOT_ENROLLED,
            self.signed(),
            resolve_device=self.registered(enrolled=False),
        )

    def test_a_key_the_resolver_returned_that_the_body_does_not_name_is_refused(self):
        """The shape a resolver keyed on an outer transport field would produce.

        This proof is internally perfect: the impostor built it, named its own key
        and signed it. It is refused because the registration handed back belongs
        to a different device, which is the check that stops a genuine signature by
        device A from being accepted as device B's attendance. `proof.sign` refuses
        to produce the mirror image of this - a body naming one device and signed
        by another - so that half cannot be constructed here at all.
        """
        self.refused(proof.KEY_MISMATCH, self.signed(device=self.impostor))

    def test_the_resolver_is_asked_for_the_key_the_body_names(self):
        asked = []

        def resolve(key_id):
            asked.append(key_id)
            return gates.Registration(verify_key=self.device.public())

        self.clear(self.signed(), resolve_device=resolve)
        self.assertEqual(asked, [self.device.public().key_id])


class ChallengeTests(Case):
    def test_a_challenge_value_this_session_never_produced_is_refused(self):
        self.refused(
            challenge.FORGED, self.signed(value=bytes(challenge.CHALLENGE_LEN))
        )

    def test_a_step_the_session_has_not_reached_is_refused(self):
        """Well-formed and unreachable. The value is derived correctly for step 40,
        so nothing about the bytes is wrong; the session is only at step 4."""
        ahead = SEQ + self.timing.steps_per_epoch * 2
        self.refused(challenge.FUTURE_STEP, self.signed(seq=ahead))

    def test_an_epoch_that_does_not_belong_to_the_sequence_is_refused(self):
        self.refused(challenge.TIMING_INCONSISTENT, self.signed(epoch=1))

    def test_a_proof_for_another_session_is_refused_by_the_binding(self):
        self.refused(proof.SESSION_MISMATCH, self.signed(session_id=OTHER_SESSION))

    def test_the_value_is_re_derived_and_never_taken_from_the_proof(self):
        """Server-side re-derivation, stated as an equality the client cannot reach.

        The proof carries eight bytes. They are accepted only because the server
        recomputed them from its own epoch key, which is why a screenshot of a QR
        code cannot be turned into a valid proof for a different step.
        """
        epoch = challenge.epoch_of(SEQ, self.timing)
        derived = challenge.challenge_value(
            self.keys.epoch_key(epoch), SESSION_ID, epoch, SEQ
        )
        cleared = self.clear(self.signed())
        self.assertEqual(cleared.signed.proof.challenge, derived)
        for seq in (SEQ - 1, SEQ + 1):
            with self.subTest(seq=seq):
                self.assertNotEqual(derived, self.value_for(seq))


class SessionOpenTests(Case):
    def test_a_step_that_begins_after_the_teacher_ended_the_session_is_refused(self):
        """The fact no challenge records. Step 4 is arithmetically impeccable and
        the session was over before it started."""
        step_start = challenge.step_bounds(START, SEQ, self.timing)[0]
        closed = gates.SessionContext(self.keys, START, closed_at=step_start - 1)
        self.refused(gates.SESSION_NOT_OPEN, self.signed(), context=closed)

    def test_a_step_that_began_before_the_session_ended_still_clears(self):
        step_start = challenge.step_bounds(START, SEQ, self.timing)[0]
        closed = gates.SessionContext(self.keys, START, closed_at=step_start + 1)
        self.clear(self.signed(), context=closed)

    def test_a_step_beginning_exactly_at_the_close_is_refused(self):
        """The boundary is stated once here so it cannot drift silently."""
        step_start = challenge.step_bounds(START, SEQ, self.timing)[0]
        closed = gates.SessionContext(self.keys, START, closed_at=step_start)
        self.refused(gates.SESSION_NOT_OPEN, self.signed(), context=closed)

    def test_a_session_that_closed_before_it_opened_cannot_be_constructed(self):
        with self.assertRaises(gates.GateError) as caught:
            gates.SessionContext(self.keys, START, closed_at=START - 1)
        self.assertEqual(caught.exception.code, gates.SESSION_NOT_OPEN)

    def test_a_session_start_that_is_not_an_integer_cannot_be_constructed(self):
        for bad in (None, "1757000000", 1.5, True):
            with self.subTest(start=bad):
                with self.assertRaises(gates.GateError) as caught:
                    gates.SessionContext(self.keys, bad)
                self.assertEqual(caught.exception.code, gates.SESSION_NOT_OPEN)


class BorrowedTests(Case):
    """The vocabulary. One exception type out, and the failing check's own code."""

    def test_the_refusal_vocabulary_is_exactly_the_union_it_claims_to_be(self):
        self.assertEqual(
            gates.REASON_CODES,
            gates.OWN_REASON_CODES
            | proof.REASON_CODES
            | challenge.REASON_CODES
            | replay.REASON_CODES,
        )
        for code in gates.OWN_REASON_CODES:
            with self.subTest(code=code):
                self.assertTrue(code.startswith("gate_"), code)
        for code in gates.BORROWED_REASON_CODES:
            with self.subTest(code=code):
                self.assertFalse(code.startswith("gate_"), code)

    def test_no_code_can_mean_both_a_refusal_and_a_dropped_observation(self):
        """An audit record carries one code, so one code must mean one thing.

        If a code appeared in both sets, reading a stored reason would not tell you
        whether the proof was rejected or merely lost some evidence - which are
        opposite outcomes for the student.
        """
        self.assertEqual(gates.DROP_REASONS & gates.REASON_CODES, frozenset())

    def test_a_signal_is_never_a_refusal_and_never_a_drop(self):
        self.assertEqual(gates.SIGNALS & gates.REASON_CODES, frozenset())
        self.assertEqual(gates.SIGNALS & gates.DROP_REASONS, frozenset())

    def test_an_undeclared_code_cannot_be_raised_dropped_or_signalled(self):
        with self.assertRaises(AssertionError):
            gates.GateError("gate_made_up", "not in the vocabulary")
        with self.assertRaises(AssertionError):
            gates.Dropped(0, "relay_hop", "chain_made_up", "not in the vocabulary")
        cleared = self.clear(self.signed())
        with self.assertRaises(AssertionError):
            replace(cleared, signals=("signal_made_up",))

    def test_an_exception_that_is_not_a_declared_refusal_is_not_disguised(self):
        """`_refuse` translates; it does not swallow. A bug in a composed module
        must surface as that bug rather than as a rejected student."""
        with self.assertRaises(ValueError):
            gates._refuse(ValueError("something else went wrong"))
        with self.assertRaises(chain.ChainError):
            gates._refuse(chain.ChainError(chain.MALFORMED, "not a gate refusal"))


class OrderingTests(Case):
    """`replay.admit` writes, so it runs last. This class is that ordering."""

    def earlier_refusals(self):
        """One representative refusal per gate that runs before the ledger."""
        step_start = challenge.step_bounds(START, SEQ, self.timing)[0]
        honest = self.signed()
        bodies, relayed = self.relayed()
        ahead = SEQ + self.timing.steps_per_epoch * 2
        return (
            ("malformed body", honest, dict(body=b"not a proof at all")),
            ("unregistered device", honest, dict(resolve_device=lambda key_id: None)),
            ("revoked device", honest, dict(resolve_device=self.registered(revoked=True))),
            ("unenrolled device", honest, dict(resolve_device=self.registered(enrolled=False))),
            ("truncated signature", honest, dict(signature=honest.signature[:-1])),
            ("another session", self.signed(session_id=OTHER_SESSION), {}),
            ("forged challenge", self.signed(value=bytes(challenge.CHALLENGE_LEN)), {}),
            ("unreached step", self.signed(seq=ahead), {}),
            (
                "ended session",
                honest,
                dict(context=gates.SessionContext(self.keys, START, closed_at=step_start - 1)),
            ),
            (
                "uncommitted observation",
                relayed,
                dict(
                    observations=bodies + (self.sighting(rssi=-40).encode(),),
                    resolve_relay=self.cohort(),
                ),
            ),
        )

    def test_a_proof_refused_by_any_earlier_gate_leaves_the_ledger_untouched(self):
        for label, signed, over in self.earlier_refusals():
            with self.subTest(gate=label):
                ledger = replay.MemoryLedger()
                with self.assertRaises(gates.GateError):
                    self.clear(signed, ledger=ledger, **over)
                self.assertEqual(len(ledger), 0)
                self.assertIsNone(
                    ledger.highest_step(SESSION_ID, self.device.public().key_id)
                )

    def test_a_damaged_copy_cannot_burn_the_nonce_the_genuine_proof_needs(self):
        """Why the write is last, stated as the attack it prevents.

        Anyone who can see one submission can resubmit it with the signature
        damaged. If the ledger were written before the signature check, that copy
        would consume the nonce and the student's real proof would arrive as a
        duplicate - a denial of attendance requiring no key material at all.
        """
        signed = self.signed()
        for damaged in (
            signed.signature[:-1],
            bytes(keys.SIGNATURE_LEN),
            signed.signature[::-1],
        ):
            with self.subTest(length=len(damaged)):
                self.refused(proof.BAD_SIGNATURE, signed, signature=damaged)
        self.assertEqual(len(self.ledger), 0)
        cleared = self.clear(signed)
        self.assertEqual(len(self.ledger), 1)
        self.assertEqual(cleared.receipt.entry.nonce, signed.proof.nonce)

    def test_the_same_proof_twice_is_a_duplicate_and_the_ledger_does_not_grow(self):
        signed = self.signed()
        self.clear(signed)
        self.refused(replay.DUPLICATE_PROOF, signed)
        self.assertEqual(len(self.ledger), 1)

    def test_two_different_proofs_sharing_a_nonce_are_refused_as_nonce_reuse(self):
        """Reported as reuse rather than as a duplicate, because the two need
        different things from the client: one retry is safe, the other is a bug."""
        nonce = bytes(range(replay.NONCE_LEN))
        first = self.signed(nonce=nonce)
        second = self.signed(nonce=nonce, captured_at=self.at() + 1)
        self.assertNotEqual(first.proof.digest(), second.proof.digest())
        self.clear(first)
        self.refused(replay.NONCE_REUSED, second)

    def test_a_step_this_device_has_already_passed_is_refused(self):
        later = SEQ + 4
        arrival = self.at(later) + 1
        self.clear(self.signed(seq=later), received_at=arrival)
        self.refused(replay.STEP_REGRESSION, self.signed(), received_at=arrival)

    def test_evidence_is_sorted_before_the_write_and_a_drop_does_not_stop_it(self):
        """A dropped observation is not a reason to skip the ledger. The proof was
        admitted, so it is counted, and the drop is recorded beside it."""
        bodies, signed = self.relayed()
        cleared = self.clear(signed, observations=bodies, resolve_relay=None)
        self.assertEqual(len(self.ledger), 1)
        self.assertEqual(self.only_drop(cleared).code, chain.UNKNOWN_RELAY)


class DropTests(Case):
    """Attached evidence that fails costs evidence, never the lesson."""

    def test_a_chain_with_no_cohort_resolver_is_dropped_not_trusted(self):
        """The handset's structural check is real and weaker. The server does not
        promote the weaker result to the stronger one just because it is all it has.
        """
        bodies, signed = self.relayed()
        cleared = self.clear(signed, observations=bodies, resolve_relay=None)
        self.assertEqual(cleared.hops, ())
        self.assertEqual(len(cleared.sightings), 1)
        self.assertEqual(self.only_drop(cleared).code, chain.UNKNOWN_RELAY)

    def test_a_hop_signed_by_a_device_outside_the_cohort_is_dropped(self):
        seen = self.sighting()
        hops = self.hops(chain.root_link(seen.encode()), devices=[self.stranger])
        bodies = (seen.encode(),) + chain.encode_chain(hops)
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            resolve_relay=self.cohort(),
        )
        self.assertEqual(cleared.hops, ())
        self.assertEqual(self.only_drop(cleared).code, chain.UNKNOWN_RELAY)

    def test_a_reordered_chain_is_dropped_as_reordered(self):
        seen = self.sighting()
        wire = chain.encode_chain(self.hops(chain.root_link(seen.encode())))
        bodies = (seen.encode(),) + tuple(reversed(wire))
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            resolve_relay=self.cohort(),
        )
        self.assertEqual(self.only_drop(cleared).code, chain.OUT_OF_ORDER)

    def test_a_chain_with_no_verified_sighting_to_root_it_is_dropped(self):
        """The root is discovered, not asserted. Nothing roots this one."""
        seen = self.sighting()
        bodies = chain.encode_chain(self.hops(chain.root_link(seen.encode())))
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            resolve_relay=self.cohort(),
        )
        self.assertEqual(self.only_drop(cleared).code, chain.BROKEN_LINK)

    def test_a_sighting_from_another_session_is_dropped_and_unroots_its_chain(self):
        """Two drops from one body, and the second is the more interesting.

        A frame emitted by the lecture next door fails the session check, so it
        never joins the verified set - and the chain rooted in it therefore has
        nothing to root it. That is the root-discovery logic doing its job: the
        server is not told which sighting a chain hangs from, it finds out, and a
        chain that hangs from nothing it accepted is unrooted.
        """
        elsewhere = keys.SessionKeys.load(OTHER_SESSION, ROOT_SECRET, SIGNING_SEED)
        seen = self.sighting(session_keys=elsewhere)
        bodies = (seen.encode(),) + chain.encode_chain(
            self.hops(chain.root_link(seen.encode()))
        )
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            resolve_relay=self.cohort(),
        )
        self.assertEqual(cleared.sightings, ())
        self.assertEqual(cleared.hops, ())
        self.assertEqual(
            [(d.index, d.code) for d in cleared.dropped],
            [(0, origin.WRONG_SESSION), (1, chain.BROKEN_LINK)],
        )

    def test_a_body_this_build_has_no_verifier_for_is_dropped_by_name(self):
        """Forward compatibility, in the safe direction. A newer client attaching
        an anchor reading gets it set aside rather than getting its proof refused.
        """
        bodies = (
            codec.encode(
                codec.DEVICE_REGISTRATION.name,
                {
                    "student_ref": 1,
                    "public_key": self.stranger.public().public_bytes,
                    "platform": proof.PLATFORM_ANDROID,
                    "capabilities": 0,
                    "created_at": START,
                    "nonce": bytes(replay.NONCE_LEN),
                },
            ),
        )
        cleared = self.clear(
            self.signed(observations=bodies), observations=bodies
        )
        drop = self.only_drop(cleared)
        self.assertEqual(drop.code, gates.UNRECOGNISED_OBSERVATION)
        self.assertEqual(drop.kind, codec.DEVICE_REGISTRATION.name)

    def test_bytes_that_are_no_schema_at_all_are_dropped_as_unrecognised(self):
        bodies = (b"\x00not a canonical struct",)
        cleared = self.clear(
            self.signed(observations=bodies), observations=bodies
        )
        drop = self.only_drop(cleared)
        self.assertEqual(drop.code, gates.UNRECOGNISED_OBSERVATION)
        self.assertEqual(drop.kind, "unrecognised")

    def test_no_relay_evidence_and_failed_relay_evidence_are_told_apart(self):
        """Both end with `hops == ()`, and a decision layer must not read them
        alike: one handset could not relay, the other tried and something was
        wrong. The record carries the difference in `dropped`, which is why
        `hops` alone is never the whole answer.
        """
        quiet = self.clear(self.signed())
        self.assertEqual((quiet.hops, quiet.dropped), ((), ()))

        bodies, signed = self.relayed()
        failed = self.clear(signed, observations=bodies, resolve_relay=None)
        self.assertEqual(failed.hops, ())
        self.assertEqual(len(failed.dropped), 1)
        self.assertNotEqual(quiet.describe(), failed.describe())


class WindowTests(Case):
    """The counter window is symmetric about the challenge's own step.

    These two tests are the ones that would have caught the bug they were written
    after. Judging a sighting at the challenge's *expiry* rather than at its step
    start slid the derived step index forward by `lifetime_seconds / step_seconds`
    steps, so the accepted window became [seq, seq+4] instead of [seq-2, seq+2] -
    silently dropping a frame heard a step or two before the scan, which is the
    common and innocent case, while accepting frames from two steps into the
    future, which is not.
    """

    def admits(self, seq):
        bodies = (self.sighting(seq).encode(),)
        cleared = self.clear(
            self.signed(observations=bodies), observations=bodies
        )
        self.assertEqual(cleared.dropped, (), cleared.describe())
        self.assertEqual(len(cleared.sightings), 1)
        return cleared

    def test_a_frame_heard_the_full_window_before_the_scan_is_admitted(self):
        self.assertEqual(
            self.admits(SEQ - self.timing.accept_window_steps).sightings[0].frame.counter,
            SEQ - self.timing.accept_window_steps,
        )

    def test_a_frame_from_the_far_edge_of_the_window_ahead_is_admitted(self):
        self.admits(SEQ + self.timing.accept_window_steps)

    def test_one_step_past_either_edge_is_dropped_and_the_two_are_told_apart(self):
        for seq, expected in (
            (SEQ - self.timing.accept_window_steps - 1, origin.STALE_COUNTER),
            (SEQ + self.timing.accept_window_steps + 1, origin.FUTURE_COUNTER),
        ):
            with self.subTest(counter=seq):
                bodies = (self.sighting(seq).encode(),)
                cleared = self.clear(
                    self.signed(observations=bodies), observations=bodies
                )
                self.assertEqual(cleared.sightings, ())
                self.assertEqual(self.only_drop(cleared).code, expected)

    def test_the_window_is_centred_on_the_challenge_not_on_the_arrival(self):
        """A proof that queued for hours accepts exactly the same frames it would
        have accepted on the spot. Otherwise every offline proof loses its radio
        evidence for having been offline, which is the one thing it cannot help.
        """
        bodies = (self.sighting().encode(),)
        signed = self.signed(observations=bodies)
        for lateness in (1, 600, self.bounds.max_offline_seconds - SEQ * 15):
            with self.subTest(seconds=lateness):
                cleared = self.clear(
                    signed,
                    observations=bodies,
                    ledger=replay.MemoryLedger(),
                    received_at=self.at() + lateness,
                )
                self.assertEqual(cleared.dropped, ())
                self.assertEqual(len(cleared.sightings), 1)


class CommitmentTests(Case):
    """The signature has to mean the evidence, and the asymmetry is deliberate."""

    def test_a_body_the_proof_never_committed_to_refuses_the_whole_proof(self):
        """Not a drop. A body nobody signed for is not evidence that failed, it is
        evidence somebody added after the fact, and admitting it would make the
        signature cover less than it appears to.
        """
        bodies = (self.sighting().encode(),)
        exc = self.refused(
            gates.OBSERVATION_NOT_COMMITTED, self.signed(), observations=bodies
        )
        self.assertIn("commits to", str(exc))

    def test_a_commitment_whose_body_never_arrived_still_clears(self):
        """The other direction, and it must not refuse: a dropped packet on a bus
        is not an attack, and a student cannot resend what their handset already
        signed over.
        """
        bodies, signed = self.relayed()
        cleared = self.clear(signed, observations=())
        self.assertEqual((cleared.sightings, cleared.hops, cleared.dropped), ((), (), ()))
        self.assertEqual(len(cleared.signed.proof.observations), len(bodies))

    def test_part_of_the_committed_evidence_arriving_is_enough(self):
        bodies, signed = self.relayed()
        cleared = self.clear(
            signed, observations=bodies[:1], resolve_relay=self.cohort()
        )
        self.assertEqual(len(cleared.sightings), 1)
        self.assertEqual(cleared.hops, ())

    def test_swapping_one_committed_body_for_another_is_refused(self):
        """The substitution a relay in the middle would attempt: same shape, same
        count, different content. The commitment is by digest, so it does not care
        that the shape matches.
        """
        bodies = (self.sighting().encode(),)
        signed = self.signed(observations=bodies)
        substituted = (self.sighting(rssi=-40).encode(),)
        self.assertNotEqual(substituted, bodies)
        self.refused(
            gates.OBSERVATION_NOT_COMMITTED, signed, observations=substituted
        )


class SignalTests(Case):
    """A signal is recorded and weighed later. None of them refuses anything."""

    def signals_of(self, **over):
        return set(self.clear(self.signed(**over.pop("signed", {})), **over).signals)

    def test_a_receiver_clock_behind_the_counter_is_a_signal_not_a_refusal(self):
        bodies = (self.sighting(at=START).encode(),)
        cleared = self.clear(self.signed(observations=bodies), observations=bodies)
        self.assertEqual(len(cleared.sightings), 1)
        self.assertIn(origin.CLAIM_BEHIND, cleared.signals)

    def test_a_receiver_clock_ahead_of_the_counter_is_a_signal_not_a_refusal(self):
        latest = origin.counter_bounds(START, SEQ, self.timing)[1]
        bodies = (
            self.sighting(at=latest + self.timing.clock_skew_seconds + 1).encode(),
        )
        cleared = self.clear(self.signed(observations=bodies), observations=bodies)
        self.assertEqual(len(cleared.sightings), 1)
        self.assertIn(origin.CLAIM_AHEAD, cleared.signals)

    def test_a_capability_bit_this_build_cannot_name_is_recorded_not_charged(self):
        """A newer client is not a suspicious client. The bit is kept visible so
        that absent evidence can be explained by the handset rather than charged
        to the student.
        """
        unknown = 1 << 30
        cleared = self.clear(self.signed(capabilities=proof.CAP_BIOMETRIC | unknown))
        self.assertIn(gates.UNKNOWN_CAPABILITY, cleared.signals)
        self.assertEqual(
            cleared.describe()["proof"]["unknown_capability_bits"], unknown
        )

    def test_a_chain_sitting_exactly_at_the_depth_limit_says_so(self):
        deep = [
            keys.SigningKey.from_seed(bytes([120 + n]) * keys.SEED_LEN)
            for n in range(chain.max_hops())
        ]
        seen = self.sighting()
        bodies = (seen.encode(),) + chain.encode_chain(
            self.hops(chain.root_link(seen.encode()), devices=deep)
        )
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            resolve_relay=self.cohort(deep),
        )
        self.assertEqual(len(cleared.hops), chain.max_hops())
        self.assertIn(chain.DEPTH_AT_LIMIT, cleared.signals)

    def test_a_relay_clock_running_backwards_is_a_signal_about_a_clock(self):
        seen = self.sighting()
        root = chain.root_link(seen.encode())
        built = chain.extend(
            (),
            root=root,
            session_id=SESSION_ID,
            observed_at=self.at(),
            signing_key=self.relays[0],
        )
        built = chain.extend(
            built,
            root=root,
            session_id=SESSION_ID,
            observed_at=self.at() - 5,
            signing_key=self.relays[1],
        )
        bodies = (seen.encode(),) + chain.encode_chain(built)
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            resolve_relay=self.cohort(),
        )
        self.assertEqual(len(cleared.hops), 2)
        self.assertIn(chain.CLAIM_NON_MONOTONIC, cleared.signals)

    def test_a_proof_carrying_every_signal_at_once_still_clears(self):
        """Signals accumulate; they never add up to a refusal. If this ever fails
        it means somebody turned a weighed observation into a gate.
        """
        bodies = (self.sighting(at=START).encode(),)
        cleared = self.clear(
            self.signed(
                observations=bodies,
                capabilities=proof.CAP_BIOMETRIC | (1 << 30),
                captured_at=self.at() + self.bounds.max_future_skew_seconds - 1,
            ),
            observations=bodies,
            received_at=self.at(),
        )
        self.assertGreaterEqual(len(cleared.signals), 2)
        self.assertTrue(set(cleared.signals) <= gates.SIGNALS)


class ClaimTests(Case):
    """What the device says about itself is carried, never counted."""

    def boastful(self):
        return proof.Claims(
            status=proof.STATUS_PRESENT, confidence_milli=1000, hop_count=99
        )

    def test_a_device_claiming_present_with_full_confidence_clears_on_its_merits(self):
        """It clears because the gates passed, not because it said so. The proof
        here carries no radio evidence at all while claiming ninety-nine hops.
        """
        cleared = self.clear(self.signed(claims=self.boastful()))
        self.assertEqual(cleared.claims, self.boastful())
        self.assertEqual(len(cleared.hops), 0)

    def test_the_server_derives_the_hop_count_and_the_claim_does_not_move_it(self):
        bodies, signed = self.relayed(claims=self.boastful())
        cleared = self.clear(
            signed, observations=bodies, resolve_relay=self.cohort()
        )
        described = cleared.describe()
        self.assertEqual(described["relay_depth"], 2)
        self.assertEqual(described["proof"]["claimed_hop_count"], 99)

    def test_a_device_claiming_suspicious_of_itself_is_not_refused_for_it(self):
        """The mirror of the boast, and it matters as much. A client-set field must
        not be able to reject a proof any more than it can accept one, or a broken
        build would deny attendance to the students running it.
        """
        cleared = self.clear(
            self.signed(
                claims=proof.Claims(status=proof.STATUS_SUSPICIOUS, confidence_milli=0)
            )
        )
        self.assertEqual(cleared.claims.status, proof.STATUS_SUSPICIOUS)

    def test_an_unrecognised_claimed_status_is_refused_rather_than_rounded(self):
        """A closed vocabulary, and the asymmetry is argued in `_check_semantics`.
        A status this build cannot name must not be folded into a neighbouring one,
        because the neighbours are PRESENT and SUSPICIOUS and guessing between them
        is the whole question. So it is refused as malformed - the same answer a
        client gets locally, since `build` and `parse` share the check.
        """
        self.refused(proof.MALFORMED, self.mutated(claims=proof.Claims(status=200)))

    def test_every_claim_in_the_record_is_labelled_as_a_claim(self):
        """A reader of an audit row should not have to know which fields came from
        the handset. The record says so in the field names.
        """
        bodies, signed = self.relayed(claims=self.boastful())
        described = self.clear(
            signed, observations=bodies, resolve_relay=self.cohort()
        ).describe()
        for key in ("claimed_status", "claimed_confidence_milli", "claimed_hop_count"):
            self.assertIn(key, described["proof"])
        self.assertEqual(
            described["origin_sightings"][0]["claimed_observed_at"], self.at()
        )


class BiometricTests(Case):
    """A biometric outcome is evidence with a reason code, not a closed door."""

    def test_every_biometric_outcome_including_failure_clears_the_gates(self):
        """§09's rule has a consequence people forget: if a failed fingerprint
        refused a proof here, a wet thumb would be indistinguishable from a proxy,
        and the student with the wet thumb has no recourse. Fusion weighs this.
        """
        for value in (
            proof.BIOMETRIC_ABSENT,
            proof.BIOMETRIC_SUCCESS,
            proof.BIOMETRIC_FAILED,
            proof.BIOMETRIC_CANCELLED,
        ):
            with self.subTest(biometric=value):
                cleared = self.clear(
                    self.signed(biometric=value, nonce=bytes([value]) * replay.NONCE_LEN),
                    ledger=replay.MemoryLedger(),
                )
                self.assertEqual(cleared.signed.proof.biometric, value)

    def test_the_outcome_reaches_the_record_by_name_for_fusion_to_weigh(self):
        cleared = self.clear(self.signed(biometric=proof.BIOMETRIC_FAILED))
        self.assertEqual(cleared.describe()["proof"]["biometric"], "failed")

    def test_no_refusal_in_the_whole_vocabulary_is_about_a_biometric(self):
        """Structural rather than remembered: there is no code to raise, so a later
        edit cannot quietly add the gate this module argues against.
        """
        for code in gates.REASON_CODES | gates.DROP_REASONS:
            self.assertNotIn("biometric", code)

    def test_a_biometric_value_this_build_has_no_name_for_is_refused(self):
        """Admitting every outcome is not the same as admitting every *value*. The
        four outcomes are each weighed differently, so a fifth one nobody can name
        cannot be recorded as though it were one of them.
        """
        self.refused(proof.MALFORMED, self.mutated(biometric=9))

    def test_an_unknown_platform_is_admitted_where_an_unknown_outcome_is_not(self):
        """The other half of the asymmetry, and the reason for it: an older server
        refusing a newer handset outright punishes a student who has done nothing
        wrong, whereas an unnameable biometric outcome has no safe reading at all.
        """
        cleared = self.clear(self.mutated(platform=77))
        self.assertEqual(cleared.describe()["proof"]["platform"], "unrecognised")


class PrivacyTests(Case):
    """What an audit record may contain, asserted against what it must not."""

    def described(self, **over):
        bodies, signed = self.relayed()
        return json.dumps(
            self.clear(
                signed, observations=bodies, resolve_relay=self.cohort(), **over
            ).describe()
        )

    def test_no_key_material_of_any_kind_reaches_the_record(self):
        record = self.described()
        for label, secret in (
            ("session root secret", ROOT_SECRET),
            ("session signing seed", SIGNING_SEED),
            ("epoch key", self.keys.epoch_key(challenge.epoch_of(SEQ, self.timing))),
            ("challenge value", self.value_for()),
            ("device public key", self.device.public().public_bytes),
        ):
            with self.subTest(secret=label):
                self.assertNotIn(secret.hex(), record)

    def test_the_record_names_no_student(self):
        """There is no student field to redact, which is the strongest version of
        this: a key id resolves to a person only against a table this layer cannot
        see, so nothing here can leak an identity it never held.
        """
        self.assertNotIn("student", self.described())

    def test_a_relay_pseudonym_never_appears_beside_a_verified_chain(self):
        """A verified chain reaches the record as a depth. The pseudonym is
        session-scoped and links to no person, but there is no reason to carry it
        once the hops have verified, so it is not carried.
        """
        record = self.described()
        for device in self.relays:
            self.assertNotIn(
                chain.pseudonym(SESSION_ID, device.public().public_bytes).hex(), record
            )


class LimitTests(Case):
    """The bounds that keep a chain from outgrowing the proof that carries it."""

    def chain_of(self, devices, *, limit=None):
        seen = self.sighting()
        root = chain.root_link(seen.encode())
        built = ()
        for index, device in enumerate(devices):
            built = chain.extend(
                built,
                root=root,
                session_id=SESSION_ID,
                observed_at=self.at() + index,
                signing_key=device,
                limit=len(devices) if limit is None else limit,
            )
        return (seen.encode(),) + chain.encode_chain(built)

    def test_a_chain_deeper_than_the_deployment_accepts_is_dropped(self):
        deep = [
            keys.SigningKey.from_seed(bytes([140 + n]) * keys.SEED_LEN)
            for n in range(chain.max_hops() + 1)
        ]
        bodies = self.chain_of(deep)
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            resolve_relay=self.cohort(deep),
        )
        self.assertEqual(cleared.hops, ())
        self.assertEqual(self.only_drop(cleared).code, chain.TOO_DEEP)

    def test_a_relay_that_appears_twice_in_one_chain_is_dropped(self):
        """A loop is not a longer chain. Two hops from one device would let a single
        handset manufacture depth, and depth is the one thing a chain contributes.
        """
        first, second = self.relays
        bodies = self.chain_of([first, second, first])
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            resolve_relay=self.cohort(),
        )
        self.assertEqual(self.only_drop(cleared).code, chain.REPEATED_RELAY)

    def test_the_deepest_accepted_chain_still_fits_a_proof_commitment(self):
        """Two bounds that have to agree, asserted where both are in scope. A chain
        travels as observation digests inside a proof, so an artifact permitting a
        deeper chain than a proof can commit to would mint chains that verify and
        then cannot be submitted - and the sighting that roots it needs a slot too.
        """
        self.assertLessEqual(chain.max_hops() + 1, proof.MAX_OBSERVATIONS)


class FailClosedTests(Case):
    """The four properties the plan asks for, named one test each.

    Three of them refuse the proof. The fourth deliberately does not, and the
    difference is the module's central argument rather than an inconsistency: a
    chain is evidence a *third party* contributed, so a rogue relay that could
    refuse a proof by poisoning a chain would be able to deny attendance to any
    student within radio range. Failing closed there means the evidence stops
    counting, not that the student stops being present.
    """

    def test_a_forged_chain_stops_counting_as_evidence(self):
        seen = self.sighting()
        built = chain.extend(
            (),
            root=chain.root_link(seen.encode()),
            session_id=SESSION_ID,
            observed_at=self.at(),
            signing_key=self.relays[0],
        )
        forged = replace(built[0], signature=bytes(keys.SIGNATURE_LEN))
        bodies = (seen.encode(), forged.encode())
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            resolve_relay=self.cohort(),
        )
        self.assertEqual(cleared.hops, ())
        self.assertEqual(self.only_drop(cleared).code, chain.BAD_SIGNATURE)
        self.assertEqual(len(cleared.sightings), 1)

    def test_a_replayed_challenge_is_refused(self):
        signed = self.signed()
        self.clear(signed)
        self.refused(replay.DUPLICATE_PROOF, signed)

    def test_a_reordered_sequence_is_refused(self):
        """Two orderings, two refusals. A step this device has already passed is a
        replay of a challenge; a chain whose hops arrive out of order is a chain
        that was taken apart. Neither can be recovered from by resubmitting.
        """
        self.clear(self.signed(seq=SEQ))
        self.refused(replay.STEP_REGRESSION, self.signed(seq=SEQ - 1))

        seen = self.sighting()
        wire = chain.encode_chain(self.hops(chain.root_link(seen.encode())))
        bodies = (seen.encode(),) + tuple(reversed(wire))
        cleared = self.clear(
            self.signed(observations=bodies),
            observations=bodies,
            ledger=replay.MemoryLedger(),
            resolve_relay=self.cohort(),
        )
        self.assertEqual(self.only_drop(cleared).code, chain.OUT_OF_ORDER)

    def test_a_truncated_signature_is_refused_at_every_length(self):
        """Including the empty one, and including a signature that is too long. A
        wrong-length signature must be a signature failure and not a crash, because
        the alternative is a 500 on submission and a student with no record.
        """
        signed = self.signed()
        damaged = [signed.signature[:n] for n in (0, 1, keys.SIGNATURE_LEN // 2, keys.SIGNATURE_LEN - 1)]
        damaged.append(signed.signature + b"\x00")
        for candidate in damaged:
            with self.subTest(length=len(candidate)):
                self.refused(proof.BAD_SIGNATURE, signed, signature=candidate)
        self.assertEqual(len(self.ledger), 0)
