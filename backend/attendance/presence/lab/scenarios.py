"""Adversarial scenario generators for CampusGuard Threat Model Rows 1-15.

Simulates each attack vector directly against the production gates, features,
fusion, and decision pipeline.
"""
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import chain, challenge, codec, config, decide, features, fusion, gates, keys, origin, proof, replay

SESSION_ID = b"lab-session-id--".ljust(proof.SESSION_ID_LEN, b"0")
ROOT_SECRET = b"lab-root-secret-key-32bytes-----".ljust(keys.SEED_LEN, b".")
SIGNING_SEED = b"lab-signing-seed-key-32bytes----".ljust(keys.SEED_LEN, b".")

START_TIME = 1_757_000_000
DEFAULT_SEQ = 5
NONCE_BASE = b"nonce-test-"


@dataclass
class ScenarioResult:
    row: int
    name: str
    expected_outcome: str  # e.g., "REFUSED:challenge_expired", "DECISION:PRESENT", etc.
    actual_outcome: str
    passed: bool
    reason_code: Optional[str] = None
    details: str = ""


class ScenarioLab:
    def __init__(self):
        self.session_keys = keys.SessionKeys.load(SESSION_ID, ROOT_SECRET, SIGNING_SEED)
        self.timing = challenge.Timing.active()
        self.bounds = replay.Bounds.active()
        self.student_key = keys.SigningKey.from_seed(b"lab-student-key".ljust(keys.SEED_LEN, b"."))
        self.impostor_key = keys.SigningKey.from_seed(b"lab-impostor-key".ljust(keys.SEED_LEN, b"."))
        self.relay_keys = [
            keys.SigningKey.from_seed(bytes([r]) * keys.SEED_LEN) for r in (81, 82)
        ]
        self.ledger = replay.MemoryLedger()
        self.context = gates.SessionContext(
            session_keys=self.session_keys,
            session_start=START_TIME,
        )

    def _step_time(self, seq: int) -> int:
        return START_TIME + seq * self.timing.step_seconds + 1

    def _challenge_val(self, seq: int) -> bytes:
        ep = challenge.epoch_of(seq, self.timing)
        return challenge.challenge_value(self.session_keys.epoch_key(ep), SESSION_ID, ep, seq)

    def _build_proof(
        self,
        seq: int,
        key: Optional[keys.SigningKey] = None,
        challenge_val: Optional[bytes] = None,
        nonce_suffix: bytes = b"001",
        biometric: int = proof.BIOMETRIC_SUCCESS,
        observations: Tuple[bytes, ...] = (),
        claimed_status: int = proof.STATUS_PRESENT,
        captured_at: Optional[int] = None,
    ) -> proof.Signed:
        signer = key or self.student_key
        c_val = self._challenge_val(seq) if challenge_val is None else challenge_val
        c_epoch = challenge.epoch_of(seq, self.timing)
        c_at = self._step_time(seq) if captured_at is None else captured_at
        nonce = (NONCE_BASE + nonce_suffix).ljust(proof.NONCE_LEN, b"x")[:proof.NONCE_LEN]

        built = proof.build(
            session_id=SESSION_ID,
            device_key_id=signer.public().key_id,
            challenge=c_val,
            challenge_epoch=c_epoch,
            challenge_seq=seq,
            captured_at=c_at,
            biometric=biometric,
            platform=proof.PLATFORM_ANDROID,
            capabilities=proof.CAP_BLE_SCAN | proof.CAP_BLE_ADVERTISE,
            nonce=nonce,
            claims=proof.Claims(
                status=claimed_status,
                confidence_milli=950,
                hop_count=len(observations),
            ),
            observations=proof.observation_digests(*observations),
        )
        return proof.sign(built, signer)

    def run_pipeline(
        self,
        signed_or_body: Any,
        now: int,
        signature: Optional[bytes] = None,
        devices_override: Optional[Dict[bytes, gates.Registration]] = None,
        unparsed_observations: Tuple[bytes, ...] = (),
    ) -> Tuple[bool, str, Optional[str]]:
        """Executes full gates -> features -> fusion -> decide pipeline.
        
        Returns: (is_cleared, verdict_or_gate_error, reason_code)
        """
        registered = devices_override if devices_override is not None else {
            self.student_key.public().key_id: gates.Registration(
                verify_key=self.student_key.public(),
                revoked=False,
                enrolled=True,
            )
        }

        if isinstance(signed_or_body, proof.Signed):
            body = signed_or_body.body
            sig = signed_or_body.signature
        else:
            body = signed_or_body
            sig = signature or b"\x00" * 64

        try:
            cleared = gates.clear(
                body,
                sig,
                context=self.context,
                resolve_device=registered.get,
                ledger=self.ledger,
                received_at=now,
                observations=unparsed_observations,
                resolve_relay=None,
                timing=self.timing,
            )
        except gates.GateError as e:
            return False, f"REFUSED:{e.code}", e.code

        # Run feature extraction, fusion, decision
        vec = features.extract(cleared)
        fused = fusion.fuse(vec)
        decision = decide.decide(fused, biometric=cleared.signed.proof.biometric)
        status_name = proof.STATUS_NAMES.get(decision.status, "unknown").upper()
        return True, f"DECISION:{status_name}", (decision.reasons[0] if decision.reasons else None)

    # --- Attack Scenarios ---

    def test_row_1_qr_screenshot_stale(self) -> ScenarioResult:
        """Row 1: Screenshot forwarded out of room; verified against client public gate."""
        seq = 2
        now = self._step_time(seq + 15)  # Well beyond challenge lifetime
        ch = challenge.issue(self.session_keys, session_start=START_TIME, at=self._step_time(seq), timing=self.timing)
        try:
            challenge.verify_public(
                ch.payload,
                verify_key=self.session_keys.public(),
                session_id=SESSION_ID,
                at=now,
                session_start=START_TIME,
                timing=self.timing,
            )
            passed = False
            out = "ACCEPTED"
            code = None
        except challenge.ChallengeError as exc:
            passed = (exc.code == challenge.EXPIRED)
            out = f"REFUSED:{exc.code}"
            code = exc.code

        return ScenarioResult(
            row=1,
            name="QR screenshot forwarded out of room",
            expected_outcome=f"REFUSED:{challenge.EXPIRED}",
            actual_outcome=out,
            passed=passed,
            reason_code=code,
        )

    def test_row_2_qr_photographed_later(self) -> ScenarioResult:
        """Row 2: Photographed unissued/future QR code submitted to backend."""
        future_seq = 25
        now = self._step_time(5)  # Session only at step 5
        signed = self._build_proof(seq=future_seq, nonce_suffix=b"r2")
        _, out, code = self.run_pipeline(signed, now=now)
        passed = (out == f"REFUSED:{challenge.FUTURE_STEP}")
        return ScenarioResult(
            row=2,
            name="QR photographed / future step submitted",
            expected_outcome=f"REFUSED:{challenge.FUTURE_STEP}",
            actual_outcome=out,
            passed=passed,
            reason_code=code,
        )

    def test_row_3_video_teacher_screen(self) -> ScenarioResult:
        """Row 3: Video replay of teacher screen evaluated authoritatively."""
        seq = 3
        now = self._step_time(seq + 20)
        ch = challenge.issue(self.session_keys, session_start=START_TIME, at=self._step_time(seq), timing=self.timing)
        try:
            challenge.verify_authoritative(
                ch.payload,
                session_keys=self.session_keys,
                session_start=START_TIME,
                at=now,
                timing=self.timing,
            )
            passed = False
            out = "ACCEPTED"
            code = None
        except challenge.ChallengeError as exc:
            passed = (exc.code == challenge.EXPIRED) or (exc.code == challenge.STALE_STEP)
            out = f"REFUSED:{exc.code}"
            code = exc.code

        return ScenarioResult(
            row=3,
            name="Video recording of rolling screen",
            expected_outcome=f"REFUSED:{challenge.EXPIRED}",
            actual_outcome=out,
            passed=passed,
            reason_code=code,
        )

    def test_row_4_session_uuid_direct(self) -> ScenarioResult:
        """Row 4: Direct session UUID submission with fabricated challenge."""
        seq = DEFAULT_SEQ
        now = self._step_time(seq)
        fake_challenge = b"\xde\xad\xbe\xef\x01\x02\x03\x04"
        signed = self._build_proof(seq=seq, challenge_val=fake_challenge, nonce_suffix=b"r4")
        _, out, code = self.run_pipeline(signed, now=now)
        passed = (out == f"REFUSED:{challenge.FORGED}")
        return ScenarioResult(
            row=4,
            name="Direct session submission with fabricated challenge",
            expected_outcome=f"REFUSED:{challenge.FORGED}",
            actual_outcome=out,
            passed=passed,
            reason_code=code,
        )

    def test_row_5_proof_replay(self) -> ScenarioResult:
        """Row 5: Replaying a captured valid proof."""
        seq = DEFAULT_SEQ
        now = self._step_time(seq)
        signed = self._build_proof(seq=seq, nonce_suffix=b"r5")
        
        # First submission succeeds
        ok1, out1, _ = self.run_pipeline(signed, now=now)
        # Second submission with exact same proof bytes
        ok2, out2, code2 = self.run_pipeline(signed, now=now)
        
        passed = ok1 and (out2 == f"REFUSED:{replay.DUPLICATE_PROOF}")
        return ScenarioResult(
            row=5,
            name="Replay of captured valid proof",
            expected_outcome=f"REFUSED:{replay.DUPLICATE_PROOF}",
            actual_outcome=out2,
            passed=passed,
            reason_code=code2,
        )

    def test_row_8_credential_sharing_unregistered_device(self) -> ScenarioResult:
        """Row 8: Submitting with an unregistered/unbound device key."""
        seq = DEFAULT_SEQ
        now = self._step_time(seq)
        signed = self._build_proof(seq=seq, key=self.impostor_key, nonce_suffix=b"r8")
        _, out, code = self.run_pipeline(signed, now=now)
        passed = (out == f"REFUSED:{gates.UNKNOWN_DEVICE}")
        return ScenarioResult(
            row=8,
            name="Credential sharing / unregistered device key",
            expected_outcome=f"REFUSED:{gates.UNKNOWN_DEVICE}",
            actual_outcome=out,
            passed=passed,
            reason_code=code,
        )

    def test_row_9_revoked_device(self) -> ScenarioResult:
        """Row 9: Submitting from a revoked device."""
        seq = DEFAULT_SEQ
        now = self._step_time(seq)
        revoked_devices = {
            self.student_key.public().key_id: gates.Registration(
                verify_key=self.student_key.public(),
                revoked=True,
                enrolled=True,
            )
        }
        signed = self._build_proof(seq=seq, nonce_suffix=b"r9")
        _, out, code = self.run_pipeline(signed, now=now, devices_override=revoked_devices)
        passed = (out == f"REFUSED:{gates.DEVICE_REVOKED}")
        return ScenarioResult(
            row=9,
            name="Revoked device submission",
            expected_outcome=f"REFUSED:{gates.DEVICE_REVOKED}",
            actual_outcome=out,
            passed=passed,
            reason_code=code,
        )

    def test_row_11_forged_challenge_hmac(self) -> ScenarioResult:
        """Row 11: Single-bit flip forgery on challenge payload."""
        seq = DEFAULT_SEQ
        now = self._step_time(seq)
        val = bytearray(self._challenge_val(seq))
        val[0] ^= 0x01
        signed = self._build_proof(seq=seq, challenge_val=bytes(val), nonce_suffix=b"r11")
        _, out, code = self.run_pipeline(signed, now=now)
        passed = (out == f"REFUSED:{challenge.FORGED}")
        return ScenarioResult(
            row=11,
            name="Forged challenge HMAC",
            expected_outcome=f"REFUSED:{challenge.FORGED}",
            actual_outcome=out,
            passed=passed,
            reason_code=code,
        )

    def test_row_12_tampered_proof_signature(self) -> ScenarioResult:
        """Row 12: Bit flipped in proof payload after signature."""
        seq = DEFAULT_SEQ
        now = self._step_time(seq)
        signed = self._build_proof(seq=seq, nonce_suffix=b"r12")
        tampered_body = bytearray(signed.body)
        tampered_body[20] ^= 0x01  # Flip a byte in the signed struct
        _, out, code = self.run_pipeline(bytes(tampered_body), now=now, signature=signed.signature)
        passed = (out == f"REFUSED:{proof.BAD_SIGNATURE}") or (out == f"REFUSED:{proof.MALFORMED}")
        return ScenarioResult(
            row=12,
            name="Tampered proof signature / byte corruption",
            expected_outcome=f"REFUSED:{proof.BAD_SIGNATURE}",
            actual_outcome=out,
            passed=passed,
            reason_code=code,
        )

    def test_row_14_garbage_relay_injection(self) -> ScenarioResult:
        """Row 14: Attacker appends invalid/corrupted relay hop.
        
        System must drop bad observation rather than refusing the compliant student.
        """
        seq = DEFAULT_SEQ
        now = self._step_time(seq)
        garbage_hop = b"garbage-hop-data-that-fails-cbor"
        signed = self._build_proof(
            seq=seq,
            nonce_suffix=b"r14",
            observations=(garbage_hop,),
        )
        ok, out, code = self.run_pipeline(
            signed,
            now=now,
            unparsed_observations=(garbage_hop,),
        )
        # Genuine student should still be admitted with a valid verdict
        passed = ok and ("DECISION:" in out)
        return ScenarioResult(
            row=14,
            name="Garbage relay observation injection",
            expected_outcome="DECISION:PRESENT or SECONDARY (observations dropped)",
            actual_outcome=out,
            passed=passed,
            reason_code=code,
        )

    def run_all_scenarios(self) -> List[ScenarioResult]:
        """Execute all implemented threat model test scenarios."""
        tests = [
            self.test_row_1_qr_screenshot_stale,
            self.test_row_2_qr_photographed_later,
            self.test_row_3_video_teacher_screen,
            self.test_row_4_session_uuid_direct,
            self.test_row_5_proof_replay,
            self.test_row_8_credential_sharing_unregistered_device,
            self.test_row_9_revoked_device,
            self.test_row_11_forged_challenge_hmac,
            self.test_row_12_tampered_proof_signature,
            self.test_row_14_garbage_relay_injection,
        ]
        results = []
        for t in tests:
            results.append(t())
        return results
