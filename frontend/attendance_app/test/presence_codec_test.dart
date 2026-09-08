import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:attendance_app/presence/crypto/codec.dart';
import 'package:attendance_app/presence/crypto/keys.dart';
import 'package:attendance_app/presence/proof.dart';
import 'package:cryptography/cryptography.dart';

void main() {
  group('CampusGuard Cross-Language Presence Codec Tests', () {
    test('encodeQrChallenge produces valid canonical CBOR bytes', () {
      final sessionId = List<int>.filled(16, 0x01);
      final keyId = List<int>.filled(16, 0x02);
      final challenge = List<int>.filled(8, 0x03);
      final prevLink = List<int>.filled(8, 0x04);

      final bytes = PresenceCodec.encodeQrChallenge(
        sessionId: sessionId,
        keyId: keyId,
        epoch: 0,
        seq: 1,
        challenge: challenge,
        prevLink: prevLink,
        issuedAt: 1757000000,
        expiresAt: 1757000030,
      );

      expect(bytes, isNotEmpty);
      expect(bytes[0], 0x8A); // CBOR array of 10 items
      expect(bytes[1], PresenceCodec.tagQrChallenge);
      expect(bytes[2], PresenceCodec.versionQrChallenge);
    });

    test('encodeAttendanceProof produces deterministic bytes and digest', () {
      final sessionId = List<int>.filled(16, 0xAA);
      final deviceKeyId = List<int>.filled(16, 0xBB);
      final challenge = List<int>.filled(8, 0xCC);
      final nonce = List<int>.filled(16, 0xDD);

      final bytes = PresenceCodec.encodeAttendanceProof(
        sessionId: sessionId,
        deviceKeyId: deviceKeyId,
        challenge: challenge,
        challengeEpoch: 0,
        challengeSeq: 5,
        nonce: nonce,
        capturedAt: 1757000075,
        biometric: 1,
        platform: 1,
        capabilities: 3,
        claimedStatus: 1,
        claimedConfidenceMilli: 900,
        claimedHopCount: 0,
        observationDigests: [],
      );

      expect(bytes, isNotEmpty);
      expect(bytes[0], 0x90); // CBOR array of 16 items
      expect(bytes[1], PresenceCodec.tagAttendanceProof);
      expect(bytes[2], PresenceCodec.versionAttendanceProof);

      final digest = PresenceCodec.digest(bytes);
      expect(digest.length, 32);
    });

    test('Ed25519 signing and verification round trip', () async {
      final algorithm = Ed25519();
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();

      final message = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final signature = await PresenceKeys.sign(keyPair, message);

      final verified = await PresenceKeys.verify(
        message: message,
        signatureBytes: signature,
        publicKeyBytes: publicKey.bytes,
      );

      expect(verified, isTrue);
    });

    test('keyIdFor derives 16-byte identifier from public key', () {
      final pubKey = List<int>.filled(32, 0x42);
      final keyId = PresenceKeys.keyIdFor(pubKey);
      expect(keyId.length, 16);
    });
  });
}
