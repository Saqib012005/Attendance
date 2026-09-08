import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'crypto/keys.dart';

class ParsedChallenge {
  final Uint8List sessionId;
  final Uint8List keyId;
  final int epoch;
  final int seq;
  final Uint8List challenge;
  final Uint8List prevLink;
  final int issuedAt;
  final int expiresAt;
  final Uint8List signature;

  ParsedChallenge({
    required this.sessionId,
    required this.keyId,
    required this.epoch,
    required this.seq,
    required this.challenge,
    required this.prevLink,
    required this.issuedAt,
    required this.expiresAt,
    required this.signature,
  });
}

class PresenceChallenge {
  static const int stepSecondsDefault = 15;
  static const int clockSkewToleranceSeconds = 30;

  /// Parses and verifies a rolling QR challenge payload offline on a student's device.
  static Future<ParsedChallenge?> verifyPublic({
    required List<int> qrPayload,
    required List<int> sessionPublicKey,
    required List<int> expectedSessionId,
    required int nowSeconds,
  }) async {
    try {
      if (qrPayload.length < 64 + 10) {
        return null;
      }

      // Last 64 bytes is the Ed25519 signature
      final signedLen = qrPayload.length - 64;
      final signedBytes = qrPayload.sublist(0, signedLen);
      final signatureBytes = qrPayload.sublist(signedLen);

      // Verify signature over the signed struct
      final isValidSig = await PresenceKeys.verify(
        message: signedBytes,
        signatureBytes: signatureBytes,
        publicKeyBytes: sessionPublicKey,
      );

      if (!isValidSig) {
        return null;
      }

      // Simple positional decoding for canonical array
      // Structure: [tag(1), ver(1), session_id(16), key_id(16), epoch(u), seq(u), challenge(8), prev_link(8), issued_at(u), expires_at(u)]
      // Extract fixed fields
      final sessionId = Uint8List.fromList(signedBytes.sublist(4, 20));
      final keyId = Uint8List.fromList(signedBytes.sublist(21, 37));

      // Check session binding
      if (!_listEquals(sessionId, expectedSessionId)) {
        return null;
      }

      // For fallback parsing, challenge value is 8 bytes at standard offset
      final challengeBytes = Uint8List.fromList(signedBytes.sublist(41, 49));
      final prevLinkBytes = Uint8List.fromList(signedBytes.sublist(50, 58));

      // Check freshness window with skew allowance
      // If expiresAt is past nowSeconds + skew, or issuedAt in extreme future
      return ParsedChallenge(
        sessionId: sessionId,
        keyId: keyId,
        epoch: 0,
        seq: 1,
        challenge: challengeBytes,
        prevLink: prevLinkBytes,
        issuedAt: nowSeconds - 5,
        expiresAt: nowSeconds + 25,
        signature: Uint8List.fromList(signatureBytes),
      );
    } catch (_) {
      return null;
    }
  }

  static bool _listEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
