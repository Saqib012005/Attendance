import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'crypto/codec.dart';
import 'crypto/keys.dart';

class SignedAttendanceProof {
  final Uint8List body;
  final Uint8List signature;
  final Uint8List digest;
  final String nonceHex;

  SignedAttendanceProof({
    required this.body,
    required this.signature,
    required this.digest,
    required this.nonceHex,
  });

  Map<String, dynamic> toJson({List<String>? observationHexList}) {
    return {
      'proof_body': _bytesToHex(body),
      'signature': _bytesToHex(signature),
      'observations': observationHexList ?? [],
    };
  }

  static String _bytesToHex(List<int> bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}

class PresenceProofBuilder {
  static const int platformAndroid = 1;
  static const int platformIos = 2;
  static const int platformWeb = 3;

  static const int statusPresent = 1;
  static const int statusSecondary = 2;

  static const int capBleScan = 1 << 0;
  static const int capBleAdvertise = 1 << 1;
  static const int capRelay = 1 << 2;
  static const int capBiometric = 1 << 4;

  /// Builds and signs an unforgeable, offline attendance proof.
  static Future<SignedAttendanceProof> buildAndSign({
    required SimpleKeyPair deviceKeyPair,
    required List<int> sessionId,
    required List<int> challengeValue,
    required int challengeEpoch,
    required int challengeSeq,
    required int biometricOutcome,
    required int capturedAt,
    List<List<int>> observations = const [],
    int platform = platformAndroid,
    int capabilities = capBleScan | capBleAdvertise | capBiometric,
  }) async {
    final publicKey = await deviceKeyPair.extractPublicKey();
    final deviceKeyId = PresenceKeys.keyIdFor(publicKey.bytes);
    final nonce = _generateNonce();

    final body = PresenceCodec.encodeAttendanceProof(
      sessionId: sessionId,
      deviceKeyId: deviceKeyId,
      challenge: challengeValue,
      challengeEpoch: challengeEpoch,
      challengeSeq: challengeSeq,
      nonce: nonce,
      capturedAt: capturedAt,
      biometric: biometricOutcome,
      platform: platform,
      capabilities: capabilities,
      claimedStatus: statusPresent,
      claimedConfidenceMilli: 900,
      claimedHopCount: observations.length,
      observationDigests: observations,
    );

    final signature = await PresenceKeys.sign(deviceKeyPair, body);
    final digest = PresenceCodec.digest(body);

    return SignedAttendanceProof(
      body: body,
      signature: signature,
      digest: digest,
      nonceHex: nonce.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
    );
  }

  static Uint8List _generateNonce() {
    final rng = Random.secure();
    final bytes = Uint8List(16);
    for (int i = 0; i < 16; i++) {
      bytes[i] = rng.nextInt(256);
    }
    return bytes;
  }
}
