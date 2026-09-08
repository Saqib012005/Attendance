import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;

/// Canonical deterministic CBOR wire codec for CampusGuard.
/// Conforms byte-for-byte to the Python canonical CBOR specification.
class PresenceCodec {
  static const int codecVersion = 1;

  // Schema tags
  static const int tagQrChallenge = 1;
  static const int tagAttendanceProof = 2;
  static const int tagOriginSighting = 3;
  static const int tagRelayHop = 4;
  static const int tagAnchorReading = 5;
  static const int tagDeviceRegistration = 6;

  // Schema versions
  static const int versionQrChallenge = 1;
  static const int versionAttendanceProof = 1;
  static const int versionOriginSighting = 1;
  static const int versionRelayHop = 1;
  static const int versionAnchorReading = 1;
  static const int versionDeviceRegistration = 1;

  /// Encodes a QR challenge payload into canonical CBOR array bytes.
  static Uint8List encodeQrChallenge({
    required List<int> sessionId,
    required List<int> keyId,
    required int epoch,
    required int seq,
    required List<int> challenge,
    required List<int> prevLink,
    required int issuedAt,
    required int expiresAt,
  }) {
    final buffer = <int>[];
    _writeArrayHeader(buffer, 10); // tag + version + 8 fields
    _writeUint(buffer, tagQrChallenge);
    _writeUint(buffer, versionQrChallenge);
    _writeBytes(buffer, sessionId);
    _writeBytes(buffer, keyId);
    _writeUint(buffer, epoch);
    _writeUint(buffer, seq);
    _writeBytes(buffer, challenge);
    _writeBytes(buffer, prevLink);
    _writeUint(buffer, issuedAt);
    _writeUint(buffer, expiresAt);
    return Uint8List.fromList(buffer);
  }

  /// Encodes an attendance proof into canonical CBOR array bytes.
  static Uint8List encodeAttendanceProof({
    required List<int> sessionId,
    required List<int> deviceKeyId,
    required List<int> challenge,
    required int challengeEpoch,
    required int challengeSeq,
    required List<int> nonce,
    required int capturedAt,
    required int biometric,
    required int platform,
    required int capabilities,
    required int claimedStatus,
    required int claimedConfidenceMilli,
    required int claimedHopCount,
    required List<List<int>> observationDigests,
  }) {
    final buffer = <int>[];
    _writeArrayHeader(buffer, 16); // tag + version + 14 fields
    _writeUint(buffer, tagAttendanceProof);
    _writeUint(buffer, versionAttendanceProof);
    _writeBytes(buffer, sessionId);
    _writeBytes(buffer, deviceKeyId);
    _writeBytes(buffer, challenge);
    _writeUint(buffer, challengeEpoch);
    _writeUint(buffer, challengeSeq);
    _writeBytes(buffer, nonce);
    _writeUint(buffer, capturedAt);
    _writeUint(buffer, biometric);
    _writeUint(buffer, platform);
    _writeUint(buffer, capabilities);
    _writeUint(buffer, claimedStatus);
    _writeUint(buffer, claimedConfidenceMilli);
    _writeUint(buffer, claimedHopCount);
    
    // Write observation digests array
    _writeArrayHeader(buffer, observationDigests.length);
    for (final digest in observationDigests) {
      _writeBytes(buffer, digest);
    }
    return Uint8List.fromList(buffer);
  }

  /// Computes canonical SHA-256 digest of signed CBOR bytes.
  static Uint8List digest(List<int> canonicalBytes) {
    final d = crypto.sha256.convert(canonicalBytes);
    return Uint8List.fromList(d.bytes);
  }

  // --- Canonical CBOR Primitive Writers ---

  static void _writeUint(List<int> buffer, int value) {
    if (value < 0) throw ArgumentError('Value must be unsigned uint: $value');
    if (value <= 23) {
      buffer.add(value);
    } else if (value <= 0xFF) {
      buffer.add(0x18);
      buffer.add(value);
    } else if (value <= 0xFFFF) {
      buffer.add(0x19);
      buffer.add((value >> 8) & 0xFF);
      buffer.add(value & 0xFF);
    } else if (value <= 0xFFFFFFFF) {
      buffer.add(0x1A);
      buffer.add((value >> 24) & 0xFF);
      buffer.add((value >> 16) & 0xFF);
      buffer.add((value >> 8) & 0xFF);
      buffer.add(value & 0xFF);
    } else {
      buffer.add(0x1B);
      for (int i = 56; i >= 0; i -= 8) {
        buffer.add((value >> i) & 0xFF);
      }
    }
  }

  static void _writeBytes(List<int> buffer, List<int> bytes) {
    final len = bytes.length;
    if (len <= 23) {
      buffer.add(0x40 | len);
    } else if (len <= 0xFF) {
      buffer.add(0x58);
      buffer.add(len);
    } else if (len <= 0xFFFF) {
      buffer.add(0x59);
      buffer.add((len >> 8) & 0xFF);
      buffer.add(len & 0xFF);
    } else {
      buffer.add(0x5A);
      buffer.add((len >> 24) & 0xFF);
      buffer.add((len >> 16) & 0xFF);
      buffer.add((len >> 8) & 0xFF);
      buffer.add(len & 0xFF);
    }
    buffer.addAll(bytes);
  }

  static void _writeText(List<int> buffer, String text) {
    final bytes = utf8.encode(text);
    final len = bytes.length;
    if (len <= 23) {
      buffer.add(0x60 | len);
    } else if (len <= 0xFF) {
      buffer.add(0x78);
      buffer.add(len);
    } else if (len <= 0xFFFF) {
      buffer.add(0x79);
      buffer.add((len >> 8) & 0xFF);
      buffer.add(len & 0xFF);
    } else {
      buffer.add(0x7A);
      buffer.add((len >> 24) & 0xFF);
      buffer.add((len >> 16) & 0xFF);
      buffer.add((len >> 8) & 0xFF);
      buffer.add(len & 0xFF);
    }
    buffer.addAll(bytes);
  }

  static void _writeArrayHeader(List<int> buffer, int length) {
    if (length <= 23) {
      buffer.add(0x80 | length);
    } else if (length <= 0xFF) {
      buffer.add(0x98);
      buffer.add(length);
    } else if (length <= 0xFFFF) {
      buffer.add(0x99);
      buffer.add((length >> 8) & 0xFF);
      buffer.add(length & 0xFF);
    } else {
      buffer.add(0x9A);
      buffer.add((length >> 24) & 0xFF);
      buffer.add((length >> 16) & 0xFF);
      buffer.add((length >> 8) & 0xFF);
      buffer.add(length & 0xFF);
    }
  }
}
