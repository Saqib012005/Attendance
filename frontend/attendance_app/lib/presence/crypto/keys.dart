import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Ed25519 key management for CampusGuard presence proofs.
class PresenceKeys {
  static const String _storageKeySeed = 'campusguard_presence_device_seed';
  static final Ed25519 _algorithm = Ed25519();
  static const FlutterSecureStorage _storage = FlutterSecureStorage();

  /// Gets or creates the persistent device signing keypair.
  static Future<SimpleKeyPair> getOrCreateDeviceKey() async {
    final existingHex = await _storage.read(key: _storageKeySeed);
    if (existingHex != null && existingHex.length == 64) {
      final seed = _hexToBytes(existingHex);
      return _algorithm.newKeyPairFromSeed(seed);
    }

    // Generate fresh seed (32 bytes)
    final keyPair = await _algorithm.newKeyPair();
    final seed = await keyPair.extractPrivateKeyBytes();
    await _storage.write(key: _storageKeySeed, value: _bytesToHex(seed));
    return keyPair;
  }

  /// Derives the 16-byte key_id from a 32-byte Ed25519 public key (SHA-256 truncated to 16 bytes).
  static Uint8List keyIdFor(List<int> publicKeyBytes) {
    final digest = crypto.sha256.convert(publicKeyBytes);
    return Uint8List.fromList(digest.bytes.sublist(0, 16));
  }

  /// Signs raw canonical bytes with the device private key.
  static Future<Uint8List> sign(SimpleKeyPair keyPair, List<int> message) async {
    final signature = await _algorithm.sign(message, keyPair: keyPair);
    return Uint8List.fromList(signature.bytes);
  }

  /// Verifies an Ed25519 signature over message bytes.
  static Future<bool> verify({
    required List<int> message,
    required List<int> signatureBytes,
    required List<int> publicKeyBytes,
  }) async {
    final publicKey = SimplePublicKey(publicKeyBytes, type: KeyPairType.ed25519);
    final signature = Signature(signatureBytes, publicKey: publicKey);
    return _algorithm.verify(message, signature: signature);
  }

  static String _bytesToHex(List<int> bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  static Uint8List _hexToBytes(String hex) {
    final result = Uint8List(hex.length ~/ 2);
    for (int i = 0; i < result.length; i++) {
      result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }
}
