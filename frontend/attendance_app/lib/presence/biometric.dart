import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';

/// Platform-native biometric gate for CampusGuard.
/// Never captures, transmits, or stores biometric templates, fingerprints, or images.
class PresenceBiometric {
  static const int outcomeAbsent = 0;
  static const int outcomeSuccess = 1;
  static const int outcomeFailed = 2;
  static const int outcomeCancelled = 3;

  static final LocalAuthentication _auth = LocalAuthentication();

  /// Checks if hardware biometric authentication is supported on this handset.
  static Future<bool> canAuthenticate() async {
    try {
      final canAuthWithBiometrics = await _auth.canCheckBiometrics;
      final isDeviceSupported = await _auth.isDeviceSupported();
      return canAuthWithBiometrics || isDeviceSupported;
    } catch (_) {
      return false;
    }
  }

  /// Performs local biometric verification. Returns outcome code (0, 1, 2, or 3).
  static Future<int> authenticate({
    String reason = 'Verify your presence to complete attendance',
  }) async {
    try {
      final supported = await canAuthenticate();
      if (!supported) {
        return outcomeAbsent;
      }

      final success = await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: false,
          useErrorDialogs: true,
        ),
      );

      return success ? outcomeSuccess : outcomeFailed;
    } on PlatformException catch (e) {
      if (e.code == 'NotAvailable' || e.code == 'PasscodeNotSet') {
        return outcomeAbsent;
      }
      if (e.code == 'UserCanceled' || e.code == 'AuthCancelled') {
        return outcomeCancelled;
      }
      return outcomeFailed;
    } catch (_) {
      return outcomeFailed;
    }
  }
}
