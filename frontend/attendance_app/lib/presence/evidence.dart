import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;

/// Container for classroom observation evidence bodies inside the collection window.
class ObservationWindow {
  final List<Uint8List> rawObservations = [];

  void addObservation(List<int> observationBytes) {
    rawObservations.add(Uint8List.fromList(observationBytes));
  }

  /// Produces fixed list of 32-byte SHA-256 digests for inclusion in AttendanceProof.
  List<Uint8List> getDigests() {
    return rawObservations.map((obs) {
      final digest = crypto.sha256.convert(obs);
      return Uint8List.fromList(digest.bytes);
    }).toList();
  }

  void clear() {
    rawObservations.clear();
  }
}
