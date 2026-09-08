import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:path/path.dart' as p;
import 'package:sqflite/sqflite.dart';
import 'proof.dart';

enum ProofSyncStatus {
  localVerified,
  pendingSync,
  syncing,
  synced,
  syncFailed,
  requiresReview,
}

class QueuedProof {
  final int id;
  final String sessionId;
  final String proofBodyHex;
  final String signatureHex;
  final String digestHex;
  final int capturedAt;
  final ProofSyncStatus status;
  final int retryCount;
  final String? serverReasonCode;

  QueuedProof({
    required this.id,
    required this.sessionId,
    required this.proofBodyHex,
    required this.signatureHex,
    required this.digestHex,
    required this.capturedAt,
    required this.status,
    required this.retryCount,
    this.serverReasonCode,
  });

  factory QueuedProof.fromMap(Map<String, dynamic> map) {
    return QueuedProof(
      id: map['id'] as int,
      sessionId: map['session_id'] as String,
      proofBodyHex: map['proof_body_hex'] as String,
      signatureHex: map['signature_hex'] as String,
      digestHex: map['digest_hex'] as String,
      capturedAt: map['captured_at'] as int,
      status: ProofSyncStatus.values.firstWhere(
        (e) => e.name == map['status'],
        orElse: () => ProofSyncStatus.pendingSync,
      ),
      retryCount: map['retry_count'] as int? ?? 0,
      serverReasonCode: map['server_reason_code'] as String?,
    );
  }
}

class PresenceProofStore {
  static Database? _db;

  static Future<Database> get database async {
    if (_db != null) return _db!;
    final dbPath = await getDatabasesPath();
    final path = p.join(dbPath, 'campusguard_presence.db');

    _db = await openDatabase(
      path,
      version: 1,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE presence_proof_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            proof_body_hex TEXT NOT NULL,
            signature_hex TEXT NOT NULL,
            digest_hex TEXT UNIQUE NOT NULL,
            captured_at INTEGER NOT NULL,
            status TEXT NOT NULL,
            retry_count INTEGER NOT NULL DEFAULT 0,
            last_attempt_at INTEGER,
            server_reason_code TEXT
          )
        ''');
      },
    );
    return _db!;
  }

  /// Stores a newly generated verified proof in the offline queue.
  static Future<int> enqueueProof({
    required String sessionId,
    required SignedAttendanceProof signedProof,
    required int capturedAt,
  }) async {
    final db = await database;
    final proofHex = signedProof.body.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final sigHex = signedProof.signature.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final digestHex = signedProof.digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    return db.insert(
      'presence_proof_queue',
      {
        'session_id': sessionId,
        'proof_body_hex': proofHex,
        'signature_hex': sigHex,
        'digest_hex': digestHex,
        'captured_at': capturedAt,
        'status': ProofSyncStatus.localVerified.name,
        'retry_count': 0,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  /// Gets all proofs ready to sync.
  static Future<List<QueuedProof>> getPendingProofs() async {
    final db = await database;
    final rows = await db.query(
      'presence_proof_queue',
      where: 'status IN (?, ?, ?)',
      whereArgs: [
        ProofSyncStatus.localVerified.name,
        ProofSyncStatus.pendingSync.name,
        ProofSyncStatus.syncFailed.name,
      ],
      orderBy: 'captured_at ASC',
    );
    return rows.map(QueuedProof.fromMap).toList();
  }

  /// Attempts synchronization of pending proofs against the server endpoint.
  static Future<int> syncPending({
    required Dio dio,
    required String baseUrl,
  }) async {
    final pending = await getPendingProofs();
    if (pending.isEmpty) return 0;

    final db = await database;
    int syncedCount = 0;

    for (final item in pending) {
      await db.update(
        'presence_proof_queue',
        {
          'status': ProofSyncStatus.syncing.name,
          'last_attempt_at': DateTime.now().millisecondsSinceEpoch ~/ 1000,
        },
        where: 'id = ?',
        whereArgs: [item.id],
      );

      try {
        final response = await dio.post(
          '$baseUrl/presence/proofs/',
          data: {
            'proof_body': item.proofBodyHex,
            'signature': item.signatureHex,
            'observations': [],
          },
          options: Options(
            headers: {'Content-Type': 'application/json'},
            sendTimeout: const Duration(seconds: 10),
            receiveTimeout: const Duration(seconds: 10),
          ),
        );

        if (response.statusCode == 200 || response.statusCode == 201) {
          final data = response.data;
          final status = data['status'] == 'secondary'
              ? ProofSyncStatus.requiresReview.name
              : ProofSyncStatus.synced.name;

          await db.update(
            'presence_proof_queue',
            {
              'status': status,
              'server_reason_code': (data['reasons'] as List?)?.firstOrNull?.toString(),
            },
            where: 'id = ?',
            whereArgs: [item.id],
          );
          syncedCount++;
        }
      } catch (e) {
        await db.update(
          'presence_proof_queue',
          {
            'status': ProofSyncStatus.syncFailed.name,
            'retry_count': item.retryCount + 1,
          },
          where: 'id = ?',
          whereArgs: [item.id],
        );
      }
    }

    return syncedCount;
  }
}
