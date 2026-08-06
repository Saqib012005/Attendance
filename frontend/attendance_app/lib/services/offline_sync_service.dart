import 'dart:convert';
import 'dart:async';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter/material.dart';
import 'storage_service.dart';
import 'attendance_service.dart';

class OfflineSyncService {
  static const String _offlineRecordsKey = 'offline_attendance_records';
  StreamSubscription<List<ConnectivityResult>>? _connectivitySubscription;
  bool _isSyncing = false;

  static final OfflineSyncService _instance = OfflineSyncService._internal();
  factory OfflineSyncService() => _instance;

  OfflineSyncService._internal() {
    _initConnectivityListener();
  }

  void _initConnectivityListener() {
    _connectivitySubscription = Connectivity().onConnectivityChanged.listen((List<ConnectivityResult> results) {
      if (results.contains(ConnectivityResult.mobile) || 
          results.contains(ConnectivityResult.wifi) || 
          results.contains(ConnectivityResult.ethernet)) {
        syncOfflineRecords();
      }
    });
  }

  void dispose() {
    _connectivitySubscription?.cancel();
  }

  /// Save a session ID to local storage when offline
  Future<void> saveOfflineRecord(String sessionId) async {
    try {
      final records = await getOfflineRecords();
      
      // Check if already exists to prevent duplicates
      if (!records.any((r) => r['session_id'] == sessionId)) {
        records.add({
          'session_id': sessionId,
          'timestamp': DateTime.now().toIso8601String(),
        });
        
        await StorageService.write(
          key: _offlineRecordsKey,
          value: jsonEncode(records),
        );
        debugPrint('Saved offline record for session: $sessionId');
      }
    } catch (e) {
      debugPrint('Error saving offline record: $e');
    }
  }

  /// Get all unsynced offline records
  Future<List<Map<String, dynamic>>> getOfflineRecords() async {
    try {
      final data = await StorageService.read(key: _offlineRecordsKey);
      if (data != null && data.isNotEmpty) {
        final List<dynamic> decoded = jsonDecode(data);
        return decoded.map((e) => e as Map<String, dynamic>).toList();
      }
    } catch (e) {
      debugPrint('Error reading offline records: $e');
    }
    return [];
  }

  /// Automatically sync all offline records to the server
  Future<void> syncOfflineRecords() async {
    if (_isSyncing) return;
    
    try {
      final records = await getOfflineRecords();
      if (records.isEmpty) return;

      _isSyncing = true;
      debugPrint('Starting sync of ${records.length} offline records...');

      List<Map<String, dynamic>> failedRecords = [];

      final attendanceService = AttendanceService();
      
      for (var record in records) {
        final sessionId = record['session_id'];
        if (sessionId != null) {
          final result = await attendanceService.markAttendance(sessionId, isSync: true);
          
          if (!result['success'] && 
              result['message'] != null && 
              (result['message'].toString().toLowerCase().contains('network') || 
               result['message'].toString().toLowerCase().contains('connection'))) {
            // Still offline or network error, keep it in failed records
            failedRecords.add(record);
          } else {
            // Success or logical error (e.g. session closed), we don't retry
            debugPrint('Synced record for session: $sessionId, result: ${result['message']}');
          }
        }
      }

      // Update storage with only the records that failed due to network
      if (failedRecords.isEmpty) {
        await StorageService.delete(key: _offlineRecordsKey);
        debugPrint('All offline records synced successfully.');
      } else {
        await StorageService.write(
          key: _offlineRecordsKey,
          value: jsonEncode(failedRecords),
        );
        debugPrint('${failedRecords.length} records failed to sync due to network.');
      }
    } finally {
      _isSyncing = false;
    }
  }
}
