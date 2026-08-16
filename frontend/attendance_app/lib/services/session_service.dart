import 'dart:convert';
import 'package:dio/dio.dart';

import '../config/api_config.dart';
import 'storage_service.dart';

class SessionService {
  final String baseUrl = ApiConfig.baseUrl; 
  final Dio _dio = Dio();

  SessionService() {
    _dio.options.baseUrl = baseUrl;
    _dio.options.connectTimeout = ApiConfig.connectionTimeout;
    _dio.options.receiveTimeout = ApiConfig.receiveTimeout;
  }

  String _parseError(dynamic data, String fallback) {
    if (data == null) return fallback;
    if (data is Map) {
      return data['error']?.toString() ??
          data['detail']?.toString() ??
          data['message']?.toString() ??
          data.toString();
    }
    if (data is String) {
      try {
        final decoded = jsonDecode(data);
        if (decoded is Map) {
          return decoded['error']?.toString() ??
              decoded['detail']?.toString() ??
              decoded['message']?.toString() ??
              data;
        }
      } catch (_) {}
      return data;
    }
    return data.toString();
  }

  Future<String?> _getToken() async {
    return await StorageService.read(key: 'access_token');
  }

  /// Create a new attendance session
  Future<Map<String, dynamic>> createSession({
    required int classId,
    required int durationMinutes,
  }) async {
    try {
      final token = await _getToken();
      
      final response = await _dio.post(
        '/sessions/create/',
        data: {
          'class_id': classId,
          'duration_minutes': durationMinutes,
        },
        options: Options(
          headers: {'Authorization': 'Bearer $token'},
        ),
      );
      
      if (response.statusCode == 201) {
        return {
          'success': true,
          'session': response.data['session'],
        };
      }
      
      return {'success': false, 'message': 'Failed to create session'};
    } on DioException catch (e) {
      return {
        'success': false,
        'message': _parseError(e.response?.data, 'Failed to create session: ${e.message}'),
      };
    }
  }

  /// Get active sessions
  Future<List<Map<String, dynamic>>> getActiveSessions() async {
    try {
      final token = await _getToken();
      
      final response = await _dio.get(
        '/sessions/active/',
        options: Options(
          headers: {'Authorization': 'Bearer $token'},
        ),
      );
      
      if (response.statusCode == 200) {
        return List<Map<String, dynamic>>.from(response.data['sessions']);
      }
      
      return [];
    } catch (e) {
      print('Error fetching active sessions: $e');
      return [];
    }
  }

  /// Get session details
  Future<Map<String, dynamic>?> getSessionDetails(String sessionId) async {
    try {
      final token = await _getToken();
      
      final response = await _dio.get(
        '/sessions/$sessionId/',
        options: Options(
          headers: {'Authorization': 'Bearer $token'},
        ),
      );
      
      if (response.statusCode == 200) {
        return response.data;
      }
      
      return null;
    } catch (e) {
      print('Error fetching session details: $e');
      return null;
    }
  }

  Future<Map<String, dynamic>?> getSecureEpoch(String sessionId) async {
    try {
      final token = await _getToken();
      final response = await _dio.get(
        '/sessions/$sessionId/secure-epoch/',
        options: Options(headers: {'Authorization': 'Bearer $token'}),
      );
      if (response.statusCode == 200) {
        if (response.data is Map) {
          return Map<String, dynamic>.from(response.data);
        } else if (response.data is String) {
          final decoded = jsonDecode(response.data);
          if (decoded is Map) {
            return Map<String, dynamic>.from(decoded);
          }
        }
      }
      return null;
    } catch (e) {
      print('getSecureEpoch error: $e');
      return null;
    }
  }

  Future<List<Map<String, dynamic>>> getPendingReviews(String sessionId) async {
    try {
      final token = await _getToken();
      final response = await _dio.get(
        '/sessions/$sessionId/reviews/',
        options: Options(headers: {'Authorization': 'Bearer $token'}),
      );
      if (response.statusCode == 200) {
        dynamic data = response.data;
        if (data is String) {
          data = jsonDecode(data);
        }
        if (data is Map && data['reviews'] != null) {
          return List<Map<String, dynamic>>.from(data['reviews']);
        }
      }
      return [];
    } catch (e) {
      print('getPendingReviews error: $e');
      return [];
    }
  }

  Future<bool> resolveReview(int recordId, String decision) async {
    try {
      final token = await _getToken();
      final response = await _dio.post(
        '/attendance/$recordId/review/',
        data: {'decision': decision},
        options: Options(headers: {'Authorization': 'Bearer $token'}),
      );
      return response.statusCode == 200;
    } catch (e) {
      print('resolveReview error: $e');
      return false;
    }
  }

  /// End session and get statistics
  Future<Map<String, dynamic>> endSession(String sessionId) async {
    try {
      final token = await _getToken();
      
      final response = await _dio.post(
        '/sessions/$sessionId/end/',
        options: Options(
          headers: {'Authorization': 'Bearer $token'},
        ),
      );
      
      if (response.statusCode == 200) {
        return {
          'success': true,
          'message': response.data['message'] ?? 'Session ended successfully',
          'statistics': response.data['statistics'] ?? {},
          'session': response.data['session'],
        };
      }
      
      return {
        'success': false,
        'message': 'Failed to end session'
      };
    } on DioException catch (e) {
      return {
        'success': false,
        'message': _parseError(e.response?.data, 'Error ending session: ${e.message}'),
      };
    } catch (e) {
      print('Error ending session: $e');
      return {
        'success': false,
        'message': 'Error: $e'
      };
    }
  }

  /// Mark attendance (for students)
  Future<Map<String, dynamic>> markAttendance(String sessionId) async {
    try {
      final token = await _getToken();
      
      final response = await _dio.post(
        '/sessions/$sessionId/mark/',
        options: Options(
          headers: {'Authorization': 'Bearer $token'},
        ),
      );
      
      if (response.statusCode == 200 || response.statusCode == 201) {
        return {
          'success': true,
          'message': response.data['message'],
        };
      }
      
      return {'success': false, 'message': 'Failed to mark attendance'};
    } on DioException catch (e) {
      return {
        'success': false,
        'message': _parseError(e.response?.data, 'Failed to mark attendance: ${e.message}'),
      };
    }
  }

  /// Get session attendance details with student list
  Future<Map<String, dynamic>?> getSessionAttendance(String sessionId) async {
    try {
      final token = await _getToken();
      
      final response = await _dio.get(
        '/sessions/$sessionId/attendance/',
        options: Options(
          headers: {'Authorization': 'Bearer $token'},
        ),
      );
      
      if (response.statusCode == 200) {
        return {
          'success': true,
          'session': response.data['session'],
          'students': List<Map<String, dynamic>>.from(
            response.data['students'] ?? []
          ),
          'statistics': response.data['statistics'] ?? {},
        };
      }
      
      return {'success': false};
    } catch (e) {
      print('Error fetching session attendance: $e');
      return {'success': false, 'error': e.toString()};
    }
  }

  /// Teacher manually marks attendance for a student
  Future<Map<String, dynamic>> manualMarkAttendance({
    required String sessionId,
    required int studentId,
    required String status, // "present" or "absent"
  }) async {
    try {
      final token = await _getToken();
      
      final response = await _dio.post(
        '/sessions/$sessionId/mark-student/',
        data: {
          'student_id': studentId,
          'status': status,
        },
        options: Options(
          headers: {'Authorization': 'Bearer $token'},
        ),
      );
      
      if (response.statusCode == 200) {
        return {
          'success': true,
          'message': response.data['message'],
          'record': response.data['record'],
        };
      }
      
      return {'success': false, 'message': 'Failed to mark attendance'};
    } on DioException catch (e) {
      return {
        'success': false,
        'message': _parseError(e.response?.data, 'Failed to mark attendance: ${e.message}'),
      };
    }
  }
}