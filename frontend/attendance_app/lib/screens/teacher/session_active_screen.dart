import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../services/session_service.dart';

class SessionActiveScreen extends StatefulWidget {
  final Map<String, dynamic> sessionData;
  final String qrCodeData;

  const SessionActiveScreen({
    super.key,
    required this.sessionData,
    required this.qrCodeData,
  });

  @override
  State<SessionActiveScreen> createState() => _SessionActiveScreenState();
}

class _SessionActiveScreenState extends State<SessionActiveScreen> {
  final SessionService _sessionService = SessionService();
  
  Timer? _countdownTimer;
  Timer? _refreshTimer;
  Timer? _qrTimer;
  int remainingSeconds = 0;
  
  List<Map<String, dynamic>> students = [];
  Map<String, dynamic> statistics = {};
  bool isLoading = true;
  bool isUploadingReference = false;
  String? referenceImagePath;
  String? _secureQr;
  String _captcha = '----';
  int _qrSeconds = 20;
  List<Map<String, dynamic>> _reviews = [];

  @override
  void initState() {
    super.initState();
    _initializeSession();
    _startAutoRefresh();
    _refreshSecureEpoch();
  }

  @override
  void dispose() {
    _countdownTimer?.cancel();
    _refreshTimer?.cancel();
    _qrTimer?.cancel();
    super.dispose();
  }

  void _initializeSession() {
    // CHANGE THIS: Use IST fields if available, fallback to original
    final startTimeStr = widget.sessionData['start_time_ist'] ?? 
                        widget.sessionData['start_time'];
    final endTimeStr = widget.sessionData['end_time_ist'] ?? 
                      widget.sessionData['end_time'];
    
    // Parse as UTC then convert to local
    DateTime startTime;
    DateTime endTime;
    
    try {
      // Parse the ISO string (includes timezone offset)
      startTime = DateTime.parse(startTimeStr);
      endTime = DateTime.parse(endTimeStr);
      
      // If no timezone info, assume it's UTC and convert to local
      if (!startTimeStr.contains('+') && !startTimeStr.contains('Z')) {
        startTime = DateTime.parse(startTimeStr).toUtc().toLocal();
        endTime = DateTime.parse(endTimeStr).toUtc().toLocal();
      }
    } catch (e) {
      print('Error parsing time: $e');
      startTime = DateTime.now();
      endTime = DateTime.now().add(const Duration(hours: 1));
    }
    
    print('Start Time: $startTime'); // Debug
    print('End Time: $endTime');     // Debug
    print('Current Time: ${DateTime.now()}'); // Debug
    
    final duration = endTime.difference(DateTime.now());
    
    setState(() {
      remainingSeconds = duration.inSeconds > 0 ? duration.inSeconds : 0;
    });

    // Start countdown
    _countdownTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (remainingSeconds > 0) {
        setState(() => remainingSeconds--);
      } else {
        timer.cancel();
        _endSession();
      }
    });

    // Load initial data
    _fetchAttendanceData();
  }

  void _startAutoRefresh() {
    // Refresh student list every 3 seconds for real-time updates
    _refreshTimer = Timer.periodic(const Duration(seconds: 3), (timer) {
      _fetchAttendanceData(showLoading: false);
      _fetchReviews();
    });
    _qrTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (!mounted) return timer.cancel();
      if (_qrSeconds <= 1) {
        _refreshSecureEpoch();
      } else {
        setState(() => _qrSeconds--);
      }
    });
  }

  Future<void> _refreshSecureEpoch() async {
    try {
      final sessionId = widget.sessionData['session_id'].toString();
      final epoch = await _sessionService.getSecureEpoch(sessionId);
      if (epoch != null && mounted) {
        setState(() {
          _secureQr = epoch['qr_payload']?.toString();
          _captcha = epoch['captcha']?.toString() ?? '----';
          final expiresAt = (epoch['expires_at'] as num?)?.toDouble() ?? 0;
          final serverTime = (epoch['server_time'] as num?)?.toDouble() ?? 0;
          final diff = (expiresAt - serverTime).ceil();
          _qrSeconds = diff > 0 ? diff.clamp(1, 20) : 20;
        });
      }
    } catch (e) {
      print('Error in _refreshSecureEpoch: $e');
    }
  }

  Future<void> _fetchReviews() async {
    try {
      final reviews = await _sessionService.getPendingReviews(widget.sessionData['session_id']);
      if (mounted) setState(() => _reviews = reviews);
    } catch (_) {}
  }

  Future<void> _fetchAttendanceData({bool showLoading = true}) async {
    if (showLoading) {
      setState(() => isLoading = true);
    }

    try {
      final result = await _sessionService.getSessionAttendance(
        widget.sessionData['session_id'],
      );

      if (result != null && result['success'] == true && mounted) {
        setState(() {
          students = List<Map<String, dynamic>>.from(result['students'] ?? []);
          statistics = result['statistics'] ?? {};
          isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => isLoading = false);
      }
      print('Error fetching attendance: $e');
    }
  }

  Future<void> _manualMarkAttendance(int studentId, String status) async {
    final result = await _sessionService.manualMarkAttendance(
      sessionId: widget.sessionData['session_id'],
      studentId: studentId,
      status: status,
    );

    if (result['success']) {
      _showSuccessSnackBar(result['message'] ?? 'Attendance updated');
      _fetchAttendanceData(showLoading: false); // Refresh immediately
    } else {
      _showErrorSnackBar(result['message'] ?? 'Failed to update');
    }
  }

  Future<void> _endSession() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.red.shade100,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Icon(Icons.warning_rounded, color: Colors.red.shade700),
            ),
            const SizedBox(width: 12),
            const Text('End Session?'),
          ],
        ),
        content: const Text(
          'All students who haven\'t marked attendance will be automatically marked as ABSENT.\n\nThis action cannot be undone.',
          style: TextStyle(fontSize: 14, height: 1.5),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
              foregroundColor: Colors.white,
            ),
            child: const Text('End Session'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      // Show loading
      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (context) => const Center(
          child: CircularProgressIndicator(),
        ),
      );

      final result = await _sessionService.endSession(widget.sessionData['session_id']);
      
      if (mounted) {
        Navigator.pop(context); // Close loading
        
        if (result['success'] == true) {
          final stats = result['statistics'] ?? {};
          
          // Show statistics dialog
          await showDialog(
            context: context,
            builder: (context) => AlertDialog(
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
              title: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(
                        colors: [Color(0xFF007C91), Color(0xFF0097A7)],
                      ),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(Icons.check_circle, color: Colors.white),
                  ),
                  const SizedBox(width: 12),
                  const Text('Session Ended'),
                ],
              ),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildStatRow('Total Students', '${stats['total_students'] ?? 0}', 
                    Icons.people, const Color(0xFF007C91)),
                  const SizedBox(height: 12),
                  _buildStatRow('Present', '${stats['present'] ?? 0}', 
                    Icons.check_circle, Colors.green),
                  const SizedBox(height: 12),
                  _buildStatRow('Absent', '${stats['absent'] ?? 0}', 
                    Icons.cancel, Colors.red),
                  const SizedBox(height: 12),
                  _buildStatRow('Attendance Rate', '${stats['attendance_rate'] ?? 0}%', 
                    Icons.trending_up, Colors.orange),
                  
                  if ((stats['auto_marked_absent'] ?? 0) > 0) ...[
                    const Divider(height: 24),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.orange.shade50,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: Colors.orange.shade200),
                      ),
                      child: Row(
                        children: [
                          Icon(Icons.info_outline, color: Colors.orange.shade700, size: 20),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              '${stats['auto_marked_absent']} student(s) automatically marked absent',
                              style: TextStyle(
                                fontSize: 12,
                                color: Colors.orange.shade700,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ],
              ),
              actions: [
                ElevatedButton(
                  onPressed: () {
                    Navigator.pop(context); // Close dialog
                    Navigator.pop(context); // Go back to previous screen
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF007C91),
                    padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  child: const Text('Done'),
                ),
              ],
            ),
          );
        } else {
          _showErrorSnackBar(result['message'] ?? 'Failed to end session');
        }
      }
    }
  }

  Widget _buildStatRow(String label, String value, IconData icon, Color color) {
    return Row(
      children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: color.withOpacity(0.1),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(icon, color: color, size: 20),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Text(
            label,
            style: TextStyle(
              fontSize: 14,
              color: Colors.grey.shade700,
            ),
          ),
        ),
        Text(
          value,
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: color,
          ),
        ),
      ],
    );
  }

  void _showSuccessSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            const Icon(Icons.check_circle, color: Colors.white),
            const SizedBox(width: 12),
            Expanded(child: Text(message)),
          ],
        ),
        backgroundColor: Colors.green,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
    );
  }

  void _showErrorSnackBar(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            const Icon(Icons.error_outline, color: Colors.white),
            const SizedBox(width: 12),
            Expanded(child: Text(message)),
          ],
        ),
        backgroundColor: Colors.red.shade600,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    );
  }

  String _formatTime(int seconds) {
    final hours = seconds ~/ 3600;
    final minutes = (seconds % 3600) ~/ 60;
    final secs = seconds % 60;
    
    if (hours > 0) {
      return '${hours.toString().padLeft(2, '0')}:${minutes.toString().padLeft(2, '0')}:${secs.toString().padLeft(2, '0')}';
    }
    return '${minutes.toString().padLeft(2, '0')}:${secs.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final isDesktop = size.width > 1000;
    final isTablet = size.width > 600 && size.width <= 1000;
    final isMobile = size.width <= 600;

    return Scaffold(
      backgroundColor: const Color(0xFFF4F8FB),
      appBar: AppBar(
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Active Session: ${widget.sessionData['class_code']}',
              style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            Text(
              widget.sessionData['class_name'] ?? '',
              style: const TextStyle(fontSize: 14, fontWeight: FontWeight.normal),
            ),
          ],
        ),
        backgroundColor: const Color(0xFF007C91),
        foregroundColor: Colors.white,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => _fetchAttendanceData(),
            tooltip: 'Refresh',
          ),
          IconButton(
            icon: const Icon(Icons.stop_circle),
            onPressed: _endSession,
            tooltip: 'End Session',
          ),
        ],
      ),
      body: isLoading
          ? const Center(child: CircularProgressIndicator())
          : isMobile
              ? _buildMobileLayout()
              : _buildDesktopLayout(isDesktop),
    );
  }

  Widget _buildMobileLayout() {
    return SingleChildScrollView(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            _buildTimerCard(),
            const SizedBox(height: 16),
            _buildQRSection(size: 200),
            const SizedBox(height: 16),
            _buildStatisticsCard(),
            const SizedBox(height: 16),
            _buildStudentsList(),
          ],
        ),
      ),
    );
  }

  Widget _buildDesktopLayout(bool isDesktop) {
    return Row(
      children: [
        // LEFT SIDE - QR Code
        Expanded(
          flex: isDesktop ? 2 : 3,
          child: Container(
            color: Colors.white,
            child: SingleChildScrollView(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    _buildTimerCard(),
                    const SizedBox(height: 32),
                    _buildQRSection(size: isDesktop ? 400 : 300),
                    const SizedBox(height: 24),
                    _buildStatisticsCard(),
                  ],
                ),
              ),
            ),
          ),
        ),

        // DIVIDER
        Container(width: 1, color: Colors.grey[300]),

        // RIGHT SIDE - Students List
        Expanded(
          flex: isDesktop ? 3 : 4,
          child: _buildStudentsList(),
        ),
      ],
    );
  }

  Widget _buildTimerCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: remainingSeconds > 60
              ? [const Color(0xFF007C91), const Color(0xFF0097A7)]
              : [Colors.orange.shade600, Colors.deepOrange.shade700],
        ),
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: (remainingSeconds > 60
                    ? const Color(0xFF007C91)
                    : Colors.orange)
                .withOpacity(0.3),
            blurRadius: 15,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.timer, color: Colors.white, size: 32),
          const SizedBox(width: 16),
          Text(
            _formatTime(remainingSeconds),
            style: const TextStyle(
              fontSize: 48,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQRSection({required double size}) {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: const Color(0xFF007C91).withOpacity(0.3), width: 2),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF007C91).withOpacity(0.12),
            blurRadius: 24,
            offset: const Offset(0, 12),
          ),
        ],
      ),
      child: Column(
        children: [
          // Live Attendance Header
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            decoration: BoxDecoration(
              color: const Color(0xFFE0F7FA),
              borderRadius: BorderRadius.circular(20),
            ),
            child: const Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.shield, color: Color(0xFF007C91), size: 18),
                SizedBox(width: 8),
                Text(
                  'LIVE ATTENDANCE',
                  style: TextStyle(
                    color: Color(0xFF007C91),
                    fontWeight: FontWeight.bold,
                    fontSize: 13,
                    letterSpacing: 1.2,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Dynamic Rotating QR Code
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: Colors.grey.shade200),
            ),
            child: QrImageView(
              data: _secureQr == null
                  ? widget.qrCodeData
                  : jsonEncode({
                      'sessionId': widget.sessionData['session_id'].toString(),
                      'payload': _secureQr,
                    }),
              version: QrVersions.auto,
              size: size,
              backgroundColor: Colors.white,
              foregroundColor: const Color(0xFF00695C),
            ),
          ),
          const SizedBox(height: 16),

          // Countdown pill
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
            decoration: BoxDecoration(
              color: Colors.amber.shade50,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.amber.shade400),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(
                    value: _qrSeconds / 20.0,
                    strokeWidth: 2.5,
                    color: Colors.amber.shade800,
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  'Refreshes in ${_qrSeconds}s',
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.bold,
                    color: Colors.amber.shade900,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Classroom CAPTCHA Display
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
            decoration: BoxDecoration(
              color: const Color(0xFFF0FDF4),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: const Color(0xFF22C55E), width: 1.5),
            ),
            child: Column(
              children: [
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: _captcha.split('').map((char) {
                    return Container(
                      margin: const EdgeInsets.symmetric(horizontal: 4),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: const Color(0xFF86EFAC)),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withOpacity(0.04),
                            blurRadius: 4,
                          ),
                        ],
                      ),
                      child: Text(
                        char,
                        style: const TextStyle(
                          fontSize: 26,
                          fontWeight: FontWeight.w900,
                          color: Color(0xFF15803D),
                          fontFamily: 'Inter',
                        ),
                      ),
                    );
                  }).toList(),
                ),
                const SizedBox(height: 4),
                const Text(
                  'Classroom CAPTCHA',
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: Color(0xFF166534),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Status Badges
          const Wrap(
            spacing: 8,
            runSpacing: 6,
            alignment: WrapAlignment.center,
            children: [
              _StatusPill(text: '● SESSION ACTIVE', color: Colors.green),
              _StatusPill(text: '● QR SECURE', color: Colors.teal),
              _StatusPill(text: '● REAL-TIME CONNECTED', color: Colors.blue),
            ],
          ),

          if (_reviews.isNotEmpty) ...[
            const SizedBox(height: 16),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: Colors.amber.shade700,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
              ),
              onPressed: _showReviewQueue,
              icon: const Icon(Icons.fact_check, size: 20),
              label: Text(
                '${_reviews.length} Teacher Review Required',
                style: const TextStyle(fontWeight: FontWeight.bold),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Future<void> _showReviewQueue() async {
    await showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => Container(
        padding: const EdgeInsets.all(24),
        decoration: const BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        child: SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Row(
                    children: [
                      Icon(Icons.verified_user, color: Color(0xFF007C91)),
                      SizedBox(width: 8),
                      Text(
                        'ATTENDANCE CROSS-VERIFICATION',
                        style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                      ),
                    ],
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
              const Divider(height: 24),
              if (_reviews.isEmpty)
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 24),
                  child: Center(child: Text('No pending cross-verification requests')),
                )
              else
                Flexible(
                  child: ListView.separated(
                    shrinkWrap: true,
                    itemCount: _reviews.length,
                    separatorBuilder: (_, __) => const Divider(height: 24),
                    itemBuilder: (context, index) {
                      final review = _reviews[index];
                      final matrix = Map<String, dynamic>.from(review['verification'] ?? {});
                      final studentName = review['student_name'] ?? 'Student';
                      final rollNo = review['roll_no'] ?? 'N/A';

                      return Container(
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: Colors.grey.shade50,
                          borderRadius: BorderRadius.circular(16),
                          border: Border.all(color: Colors.grey.shade200),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Text(
                                  studentName,
                                  style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                                ),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                                  decoration: BoxDecoration(
                                    color: Colors.amber.shade100,
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                  child: Text(
                                    'Roll No: $rollNo',
                                    style: TextStyle(
                                      fontWeight: FontWeight.w600,
                                      fontSize: 12,
                                      color: Colors.amber.shade900,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 12),
                            const Text(
                              'VERIFICATION DETAILS',
                              style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.grey),
                            ),
                            const SizedBox(height: 8),
                            Wrap(
                              spacing: 8,
                              runSpacing: 6,
                              children: [
                                _GateBadge(label: 'QR Authenticity', passed: matrix['qr_authenticity'] == 'pass'),
                                _GateBadge(label: 'QR Freshness', passed: matrix['qr_freshness'] == 'pass'),
                                _GateBadge(label: 'Session Validation', passed: matrix['session'] == 'pass'),
                                _GateBadge(label: 'Student Eligibility', passed: matrix['student_eligibility'] == 'pass'),
                                _GateBadge(label: 'Device Validation', passed: matrix['device'] == 'pass'),
                                _GateBadge(label: 'Numeric CAPTCHA', passed: matrix['captcha'] == 'pass'),
                                _GateBadge(label: 'Gyroscope', passed: matrix['gyroscope'] == 'pass'),
                                _GateBadge(label: 'Accelerometer', passed: matrix['accelerometer'] == 'pass'),
                              ],
                            ),
                            const SizedBox(height: 16),
                            Row(
                              mainAxisAlignment: MainAxisAlignment.end,
                              children: [
                                OutlinedButton.icon(
                                  style: OutlinedButton.styleFrom(
                                    foregroundColor: Colors.red.shade700,
                                    side: BorderSide(color: Colors.red.shade300),
                                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                                  ),
                                  icon: const Icon(Icons.close, size: 18),
                                  label: const Text('DO NOT MARK PRESENT'),
                                  onPressed: () async {
                                    await _sessionService.resolveReview(review['record_id'], 'reject');
                                    if (mounted) Navigator.pop(context);
                                    _fetchReviews();
                                  },
                                ),
                                const SizedBox(width: 12),
                                FilledButton.icon(
                                  style: FilledButton.styleFrom(
                                    backgroundColor: Colors.green.shade600,
                                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                                  ),
                                  icon: const Icon(Icons.check, size: 18),
                                  label: const Text('MARK PRESENT'),
                                  onPressed: () async {
                                    await _sessionService.resolveReview(review['record_id'], 'present');
                                    if (mounted) Navigator.pop(context);
                                    _fetchReviews();
                                    _fetchAttendanceData(showLoading: false);
                                  },
                                ),
                              ],
                            ),
                          ],
                        ),
                      );
                    },
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStatisticsCard() {
    final total = statistics['total'] ?? 0;
    final present = statistics['present'] ?? 0;
    final absent = statistics['absent'] ?? 0;
    final rate = statistics['attendance_rate'] ?? 0.0;

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [Colors.blue.shade50, Colors.white],
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.blue.shade200),
      ),
      child: Column(
        children: [
          const Text(
            'Attendance Statistics',
            style: TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.bold,
              color: Color(0xFF1F2937),
            ),
          ),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: [
              _buildStatItem('Total', total.toString(), Colors.blue),
              _buildStatItem('Present', present.toString(), Colors.green),
              _buildStatItem('Absent', absent.toString(), Colors.red),
            ],
          ),
          const SizedBox(height: 16),
          LinearProgressIndicator(
            value: total > 0 ? present / total : 0,
            backgroundColor: Colors.grey[300],
            valueColor: AlwaysStoppedAnimation<Color>(
              rate >= 75 ? Colors.green : (rate >= 50 ? Colors.orange : Colors.red),
            ),
            minHeight: 10,
            borderRadius: BorderRadius.circular(5),
          ),
          const SizedBox(height: 8),
          Text(
            '${rate.toStringAsFixed(1)}% Attendance Rate',
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.bold,
              color: rate >= 75
                  ? Colors.green[700]
                  : (rate >= 50 ? Colors.orange[700] : Colors.red[700]),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatItem(String label, String value, Color color) {
    return Column(
      children: [
        Text(
          value,
          style: TextStyle(
            fontSize: 28,
            fontWeight: FontWeight.bold,
            color: color,
          ),
        ),
        Text(
          label,
          style: TextStyle(
            fontSize: 14,
            color: Colors.grey[600],
          ),
        ),
      ],
    );
  }

  Widget _buildStudentsList() {
    if (students.isEmpty) {
      return const Center(
        child: Text('No students enrolled in this class'),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: students.length,
      itemBuilder: (context, index) {
        final student = students[index];
        final isPresent = student['status'] == 'present';
        final hasRecord = student['has_record'] == true;

        return Card(
          margin: const EdgeInsets.only(bottom: 12),
          elevation: 2,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(
              color: isPresent ? Colors.green : Colors.red.shade200,
              width: 2,
            ),
          ),
          child: ListTile(
            contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            leading: CircleAvatar(
              radius: 24,
              backgroundColor: isPresent ? Colors.green : Colors.red,
              child: Icon(
                isPresent ? Icons.check_circle : Icons.cancel,
                color: Colors.white,
                size: 28,
              ),
            ),
            title: Text(
              student['username'] ?? 'Unknown',
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            subtitle: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const SizedBox(height: 4),
                Text(
                  'Roll No: ${student['roll_no'] ?? 'N/A'}',
                  style: TextStyle(color: Colors.grey[700]),
                ),
                if (hasRecord && student['marked_at'] != null)
                  Text(
                    'Marked at: ${DateTime.parse(student['marked_at']).toLocal().toString().substring(11, 16)}',
                    style: TextStyle(
                      fontSize: 12,
                      color: Colors.grey[600],
                      fontStyle: FontStyle.italic,
                    ),
                  ),
              ],
            ),
            trailing: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Present Button
                IconButton(
                  onPressed: isPresent
                      ? null
                      : () => _manualMarkAttendance(
                            student['id'],
                            'present',
                          ),
                  icon: const Icon(Icons.check_circle),
                  color: Colors.green,
                  tooltip: 'Mark Present',
                  style: IconButton.styleFrom(
                    backgroundColor: isPresent
                        ? Colors.green.withOpacity(0.2)
                        : Colors.green.withOpacity(0.1),
                  ),
                ),
                const SizedBox(width: 8),
                // Absent Button
                IconButton(
                  onPressed: !isPresent
                      ? null
                      : () => _manualMarkAttendance(
                            student['id'],
                            'absent',
                          ),
                  icon: const Icon(Icons.cancel),
                  color: Colors.red,
                  tooltip: 'Mark Absent',
                  style: IconButton.styleFrom(
                    backgroundColor: !isPresent
                        ? Colors.red.withOpacity(0.2)
                        : Colors.red.withOpacity(0.1),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

class _StatusPill extends StatelessWidget {
  final String text;
  final Color color;

  const _StatusPill({required this.text, required this.color});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Text(
        text,
        style: TextStyle(
          color: color,
          fontSize: 11,
          fontWeight: FontWeight.bold,
          letterSpacing: 0.5,
        ),
      ),
    );
  }
}

class _GateBadge extends StatelessWidget {
  final String label;
  final bool passed;

  const _GateBadge({required this.label, required this.passed});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: passed ? Colors.green.shade50 : Colors.red.shade50,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: passed ? Colors.green.shade300 : Colors.red.shade300),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            passed ? Icons.check_circle : Icons.cancel,
            size: 16,
            color: passed ? Colors.green.shade700 : Colors.red.shade700,
          ),
          const SizedBox(width: 6),
          Text(
            label,
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: passed ? Colors.green.shade900 : Colors.red.shade900,
            ),
          ),
        ],
      ),
    );
  }
}