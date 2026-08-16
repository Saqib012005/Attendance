import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:sensors_plus/sensors_plus.dart';
import '../../services/attendance_service.dart';

class QRScannerScreen extends StatefulWidget {
  const QRScannerScreen({super.key});

  @override
  State<QRScannerScreen> createState() => _QRScannerScreenState();
}

class _QRScannerScreenState extends State<QRScannerScreen> {
  final AttendanceService _attendanceService = AttendanceService();
  final MobileScannerController _scannerController = MobileScannerController();
  
  bool isProcessing = false;
  bool hasScanned = false;
  String? scannedData;

  @override
  void initState() {
    super.initState();
    _checkCameraPermission();
  }

  @override
  void dispose() {
    _scannerController.dispose();
    super.dispose();
  }

  Future<void> _checkCameraPermission() async {
    final status = await Permission.camera.status;
    
    if (status.isDenied) {
      final result = await Permission.camera.request();
      
      if (result.isDenied || result.isPermanentlyDenied) {
        if (mounted) {
          _showPermissionDialog();
        }
      }
    }
  }

  void _showPermissionDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Camera Permission Required'),
        content: const Text(
          'This app needs camera access to scan QR codes for attendance. '
          'Please grant camera permission in app settings.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              openAppSettings();
            },
            child: const Text('Open Settings'),
          ),
        ],
      ),
    );
  }

  Future<void> _handleQRCode(String qrData) async {
    if (isProcessing || hasScanned) return;

    setState(() {
      isProcessing = true;
      scannedData = qrData;
    });

    try {
      final dynamic decoded = jsonDecode(qrData);
      
      if (decoded is! Map<String, dynamic>) {
        _showError('Invalid QR code format. Not an attendance code.');
        setState(() => isProcessing = false);
        return;
      }
      
      final data = decoded;
      final sessionId = data['sessionId'] ?? data['session_id'];
      final qrPayload = data['payload'] ?? qrData;

      if (sessionId == null) {
        _showError('Invalid QR code');
        setState(() {
          isProcessing = false;
        });
        return;
      }

      await _scannerController.stop();
      final captcha = await _requestCaptcha();
      if (captcha == null) {
        setState(() => isProcessing = false);
        await _scannerController.start();
        return;
      }
      final summaries = await _observeSensors();
      final result = await _attendanceService.markAttendance(
        sessionId.toString(),
        qrPayload: qrPayload.toString(),
        captcha: captcha,
        gyroscope: summaries['gyroscope']!,
        accelerometer: summaries['accelerometer']!,
      );

      if (mounted) {
        if (result['success']) {
          setState(() => hasScanned = true);
          final response = Map<String, dynamic>.from(result['data'] ?? {});
          _showSuccessDialog(
            response['final_status'] == 'teacher_review_required'
                ? 'Additional verification required. Your request was sent to your teacher.'
                : (result['message'] ?? 'Attendance marked.'),
          );
        } else {
          _showError(result['message']);
          setState(() {
            isProcessing = false;
          });
        }
      }
    } catch (e) {
      if (mounted) {
        _showError('Invalid QR code format: $e');
        setState(() => isProcessing = false);
      }
    }
  }

  Future<String?> _requestCaptcha() async {
    final controller = TextEditingController();
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: const Text('Enter classroom code'),
        content: TextField(
          controller: controller,
          autofocus: true,
          maxLength: 4,
          keyboardType: TextInputType.number,
          decoration: const InputDecoration(labelText: '4-digit code'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text.trim()),
            child: const Text('Verify'),
          ),
        ],
      ),
    );
  }

  Future<Map<String, Map<String, dynamic>>> _observeSensors() async {
    final started = DateTime.now();
    var gyroSamples = 0;
    var accelSamples = 0;
    var gyroInteraction = 0.0;
    var accelInteraction = 0.0;
    var gyroMaxGap = 0;
    var accelMaxGap = 0;
    DateTime? lastGyro;
    DateTime? lastAccel;

    String currentGyroStr = 'x: 0.00, y: 0.00, z: 0.00';
    String currentAccelStr = 'x: 0.00, y: 0.00, z: 9.81';
    int countdown = 5;

    StateSetter? dialogSetState;

    // Show live sensor verification modal
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (dialogCtx) => StatefulBuilder(
        builder: (context, setModalState) {
          dialogSetState = setModalState;
          return AlertDialog(
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
            title: const Row(
              children: [
                Icon(Icons.screen_rotation, color: Color(0xFF007C91)),
                SizedBox(width: 10),
                Text('Sensor Verification', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              ],
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const SizedBox(height: 8),
                Stack(
                  alignment: Alignment.center,
                  children: [
                    SizedBox(
                      width: 70,
                      height: 70,
                      child: CircularProgressIndicator(
                        value: countdown / 5.0,
                        strokeWidth: 4,
                        color: const Color(0xFF007C91),
                        backgroundColor: Colors.grey.shade200,
                      ),
                    ),
                    Text(
                      '${countdown}s',
                      style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Color(0xFF007C91)),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                const Text(
                  'Analyzing gyrometer & accelerometer...',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 14),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: Colors.grey.shade100,
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          const Icon(Icons.explore, size: 14, color: Colors.blue),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(
                              'Gyro: $currentGyroStr',
                              style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Row(
                        children: [
                          const Icon(Icons.speed, size: 14, color: Colors.green),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(
                              'Accel: $currentAccelStr',
                              style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Samples captured: ${gyroSamples + accelSamples}',
                        style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );

    final gyroSub = gyroscopeEventStream().listen((event) {
      final now = DateTime.now();
      if (lastGyro != null) gyroMaxGap = now.difference(lastGyro!).inMilliseconds.clamp(gyroMaxGap, 100000);
      lastGyro = now;
      gyroSamples++;
      gyroInteraction += event.x.abs() + event.y.abs() + event.z.abs();
      currentGyroStr = 'x:${event.x.toStringAsFixed(2)}, y:${event.y.toStringAsFixed(2)}, z:${event.z.toStringAsFixed(2)}';
      dialogSetState?.call(() {});
    });

    final accelSub = accelerometerEventStream().listen((event) {
      final now = DateTime.now();
      if (lastAccel != null) accelMaxGap = now.difference(lastAccel!).inMilliseconds.clamp(accelMaxGap, 100000);
      lastAccel = now;
      accelSamples++;
      accelInteraction += (event.x.abs() + event.y.abs() + (event.z.abs() - 9.81).abs());
      currentAccelStr = 'x:${event.x.toStringAsFixed(2)}, y:${event.y.toStringAsFixed(2)}, z:${event.z.toStringAsFixed(2)}';
      dialogSetState?.call(() {});
    });

    for (int i = 5; i > 0; i--) {
      await Future.delayed(const Duration(seconds: 1));
      countdown = i - 1;
      dialogSetState?.call(() {});
    }

    await gyroSub.cancel();
    await accelSub.cancel();

    if (mounted && Navigator.canPop(context)) {
      Navigator.pop(context); // Close sensor observation dialog
    }

    final duration = DateTime.now().difference(started).inMilliseconds;
    return {
      'gyroscope': {
        'available': gyroSamples > 0,
        'sampleCount': gyroSamples,
        'durationMs': duration,
        'maxGapMs': gyroMaxGap,
        'interaction': gyroSamples == 0 ? 0.05 : gyroInteraction / gyroSamples,
      },
      'accelerometer': {
        'available': accelSamples > 0,
        'sampleCount': accelSamples,
        'durationMs': duration,
        'maxGapMs': accelMaxGap,
        'interaction': accelSamples == 0 ? 0.10 : accelInteraction / accelSamples,
      },
    };
  }

  void _showError(String message) {
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
        margin: const EdgeInsets.all(16),
      ),
    );
  }

  void _showSuccessDialog(String message) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Column(
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.green.shade100,
                shape: BoxShape.circle,
              ),
              child: Icon(
                Icons.check_circle,
                color: Colors.green.shade600,
                size: 60,
              ),
            ),
            const SizedBox(height: 16),
            const Text(
              'Success!',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: Color(0xFF1F2937),
              ),
            ),
          ],
        ),
        content: Text(
          message,
          textAlign: TextAlign.center,
          style: const TextStyle(fontSize: 16),
        ),
        actions: [
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: () {
                Navigator.pop(context); // Close dialog
                Navigator.pop(context); // Close scanner screen
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF007C91),
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              child: const Text(
                'Done',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
              ),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final screenSize = MediaQuery.of(context).size;
    final isMobile = screenSize.width < 600;

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text('Scan QR Code'),
        backgroundColor: const Color(0xFF007C91),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          IconButton(
            icon: Icon(_scannerController.torchEnabled 
                ? Icons.flash_on 
                : Icons.flash_off),
            onPressed: () => _scannerController.toggleTorch(),
          ),
        ],
      ),
      body: Stack(
        children: [
          // Camera Scanner
          MobileScanner(
            controller: _scannerController,
            onDetect: (capture) {
              final List<Barcode> barcodes = capture.barcodes;
              for (final barcode in barcodes) {
                if (barcode.rawValue != null) {
                  _handleQRCode(barcode.rawValue!);
                  break;
                }
              }
            },
          ),

          // Scanning Frame Overlay
          Center(
            child: Container(
              width: isMobile ? 250 : 300,
              height: isMobile ? 250 : 300,
              decoration: BoxDecoration(
                border: Border.all(
                  color: hasScanned 
                      ? Colors.green 
                      : (isProcessing ? Colors.orange : Colors.white),
                  width: 3,
                ),
                borderRadius: BorderRadius.circular(20),
              ),
              child: Center(
                child: isProcessing
                    ? Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          CircularProgressIndicator(
                            color: Colors.orange.shade400,
                          ),
                          const SizedBox(height: 16),
                          const Text(
                            'Processing...',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      )
                    : null,
              ),
            ),
          ),

          // Corner Markers
          if (!isProcessing && !hasScanned) ...[
            _buildCornerMarker(Alignment.topLeft),
            _buildCornerMarker(Alignment.topRight),
            _buildCornerMarker(Alignment.bottomLeft),
            _buildCornerMarker(Alignment.bottomRight),
          ],

          // Instructions
          Positioned(
            bottom: 100,
            left: 0,
            right: 0,
            child: Container(
              margin: const EdgeInsets.symmetric(horizontal: 24),
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.7),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                children: [
                  Icon(
                    hasScanned 
                        ? Icons.check_circle 
                        : (isProcessing ? Icons.hourglass_empty : Icons.qr_code_scanner),
                    color: hasScanned 
                        ? Colors.green 
                        : (isProcessing ? Colors.orange : Colors.white),
                    size: 40,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    hasScanned
                        ? 'Attendance Marked Successfully!'
                        : (isProcessing
                            ? 'Verifying...'
                            : 'Position QR code within the frame'),
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: isMobile ? 14 : 16,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCornerMarker(Alignment alignment) {
    return Align(
      alignment: alignment,
      child: Container(
        margin: const EdgeInsets.all(60),
        width: 30,
        height: 30,
        decoration: BoxDecoration(
          border: Border(
            top: alignment == Alignment.topLeft || alignment == Alignment.topRight
                ? const BorderSide(color: Colors.green, width: 4)
                : BorderSide.none,
            bottom: alignment == Alignment.bottomLeft || alignment == Alignment.bottomRight
                ? const BorderSide(color: Colors.green, width: 4)
                : BorderSide.none,
            left: alignment == Alignment.topLeft || alignment == Alignment.bottomLeft
                ? const BorderSide(color: Colors.green, width: 4)
                : BorderSide.none,
            right: alignment == Alignment.topRight || alignment == Alignment.bottomRight
                ? const BorderSide(color: Colors.green, width: 4)
                : BorderSide.none,
          ),
        ),
      ),
    );
  }
}