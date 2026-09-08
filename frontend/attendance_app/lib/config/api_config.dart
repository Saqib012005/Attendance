import 'package:flutter/foundation.dart';

class ApiConfig {
  // Override the base URL at compile time for ANY environment:
  //   flutter run --dart-define=API_BASE_URL=https://your-host/api/v1
  static const String _apiBaseUrl = String.fromEnvironment('API_BASE_URL');

  // Railway Cloud Production backend URL
  static const String _productionUrl = 'https://backend-production-b537.up.railway.app/api/v1';

  // Local fallback for emulator debugging
  static const String _androidEmulatorUrl = 'http://10.0.2.2:8000/api/v1';

  // Base URL resolution
  static String get baseUrl {
    if (_apiBaseUrl.isNotEmpty) return _apiBaseUrl; // compile-time override wins
    if (kIsWeb) {
      final origin = Uri.base.origin;
      if (origin.isNotEmpty && !origin.startsWith('file:')) {
        return '$origin/api/v1';
      }
      return _productionUrl;
    }
    return _productionUrl; // default production backend for mobile release APKs
  }

  // Connection settings
  static const Duration connectionTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);

  // Auth endpoints (computed getters)
  static String get login => '$baseUrl/auth/token/';
  static String get register => '$baseUrl/auth/register/';
  static String get me => '$baseUrl/auth/me/';
  static String get tokenRefresh => '$baseUrl/auth/token/refresh/';

  // Headers
  static Map<String, String> get headers => {
    'Content-Type': 'application/json',
    'Bypass-Tunnel-Reminder': 'true',
  };

  static Map<String, String> authHeaders(String? token) => {
    'Content-Type': 'application/json',
    if (token != null && token.isNotEmpty) 'Authorization': 'Bearer $token',
    'Bypass-Tunnel-Reminder': 'true',
  };
}
// import 'package:flutter/foundation.dart';

// class ApiConfig {
//   static const String _apiBaseUrl =
//       String.fromEnvironment('API_BASE_URL');

//   // Android Emulator
//   static const String _androidEmulatorUrl =
//       'http://10.0.2.2:8000/api/v1';

//   // Flutter Web / Chrome
//   static const String _webUrl =
//       'http://localhost:8000/api/v1';

//   static const String _productionUrl =
//       'https://your-backend.example.com/api/v1';

//   static const bool isProduction = false;

//   // static String get baseUrl {
//   //   if (_apiBaseUrl.isNotEmpty) {
//   //     return _apiBaseUrl;
//   //   }

//   //   if (isProduction) {
//   //     return _productionUrl;
//   //   }

//   //   if (kIsWeb) {
//   //     return _webUrl;
//   //   }

//   //   return _androidEmulatorUrl;
//   // }
//     static String get baseUrl {
//     if (_apiBaseUrl.isNotEmpty) {
//       return _apiBaseUrl;
//     }

//     if (isProduction) {
//       return _productionUrl;
//     }

//     if (defaultTargetPlatform == TargetPlatform.windows) {
//       return _webUrl; 
//     }

//     if (kIsWeb) {
//       return _webUrl;
//     }

//     return _androidEmulatorUrl;
//   }

//   static const Duration connectionTimeout =
//       Duration(seconds: 90);

//   static const Duration receiveTimeout =
//       Duration(seconds: 90);

//   static String login = '$baseUrl/auth/token/';
//   static String register = '$baseUrl/auth/register/';
//   static String me = '$baseUrl/auth/me/';
//   static String tokenRefresh =
//       '$baseUrl/auth/token/refresh/';

//   static Map<String, String> get headers => {
//         'Content-Type': 'application/json',
//       };

//   static Map<String, String> authHeaders(String? token) => {
//         'Content-Type': 'application/json',
//         'Authorization': 'Bearer ${token ?? ""}',
//       };
// }