import 'package:flutter/material.dart';
import '../../services/auth_service.dart';
import '../../services/profile_service.dart';
import '../student/my_classes_screen.dart';
import '../student/qr_scanner_screen.dart';
import '../student/attendance_history_screen.dart';
import '../student/student_profile_screen.dart';

// ─── App colour constants ──────────────────────────────────────────────────────
// Mirrors TeacherDashboardPage._AppColors exactly.
abstract class _AppColors {
  static const tealDark    = Color(0xFF007C91);
  static const teal        = Color(0xFF0097A7);
  static const tealLight   = Color(0xFF0288A3);
  static const background  = Color(0xFFF7FAFC);
  static const darkBg      = Color(0xFF1E1E2D);
  static const textPrimary = Color(0xFF1F2937);
  static const textMuted   = Color(0xFF6B7280);
}

// ─── Navigation enum ──────────────────────────────────────────────────────────
enum _DashboardAction {
  myClasses,
  scanQR,
  attendanceHistory,
  profile,
  announcements,
  logout,
}

// ─── Typed card model ─────────────────────────────────────────────────────────
class _DashboardCard {
  final String           title;
  final String           subtitle;
  final IconData         icon;
  final Color            color;
  final List<Color>      gradient;
  final _DashboardAction action;

  const _DashboardCard({
    required this.title,
    required this.subtitle,
    required this.icon,
    required this.color,
    required this.gradient,
    required this.action,
  });
}

// ─── Page ─────────────────────────────────────────────────────────────────────
class StudentDashboardPage extends StatefulWidget {
  const StudentDashboardPage({super.key});

  @override
  State<StudentDashboardPage> createState() => _StudentDashboardPageState();
}

class _StudentDashboardPageState extends State<StudentDashboardPage> {
  final AuthService    _authService    = AuthService();
  final ProfileService _profileService = ProfileService();

  bool   _isSidebarExpanded = false;
  String _studentName       = 'Loading...';
  String _username          = '';
  bool   _isLoading         = true;
  int    _totalClasses      = 0;
  double _attendanceRate    = 0.0;

  Map<String, dynamic>? _cachedUserData;
  DateTime?             _lastFetch;

  // Compile-time constant — no heap allocation on every build.
  static const _cards = <_DashboardCard>[
    _DashboardCard(
      title:    'My Classes',
      subtitle: 'View enrolled courses',
      icon:     Icons.school_rounded,
      color:    Color(0xFF3B82F6),
      gradient: [Color(0xFF60A5FA), Colors.white],
      action:   _DashboardAction.myClasses,
    ),
    _DashboardCard(
      title:    'Scan QR',
      subtitle: 'Mark your attendance',
      icon:     Icons.qr_code_scanner_rounded,
      color:    Color(0xFF22C55E),
      gradient: [Color(0xFF1EB957), Colors.white],
      action:   _DashboardAction.scanQR,
    ),
    _DashboardCard(
      title:    'Attendance History',
      subtitle: 'View past records',
      icon:     Icons.history_rounded,
      color:    Color(0xFF0FA797),
      gradient: [Color(0xFF14B8A6), Colors.white],
      action:   _DashboardAction.attendanceHistory,
    ),
    _DashboardCard(
      title:    'Profile',
      subtitle: 'Manage your account',
      icon:     Icons.person_rounded,
      color:    Color(0xFF999EA5),
      gradient: [Color(0xFF9CA3AF), Colors.white],
      action:   _DashboardAction.profile,
    ),
    _DashboardCard(
      title:    'Announcements',
      subtitle: 'View class updates',
      icon:     Icons.campaign_rounded,
      color:    Color(0xFFF566C5),
      gradient: [Color(0xFFE597F3), Colors.white],
      action:   _DashboardAction.announcements,
    ),
  ];

  // ─── Lifecycle ────────────────────────────────────────────────────────────────
  // Note: didChangeDependencies is intentionally omitted.
  // Calling _loadUserData() there triggers a reload on every route pop/push
  // which is both wasteful and causes a visible loading flash. forceRefresh:true
  // on individual Navigator.push().then() calls is the correct pattern.

  @override
  void initState() {
    super.initState();
    _loadUserData();
  }

  // ─── Data loading ─────────────────────────────────────────────────────────────

  Future<void> _loadUserData({bool forceRefresh = false}) async {
    final cacheValid = _cachedUserData != null &&
        _lastFetch != null &&
        DateTime.now().difference(_lastFetch!) < const Duration(minutes: 5);

    if (!forceRefresh && cacheValid) {
      if (!mounted) return;
      setState(() {
        _studentName    = _cachedUserData!['first_name']      ?? 'Student';
        _username       = _cachedUserData!['username']        ?? '';
        _totalClasses   = _cachedUserData!['total_classes']   ?? 0;
        _attendanceRate = _cachedUserData!['attendance_rate'] ?? 0.0;
        _isLoading      = false;
      });
      return;
    }

    if (!mounted) return;
    setState(() => _isLoading = true);

    try {
      // Parallelise all three network calls.
      final results = await Future.wait([
        _authService.getCurrentUser(),
        _profileService.getStudentClasses(),
        _profileService.getStudentStats(),
      ]);

      if (!mounted) return;

      final userData = results[0] is Map<String, dynamic>
          ? results[0] as Map<String, dynamic>
          : null;
      final classes = results[1] is List ? results[1] as List : <dynamic>[];
      final stats   = results[2] is Map<String, dynamic>
          ? results[2] as Map<String, dynamic>
          : <String, dynamic>{};

      final rate = double.tryParse(
        stats['attendance_rate']?.toString() ?? '0.0',
      ) ?? 0.0;

      setState(() {
        _cachedUserData = {
          ...?userData,
          'total_classes':   classes.length,
          'attendance_rate': rate,
        };
        _lastFetch      = DateTime.now();
        _studentName    = userData?['first_name'] ?? userData?['username'] ?? 'Student';
        _username       = userData?['username']   ?? '';
        _totalClasses   = classes.length;
        _attendanceRate = rate;
        _isLoading      = false;
      });

      debugPrint(
        'Dashboard Stats: $_totalClasses classes, '
        '${_attendanceRate.toStringAsFixed(1)}% attendance',
      );
    } catch (e, stackTrace) {
      if (!mounted) return;
      debugPrint('_loadUserData error: $e\n$stackTrace');
      setState(() {
        _studentName    = 'Student';
        _username       = '';
        _totalClasses   = 0;
        _attendanceRate = 0.0;
        _isLoading      = false;
      });
      _showSnackBar('Failed to load data. Please try again.', Colors.red);
    }
  }

  // ─── Navigation ───────────────────────────────────────────────────────────────

  Future<void> _handleCardAction(_DashboardAction action) async {
    switch (action) {
      case _DashboardAction.myClasses:
        await Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const StudentMyClassesScreen()),
        );
        _loadUserData(forceRefresh: true);

      case _DashboardAction.scanQR:
        await Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const QRScannerScreen()),
        );
        _loadUserData(forceRefresh: true);

      case _DashboardAction.attendanceHistory:
        await Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const AttendanceHistoryScreen()),
        );

      case _DashboardAction.profile:
        await Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const StudentProfileScreen()),
        );
        _loadUserData(forceRefresh: true);

      case _DashboardAction.announcements:
        _showSnackBar('Announcements – Coming Soon!', Colors.blue);

      case _DashboardAction.logout:
        await _logout();
    }
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────────

  void _showSnackBar(String message, Color color) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content:         Text(message),
        backgroundColor: color,
        duration:        const Duration(seconds: 3),
      ),
    );
  }

  Future<void> _logout() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title:   const Text('Logout'),
        content: const Text('Are you sure you want to logout?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Logout', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );

    if (confirm == true) {
      // Clear cache before navigating away (no setState needed — widget is leaving).
      _cachedUserData = null;
      _lastFetch      = null;
      await _authService.logout();
      if (mounted) Navigator.pushReplacementNamed(context, '/login');
    }
  }

  // ─── Build ────────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final screenW   = MediaQuery.of(context).size.width;
    final isMobile  = screenW < 600;
    final isDesktop = screenW >= 1024;

    if (isDesktop) return _buildDesktopLayout();

    final crossAxisCount = isMobile ? 1 : 2;

    return Scaffold(
      backgroundColor: _AppColors.background,
      appBar:          _buildTopBar(isMobile),
      drawer:          _buildMobileDrawer(),
      body: Stack(
        children: [
          SafeArea(
            child: SingleChildScrollView(
              physics: const BouncingScrollPhysics(),
              child: Padding(
                padding: EdgeInsets.all(isMobile ? 16 : 24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildStatsSection(isMobile),
                    const SizedBox(height: 24),
                    _buildSectionHeader(),
                    const SizedBox(height: 16),
                    _buildDashboardGrid(crossAxisCount, isMobile),
                  ],
                ),
              ),
            ),
          ),
          if (_isLoading) _buildLoadingOverlay(),
        ],
      ),
    );
  }

  Widget _buildDesktopLayout() {
    return Scaffold(
      backgroundColor: _AppColors.background,
      body: Stack(
        children: [
          SafeArea(
            child: Row(
              children: [
                _buildDesktopSidebar(),
                Expanded(
                  child: SingleChildScrollView(
                    physics: const BouncingScrollPhysics(),
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(40, 20, 40, 40),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          _buildDesktopHeader(),
                          const SizedBox(height: 32),
                          _buildStatsSection(false),
                          const SizedBox(height: 48),
                          _buildSectionHeader(),
                          const SizedBox(height: 24),
                          _buildDashboardGrid(3, false),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
          if (_isLoading) _buildLoadingOverlay(),
        ],
      ),
    );
  }

  // ─── Shared widgets ───────────────────────────────────────────────────────────

  Widget _buildLoadingOverlay() => Container(
        color: Colors.black26,
        child: const Center(
          child: Card(
            child: Padding(
              padding: EdgeInsets.all(24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  CircularProgressIndicator(),
                  SizedBox(height: 16),
                  Text('Loading...'),
                ],
              ),
            ),
          ),
        ),
      );

  // Single _buildStatsSection replaces the old duplicate _buildStatsRow pattern.
  Widget _buildStatsSection(bool isMobile) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final classesCard = _buildStatCard(
          value:          _totalClasses.toString(),
          label:          'Enrolled Classes',
          iconColor:      const Color(0xFF14DCCA),
          gradientColors: [const Color(0xFF65E8E1), Colors.white],
          borderColor:    _AppColors.teal,
        );
        final attendanceCard = _buildStatCard(
          value:          '${_attendanceRate.toStringAsFixed(1)}%',
          label:          'Attendance Rate',
          iconColor:      const Color(0xFF86EFAC),
          gradientColors: [const Color(0xFFBBF7D0), Colors.white],
          borderColor:    const Color(0xFF4ADE80),
        );

        if (constraints.maxWidth < 700) {
          return Column(children: [
            classesCard,
            const SizedBox(height: 16),
            attendanceCard,
          ]);
        }
        return Row(children: [
          Expanded(child: classesCard),
          const SizedBox(width: 16),
          Expanded(child: attendanceCard),
        ]);
      },
    );
  }

  Widget _buildStatCard({
    required String      value,
    required String      label,
    required Color       iconColor,
    required List<Color> gradientColors,
    required Color       borderColor,
  }) {
    return Container(
      height:  108,
      padding: const EdgeInsets.symmetric(horizontal: 24),
      decoration: ShapeDecoration(
        gradient: LinearGradient(
          begin:  const Alignment(-0.13, 0),
          end:    const Alignment(1.12, 1),
          colors: gradientColors,
        ),
        shape: RoundedRectangleBorder(
          side:         BorderSide(width: 2, color: borderColor),
          borderRadius: BorderRadius.circular(23),
        ),
      ),
      child: Row(
        children: [
          Container(
            width:   68,
            height:  68,
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(color: iconColor, shape: BoxShape.circle),
            child: const Icon(Icons.bar_chart_rounded, color: Colors.white, size: 28),
          ),
          const SizedBox(width: 38),
          Column(
            mainAxisAlignment:  MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                value,
                style: const TextStyle(
                  color:      Colors.black,
                  fontSize:   40,
                  fontFamily: 'Inter',
                  fontWeight: FontWeight.w700,
                ),
              ),
              Text(
                label,
                style: const TextStyle(
                  color:      _AppColors.textMuted,
                  fontSize:   17,
                  fontFamily: 'Inter',
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSectionHeader() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Overview',
          style: TextStyle(
            fontSize:   26,
            fontFamily: 'Inter',
            fontWeight: FontWeight.w700,
            color:      Colors.black,
          ),
        ),
        const SizedBox(height: 18),
        Row(
          children: [
            Container(
              width:  12,
              height: 43,
              decoration: ShapeDecoration(
                color: _AppColors.tealLight,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(6),
                ),
              ),
            ),
            const SizedBox(width: 12),
            const Text(
              'Quick Actions',
              style: TextStyle(
                fontSize:   33,
                fontFamily: 'Inter',
                fontWeight: FontWeight.w700,
                color:      Colors.black,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildDashboardGrid(int crossAxisCount, bool isMobile) {
    final childAspectRatio =
        crossAxisCount == 1 ? 1.5 : (crossAxisCount == 2 ? 1.3 : 1.6);

    return GridView.builder(
      itemCount:  _cards.length,
      physics:    const NeverScrollableScrollPhysics(),
      shrinkWrap: true,
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount:   crossAxisCount,
        mainAxisSpacing:  42,
        crossAxisSpacing: 55,
        childAspectRatio: childAspectRatio,
      ),
      itemBuilder: (context, idx) => _buildActionCard(_cards[idx], isMobile),
    );
  }

  Widget _buildActionCard(_DashboardCard card, bool isMobile) {
    return InkWell(
      onTap:        () => _handleCardAction(card.action),
      borderRadius: BorderRadius.circular(43),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 24),
        decoration: ShapeDecoration(
          gradient: LinearGradient(
            begin:  const Alignment(-0.05, -0.07),
            end:    const Alignment(1.18, 1.28),
            colors: card.gradient,
          ),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(43),
            side: const BorderSide(color: Color(0xFFE5E7EB), width: 1.5),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisAlignment:  MainAxisAlignment.center,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                Container(
                  width:   68,
                  height:  68,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.25),
                    border: Border.all(
                      color: card.color.withValues(alpha: 0.70),
                      width: 1.5,
                    ),
                    shape: BoxShape.circle,
                  ),
                  child: Icon(card.icon, color: card.color, size: 30),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        card.title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          color:      Colors.black,
                          fontSize:   20,
                          fontFamily: 'Inter',
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        card.subtitle,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          color:      Colors.black,
                          fontSize:   14,
                          fontFamily: 'Inter',
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  // ─── AppBar ───────────────────────────────────────────────────────────────────

  PreferredSizeWidget _buildTopBar(bool isMobile) {
    return AppBar(
      backgroundColor: Colors.transparent,
      elevation:       0,
      title: Row(
        children: [
          Container(
            decoration: const BoxDecoration(
              gradient: LinearGradient(
                colors: [_AppColors.tealDark, _AppColors.teal],
              ),
              shape: BoxShape.circle,
            ),
            padding: const EdgeInsets.all(8),
            child: const Icon(Icons.school_rounded, color: Colors.white, size: 20),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              'Welcome, $_username',
              style: TextStyle(
                fontSize:   isMobile ? 16 : 18,
                fontWeight: FontWeight.bold,
                color:      _AppColors.textPrimary,
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
      actions: [
        IconButton(
          icon:      const Icon(Icons.refresh, color: _AppColors.textPrimary),
          onPressed: () => _loadUserData(forceRefresh: true),
        ),
        IconButton(
          icon:      const Icon(Icons.logout, color: _AppColors.textPrimary),
          onPressed: _logout,
        ),
      ],
    );
  }

  // ─── Desktop ──────────────────────────────────────────────────────────────────

  Widget _buildDesktopHeader() {
    return Row(
      children: [
        Container(
          width:  76,
          height: 76,
          decoration: BoxDecoration(
            gradient: const LinearGradient(
              colors: [_AppColors.tealDark, _AppColors.teal],
              begin:  Alignment.topCenter,
              end:    Alignment.bottomCenter,
            ),
            borderRadius: BorderRadius.circular(63.5),
          ),
          child: const Icon(Icons.school_rounded, color: Colors.white, size: 38),
        ),
        const SizedBox(width: 20),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Welcome, $_username',
                style: const TextStyle(
                  color:      _AppColors.tealDark,
                  fontSize:   38,
                  fontFamily: 'Inter',
                  fontWeight: FontWeight.w700,
                ),
                overflow: TextOverflow.ellipsis,
              ),
              const SizedBox(height: 4),
              Text(
                '@$_username',
                style: const TextStyle(
                  fontSize:   16,
                  color:      _AppColors.textMuted,
                  fontFamily: 'Inter',
                ),
              ),
            ],
          ),
        ),
        IconButton(
          icon:      const Icon(Icons.refresh, color: _AppColors.textPrimary),
          onPressed: () => _loadUserData(forceRefresh: true),
        ),
        IconButton(
          icon:      const Icon(Icons.logout, color: _AppColors.textPrimary),
          onPressed: _logout,
        ),
      ],
    );
  }

  Widget _buildDesktopSidebar() {
    return AnimatedContainer(
      duration: const Duration(milliseconds: 300),
      width: _isSidebarExpanded ? 220 : 72,
      decoration: const BoxDecoration(color: _AppColors.darkBg),
      child: Column(
        children: [
          const SizedBox(height: 24),
          Container(
            width:  48,
            height: 48,
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [_AppColors.tealDark, _AppColors.teal],
              ),
              borderRadius: BorderRadius.circular(24),
            ),
            child: const Icon(Icons.school_rounded, color: Colors.white, size: 26),
          ),
          IconButton(
            icon: Icon(
              _isSidebarExpanded ? Icons.chevron_left : Icons.chevron_right,
              color: Colors.white70,
            ),
            onPressed: () =>
                setState(() => _isSidebarExpanded = !_isSidebarExpanded),
          ),
          const SizedBox(height: 8),
          Expanded(
            child: ListView(
              padding: EdgeInsets.zero,
              children: _cards
                  .map((c) => _buildSidebarItem(c.icon, c.title, c.action))
                  .toList(),
            ),
          ),
          _buildSidebarItem(Icons.logout, 'Logout', _DashboardAction.logout),
          const SizedBox(height: 20),
        ],
      ),
    );
  }

  Widget _buildSidebarItem(
    IconData        icon,
    String          label,
    _DashboardAction action, {
    bool isMobile = false,
  }) {
    final showLabel = _isSidebarExpanded || isMobile;
    return Tooltip(
      message: showLabel ? '' : label,
      child: ListTile(
        leading: Icon(icon, color: Colors.white70, size: isMobile ? 24 : 20),
        title: showLabel
            ? Text(label, style: const TextStyle(color: Colors.white, fontSize: 14))
            : null,
        onTap: () => _handleCardAction(action),
      ),
    );
  }

  Widget _buildMobileDrawer() {
    return Drawer(
      child: Container(
        decoration: const BoxDecoration(color: _AppColors.darkBg),
        child: ListView(
          children: [
            DrawerHeader(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  colors: [_AppColors.tealDark, _AppColors.teal],
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment:  MainAxisAlignment.end,
                children: [
                  const CircleAvatar(
                    radius:          30,
                    backgroundColor: Colors.white,
                    child: Icon(
                      Icons.person_rounded,
                      size:  35,
                      color: _AppColors.tealDark,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Text(
                    _studentName,
                    style: const TextStyle(
                      color:      Colors.white,
                      fontSize:   18,
                      fontWeight: FontWeight.bold,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                  Text(
                    '@$_username',
                    style: const TextStyle(color: Colors.white70, fontSize: 14),
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            ..._cards.map(
              (c) => _buildSidebarItem(c.icon, c.title, c.action, isMobile: true),
            ),
            const Divider(color: Colors.white24),
            _buildSidebarItem(
              Icons.logout,
              'Logout',
              _DashboardAction.logout,
              isMobile: true,
            ),
          ],
        ),
      ),
    );
  }
}