import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../services/attendance_service.dart';

// ─── App colour constants (mirrors StudentDashboardPage._AppColors exactly) ───
abstract class _AppColors {
  static const tealDark    = Color(0xFF007C91);
  static const teal        = Color(0xFF0097A7);
  static const tealLight   = Color(0xFF0288A3);
  static const background  = Color(0xFFF7FAFC);
  static const darkBg      = Color(0xFF1E1E2D);
  static const textPrimary = Color(0xFF1F2937);
  static const textMuted   = Color(0xFF6B7280);
}

class AttendanceHistoryScreen extends StatefulWidget {
  const AttendanceHistoryScreen({super.key});

  @override
  State<AttendanceHistoryScreen> createState() => _AttendanceHistoryScreenState();
}

class _AttendanceHistoryScreenState extends State<AttendanceHistoryScreen> {
  final AttendanceService _attendanceService = AttendanceService();

  List<Map<String, dynamic>> attendanceRecords = [];
  Map<String, List<Map<String, dynamic>>> groupedRecords = {};
  bool isLoading = true;
  String? errorMessage;

  String selectedFilter = 'All';      // 'All', 'Present', 'Absent'
  String selectedView   = 'Timeline'; // 'Timeline', 'ByClass'

  // ─── Lifecycle ──────────────────────────────────────────────────────────────

  @override
  void initState() {
    super.initState();
    _loadAttendanceHistory();
  }

  // ─── Data loading ────────────────────────────────────────────────────────────

  Future<void> _loadAttendanceHistory() async {
    setState(() {
      isLoading     = true;
      errorMessage  = null;
    });

    try {
      final records = await _attendanceService.getMyAttendance();
      if (mounted) {
        setState(() {
          attendanceRecords = records;
          _groupRecordsByClass();
          isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          errorMessage = 'Failed to load attendance: $e';
          isLoading    = false;
        });
      }
    }
  }

  void _groupRecordsByClass() {
    groupedRecords.clear();
    for (final record in attendanceRecords) {
      final key = '${record['class_code']} - ${record['class_name']}';
      (groupedRecords[key] ??= []).add(record);
    }
  }

  // ─── Derived state ───────────────────────────────────────────────────────────

  List<Map<String, dynamic>> get filteredRecords {
    if (selectedFilter == 'All') return attendanceRecords;
    return attendanceRecords
        .where((r) =>
            r['status'].toString().toLowerCase() ==
            selectedFilter.toLowerCase())
        .toList();
  }

  Map<String, dynamic> get statistics {
    final total   = attendanceRecords.length;
    final present = attendanceRecords.where((r) => r['status'] == 'present').length;
    final absent  = total - present;
    final rate    = total > 0 ? present / total * 100 : 0.0;
    return {'total': total, 'present': present, 'absent': absent, 'rate': rate};
  }

  // ─── Build ───────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final screenW  = MediaQuery.of(context).size.width;
    final isMobile = screenW < 600;

    return Scaffold(
      backgroundColor: _AppColors.background,
      appBar: _buildTopBar(isMobile),
      body: Stack(
        children: [
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (!isLoading && attendanceRecords.isNotEmpty) ...[
                Padding(
                  padding: EdgeInsets.fromLTRB(
                    isMobile ? 16 : 24, 20, isMobile ? 16 : 24, 0,
                  ),
                  child: _buildStatsSection(isMobile),
                ),
                Padding(
                  padding: EdgeInsets.fromLTRB(
                    isMobile ? 16 : 24, 24, isMobile ? 16 : 24, 0,
                  ),
                  child: _buildSectionHeader(),
                ),
                _buildFilterChips(isMobile),
              ],
              Expanded(
                child: RefreshIndicator(
                  onRefresh: _loadAttendanceHistory,
                  child: _buildBody(isMobile),
                ),
              ),
            ],
          ),
          if (isLoading) _buildLoadingOverlay(),
        ],
      ),
    );
  }

  // ─── AppBar (mirrors StudentDashboardPage._buildTopBar) ──────────────────────

  PreferredSizeWidget _buildTopBar(bool isMobile) {
    return AppBar(
      backgroundColor: Colors.transparent,
      elevation:       0,
      leading: IconButton(
        icon:      const Icon(Icons.arrow_back_rounded, color: _AppColors.textPrimary),
        onPressed: () => Navigator.pop(context),
      ),
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
            child: const Icon(Icons.history_rounded, color: Colors.white, size: 20),
          ),
          const SizedBox(width: 12),
          Text(
            'Attendance History',
            style: TextStyle(
              fontSize:   isMobile ? 16 : 18,
              fontWeight: FontWeight.bold,
              fontFamily: 'Inter',
              color:      _AppColors.textPrimary,
            ),
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
      actions: [
        // View toggle — styled with dashboard teal
        Container(
          margin: const EdgeInsets.symmetric(vertical: 10),
          decoration: BoxDecoration(
            color:        _AppColors.teal.withValues(alpha: 0.10),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildViewToggleButton(Icons.view_timeline_rounded, 'Timeline', isMobile),
              _buildViewToggleButton(Icons.view_module_rounded,   'ByClass',  isMobile),
            ],
          ),
        ),
        const SizedBox(width: 4),
        IconButton(
          icon:      const Icon(Icons.refresh, color: _AppColors.textPrimary),
          onPressed: _loadAttendanceHistory,
        ),
      ],
    );
  }

  Widget _buildViewToggleButton(IconData icon, String view, bool isMobile) {
    final isSelected = selectedView == view;
    return InkWell(
      onTap:        () => setState(() => selectedView = view),
      borderRadius: BorderRadius.circular(10),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: EdgeInsets.symmetric(horizontal: isMobile ? 8 : 12, vertical: 8),
        decoration: BoxDecoration(
          color:        isSelected ? _AppColors.teal : Colors.transparent,
          borderRadius: BorderRadius.circular(10),
        ),
        child: Icon(
          icon,
          color: isSelected ? Colors.white : _AppColors.teal,
          size:  isMobile ? 18 : 20,
        ),
      ),
    );
  }

  // ─── Loading overlay (mirrors StudentDashboardPage) ───────────────────────────

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

  // ─── Stats section (adapted from StudentDashboardPage._buildStatsSection) ────
  //
  // Primary cards: "Sessions Present" + "Attendance Rate" (same 2-card layout).
  // Supplemental row: Total / Absent as smaller accent pills below.

  Widget _buildStatsSection(bool isMobile) {
    final stats = statistics;

    return LayoutBuilder(
      builder: (context, constraints) {
        final presentCard = _buildStatCard(
          value:          '${stats['present']}',
          label:          'Sessions Present',
          iconColor:      const Color(0xFF86EFAC),
          gradientColors: [const Color(0xFFBBF7D0), Colors.white],
          borderColor:    const Color(0xFF4ADE80),
        );
        final rateCard = _buildStatCard(
          value:          '${(stats['rate'] as double).toStringAsFixed(1)}%',
          label:          'Attendance Rate',
          iconColor:      const Color(0xFF14DCCA),
          gradientColors: [const Color(0xFF65E8E1), Colors.white],
          borderColor:    _AppColors.teal,
        );

        final twoCards = constraints.maxWidth < 700
            ? Column(children: [
                presentCard,
                const SizedBox(height: 16),
                rateCard,
              ])
            : Row(children: [
                Expanded(child: presentCard),
                const SizedBox(width: 16),
                Expanded(child: rateCard),
              ]);

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            twoCards,
            const SizedBox(height: 12),
            Row(children: [
              Expanded(
                child: _buildMiniStatPill(
                  label: 'Total Sessions',
                  value: '${stats['total']}',
                  color: _AppColors.teal,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _buildMiniStatPill(
                  label: 'Absent',
                  value: '${stats['absent']}',
                  color: const Color(0xFFEF4444),
                ),
              ),
            ]),
          ],
        );
      },
    );
  }

  // Directly mirrors StudentDashboardPage._buildStatCard
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
          const SizedBox(width: 24),
          Expanded(
            child: Column(
              mainAxisAlignment:  MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  value,
                  style: const TextStyle(
                    color:      Colors.black,
                    fontSize:   36,
                    fontFamily: 'Inter',
                    fontWeight: FontWeight.w700,
                  ),
                ),
                Text(
                  label,
                  style: const TextStyle(
                    color:      _AppColors.textMuted,
                    fontSize:   14,
                    fontFamily: 'Inter',
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMiniStatPill({
    required String label,
    required String value,
    required Color  color,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      decoration: ShapeDecoration(
        gradient: LinearGradient(
          colors: [color.withValues(alpha: 0.08), Colors.white],
        ),
        shape: RoundedRectangleBorder(
          side:         BorderSide(width: 1.5, color: color.withValues(alpha: 0.30)),
          borderRadius: BorderRadius.circular(14),
        ),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            value,
            style: TextStyle(
              color:      color,
              fontSize:   20,
              fontFamily: 'Inter',
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(width: 8),
          Flexible(
            child: Text(
              label,
              style: const TextStyle(
                color:      _AppColors.textMuted,
                fontSize:   13,
                fontFamily: 'Inter',
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  // ─── Section header (mirrors StudentDashboardPage._buildSectionHeader) ────────

  Widget _buildSectionHeader() {
    return Row(
      children: [
        Container(
          width:  10,
          height: 36,
          decoration: ShapeDecoration(
            color: _AppColors.tealLight,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(6),
            ),
          ),
        ),
        const SizedBox(width: 12),
        const Text(
          'Records',
          style: TextStyle(
            fontSize:   26,
            fontFamily: 'Inter',
            fontWeight: FontWeight.w700,
            color:      Colors.black,
          ),
        ),
      ],
    );
  }

  // ─── Filter chips (restyled to dashboard teal theme) ─────────────────────────

  Widget _buildFilterChips(bool isMobile) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 8),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          children: [
            _buildFilterChip('All',     isMobile),
            const SizedBox(width: 10),
            _buildFilterChip('Present', isMobile),
            const SizedBox(width: 10),
            _buildFilterChip('Absent',  isMobile),
          ],
        ),
      ),
    );
  }

  Widget _buildFilterChip(String label, bool isMobile) {
    final isSelected = selectedFilter == label;
    return GestureDetector(
      onTap: () => setState(() => selectedFilter = label),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: EdgeInsets.symmetric(
          horizontal: isMobile ? 18 : 22,
          vertical: 9,
        ),
        decoration: ShapeDecoration(
          color: isSelected ? _AppColors.teal : Colors.white,
          shape: RoundedRectangleBorder(
            side: BorderSide(
              color: isSelected ? _AppColors.teal : const Color(0xFFE5E7EB),
              width: 1.5,
            ),
            borderRadius: BorderRadius.circular(20),
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            color:      isSelected ? Colors.white : _AppColors.textMuted,
            fontFamily: 'Inter',
            fontWeight: FontWeight.w600,
            fontSize:   isMobile ? 13 : 14,
          ),
        ),
      ),
    );
  }

  // ─── Body router ─────────────────────────────────────────────────────────────

  Widget _buildBody(bool isMobile) {
    if (isLoading) return const SizedBox.shrink(); // covered by loading overlay

    if (errorMessage != null) {
      return Center(child: _buildErrorState(isMobile));
    }

    if (attendanceRecords.isEmpty) {
      return Center(child: _buildEmptyState(isMobile));
    }

    return selectedView == 'Timeline'
        ? _buildTimelineView(isMobile)
        : _buildClassGroupedView(isMobile);
  }

  // ─── Timeline view ───────────────────────────────────────────────────────────

  Widget _buildTimelineView(bool isMobile) {
    final records = filteredRecords;

    if (records.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Text(
            'No $selectedFilter records found',
            style: const TextStyle(
              color:      _AppColors.textMuted,
              fontSize:   16,
              fontFamily: 'Inter',
            ),
          ),
        ),
      );
    }

    return ListView.builder(
      padding:   EdgeInsets.all(isMobile ? 16 : 24),
      itemCount: records.length,
      itemBuilder: (context, index) => TweenAnimationBuilder<double>(
        tween:    Tween(begin: 0.0, end: 1.0),
        duration: Duration(milliseconds: 400 + (index * 80)),
        curve:    Curves.easeOutCubic,
        builder: (context, value, child) => Transform.translate(
          offset: Offset(0, 30 * (1 - value)),
          child:  Opacity(opacity: value, child: child),
        ),
        child: _buildAttendanceCard(records[index], isMobile),
      ),
    );
  }

  // ─── By-class grouped view ───────────────────────────────────────────────────

  Widget _buildClassGroupedView(bool isMobile) {
    return ListView.builder(
      padding:   EdgeInsets.all(isMobile ? 16 : 24),
      itemCount: groupedRecords.length,
      itemBuilder: (context, index) {
        final className    = groupedRecords.keys.elementAt(index);
        final records      = groupedRecords[className]!;
        final presentCount = records.where((r) => r['status'] == 'present').length;
        final rate         = presentCount / records.length * 100;

        return TweenAnimationBuilder<double>(
          tween:    Tween(begin: 0.0, end: 1.0),
          duration: Duration(milliseconds: 400 + (index * 80)),
          curve:    Curves.easeOutCubic,
          builder: (context, value, child) => Transform.translate(
            offset: Offset(0, 30 * (1 - value)),
            child:  Opacity(opacity: value, child: child),
          ),
          child: Container(
            margin: const EdgeInsets.only(bottom: 16),
            decoration: ShapeDecoration(
              gradient: const LinearGradient(
                begin:  Alignment(-0.05, -0.07),
                end:    Alignment(1.18, 1.28),
                colors: [Color(0xFFE0F7FA), Colors.white],
              ),
              shape: RoundedRectangleBorder(
                side:         const BorderSide(color: Color(0xFFE5E7EB), width: 1.5),
                borderRadius: BorderRadius.circular(23),
              ),
            ),
            child: Theme(
              data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
              child: ExpansionTile(
                tilePadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 8),
                leading: Container(
                  width:   52,
                  height:  52,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [_AppColors.tealDark, _AppColors.teal],
                    ),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(Icons.school_rounded, color: Colors.white, size: 24),
                ),
                title: Text(
                  className,
                  style: const TextStyle(
                    fontFamily: 'Inter',
                    fontWeight: FontWeight.w700,
                    fontSize:   16,
                    color:      _AppColors.textPrimary,
                  ),
                ),
                subtitle: Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Row(
                    children: [
                      Icon(Icons.event_note_rounded, size: 14, color: _AppColors.textMuted),
                      const SizedBox(width: 4),
                      Text(
                        '${records.length} sessions',
                        style: const TextStyle(
                          fontSize:   12,
                          fontFamily: 'Inter',
                          color:      _AppColors.textMuted,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Icon(
                        rate >= 75
                            ? Icons.trending_up_rounded
                            : Icons.trending_down_rounded,
                        size:  14,
                        color: rate >= 75
                            ? const Color(0xFF22C55E)
                            : Colors.orange,
                      ),
                      const SizedBox(width: 4),
                      Text(
                        '${rate.toStringAsFixed(1)}%',
                        style: TextStyle(
                          fontSize:   12,
                          fontFamily: 'Inter',
                          color:      rate >= 75
                              ? const Color(0xFF22C55E)
                              : Colors.orange,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
                children: records
                    .map((r) => Padding(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 16, vertical: 4),
                          child: _buildCompactAttendanceCard(r, isMobile),
                        ))
                    .toList(),
              ),
            ),
          ),
        );
      },
    );
  }

  // ─── Attendance card (action-card pattern from dashboard) ────────────────────

  Widget _buildAttendanceCard(Map<String, dynamic> record, bool isMobile) {
    final status      = record['status'] ?? 'unknown';
    final isPresent   = status == 'present';
    final statusColor = isPresent
        ? const Color(0xFF22C55E)
        : const Color(0xFFEF4444);
    final gradient = isPresent
        ? [const Color(0xFFDCFCE7), Colors.white]
        : [const Color(0xFFFEE2E2), Colors.white];
    final markedAt = DateTime.parse(record['marked_at']).toLocal();

    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
      decoration: ShapeDecoration(
        gradient: LinearGradient(
          begin:  const Alignment(-0.05, -0.07),
          end:    const Alignment(1.18, 1.28),
          colors: gradient,
        ),
        shape: RoundedRectangleBorder(
          side: BorderSide(
            color: statusColor.withValues(alpha: 0.30),
            width: 1.5,
          ),
          borderRadius: BorderRadius.circular(23),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Header row ──────────────────────────────────────────────────────
          Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              // Icon circle — mirrors dashboard card icon circle exactly
              Container(
                width:   60,
                height:  60,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color:  Colors.white.withValues(alpha: 0.25),
                  border: Border.all(
                    color: statusColor.withValues(alpha: 0.70),
                    width: 1.5,
                  ),
                  shape: BoxShape.circle,
                ),
                child: Icon(
                  isPresent
                      ? Icons.check_circle_rounded
                      : Icons.cancel_rounded,
                  color: statusColor,
                  size:  28,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      record['class_code'] ?? 'N/A',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize:   isMobile ? 16 : 18,
                        fontFamily: 'Inter',
                        fontWeight: FontWeight.w700,
                        color:      _AppColors.textPrimary,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      record['class_name'] ?? 'Unknown Class',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                        fontSize:   13,
                        fontFamily: 'Inter',
                        color:      _AppColors.textMuted,
                      ),
                    ),
                  ],
                ),
              ),
              // Status badge
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
                decoration: ShapeDecoration(
                  color: statusColor,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(20),
                  ),
                ),
                child: Text(
                  status.toUpperCase(),
                  style: const TextStyle(
                    color:         Colors.white,
                    fontSize:      11,
                    fontFamily:    'Inter',
                    fontWeight:    FontWeight.w700,
                    letterSpacing: 0.8,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          // ── Date / time info row ─────────────────────────────────────────────
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            decoration: ShapeDecoration(
              gradient: LinearGradient(
                colors: [statusColor.withValues(alpha: 0.06), Colors.white],
              ),
              shape: RoundedRectangleBorder(
                side:         const BorderSide(color: Color(0xFFE5E7EB), width: 1),
                borderRadius: BorderRadius.circular(14),
              ),
            ),
            child: Row(
              children: [
                Expanded(
                  child: _buildInfoCell(
                    icon:  Icons.calendar_today_rounded,
                    label: 'Date',
                    value: DateFormat('dd/MM/yy').format(markedAt),
                  ),
                ),
                Container(
                  width:  1,
                  height: 36,
                  margin: const EdgeInsets.symmetric(horizontal: 12),
                  color:  const Color(0xFFE5E7EB),
                ),
                Expanded(
                  child: _buildInfoCell(
                    icon:  Icons.access_time_rounded,
                    label: 'Time',
                    value: DateFormat('hh:mm a').format(markedAt),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoCell({
    required IconData icon,
    required String   label,
    required String   value,
  }) {
    return Row(
      children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color:        Colors.white,
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(icon, size: 16, color: _AppColors.textMuted),
        ),
        const SizedBox(width: 10),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: const TextStyle(
                fontSize:   11,
                fontFamily: 'Inter',
                color:      _AppColors.textMuted,
              ),
            ),
            const SizedBox(height: 3),
            Text(
              value,
              style: const TextStyle(
                fontSize:   14,
                fontFamily: 'Inter',
                fontWeight: FontWeight.w700,
                color:      _AppColors.textPrimary,
              ),
            ),
          ],
        ),
      ],
    );
  }

  // ─── Compact card (inside ByClass expansion) ──────────────────────────────────

  Widget _buildCompactAttendanceCard(Map<String, dynamic> record, bool isMobile) {
    final status      = record['status'] ?? 'unknown';
    final isPresent   = status == 'present';
    final statusColor = isPresent
        ? const Color(0xFF22C55E)
        : const Color(0xFFEF4444);
    final markedAt = DateTime.parse(record['marked_at']).toLocal();

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: ShapeDecoration(
        gradient: LinearGradient(
          colors: [statusColor.withValues(alpha: 0.06), Colors.white],
        ),
        shape: RoundedRectangleBorder(
          side: BorderSide(
            color: statusColor.withValues(alpha: 0.20),
            width: 1.5,
          ),
          borderRadius: BorderRadius.circular(14),
        ),
      ),
      child: Row(
        children: [
          Icon(
            isPresent ? Icons.check_circle_rounded : Icons.cancel_rounded,
            color: statusColor,
            size:  20,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              DateFormat('MMM dd, yyyy • hh:mm a').format(markedAt),
              style: const TextStyle(
                fontSize:   13,
                fontFamily: 'Inter',
                fontWeight: FontWeight.w600,
                color:      _AppColors.textPrimary,
              ),
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: ShapeDecoration(
              color: statusColor,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: Text(
              status.toUpperCase(),
              style: const TextStyle(
                color:      Colors.white,
                fontSize:   10,
                fontFamily: 'Inter',
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ─── Empty state (adapted for light background) ───────────────────────────────

  Widget _buildEmptyState(bool isMobile) {
    return Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          TweenAnimationBuilder<double>(
            tween:    Tween(begin: 0.0, end: 1.0),
            duration: const Duration(milliseconds: 800),
            curve:    Curves.easeOutCubic,
            builder: (context, value, child) => Transform.scale(
              scale: value,
              child: Opacity(opacity: value, child: child),
            ),
            child: Container(
              padding: const EdgeInsets.all(28),
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [Color(0xFF65E8E1), _AppColors.teal],
                  begin:  Alignment.topLeft,
                  end:    Alignment.bottomRight,
                ),
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color:      _AppColors.teal.withValues(alpha: 0.30),
                    blurRadius: 24,
                    offset:     const Offset(0, 10),
                  ),
                ],
              ),
              child: Icon(
                Icons.history_rounded,
                size:  isMobile ? 60 : 76,
                color: Colors.white,
              ),
            ),
          ),
          const SizedBox(height: 28),
          const Text(
            'No Attendance Records',
            style: TextStyle(
              color:      _AppColors.textPrimary,
              fontSize:   22,
              fontFamily: 'Inter',
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 12),
          const Text(
            'Start scanning QR codes to track\nyour attendance history',
            textAlign: TextAlign.center,
            style: TextStyle(
              color:      _AppColors.textMuted,
              fontSize:   15,
              fontFamily: 'Inter',
            ),
          ),
          const SizedBox(height: 32),
          ElevatedButton.icon(
            onPressed: () => Navigator.pop(context),
            icon:  const Icon(Icons.qr_code_scanner_rounded, size: 22),
            label: const Text(
              'Scan QR Code',
              style: TextStyle(
                fontSize:   16,
                fontFamily: 'Inter',
                fontWeight: FontWeight.w600,
              ),
            ),
            style: ElevatedButton.styleFrom(
              backgroundColor: _AppColors.teal,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(14),
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ─── Error state (adapted for light background) ───────────────────────────────

  Widget _buildErrorState(bool isMobile) {
    return Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            padding: const EdgeInsets.all(24),
            decoration: const BoxDecoration(
              color: Color(0xFFFEE2E2),
              shape: BoxShape.circle,
            ),
            child: Icon(
              Icons.error_outline_rounded,
              size:  isMobile ? 60 : 76,
              color: Color(0xFFEF4444),
            ),
          ),
          const SizedBox(height: 24),
          const Text(
            'Oops! Something went wrong',
            style: TextStyle(
              color:      _AppColors.textPrimary,
              fontSize:   20,
              fontFamily: 'Inter',
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 12),
          Text(
            errorMessage!,
            textAlign: TextAlign.center,
            style: const TextStyle(
              color:      _AppColors.textMuted,
              fontSize:   14,
              fontFamily: 'Inter',
            ),
          ),
          const SizedBox(height: 28),
          ElevatedButton.icon(
            onPressed: _loadAttendanceHistory,
            icon:  const Icon(Icons.refresh_rounded, size: 20),
            label: const Text(
              'Try Again',
              style: TextStyle(
                fontFamily: 'Inter',
                fontWeight: FontWeight.w600,
              ),
            ),
            style: ElevatedButton.styleFrom(
              backgroundColor: _AppColors.teal,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 14),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
          ),
        ],
      ),
    );
  }
}