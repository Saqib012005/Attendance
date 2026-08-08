import 'dart:ui';
import 'package:flutter/material.dart';
import '../../services/class_service.dart';

class PendingClassesScreen extends StatefulWidget {
  final List<Map<String, dynamic>> pendingClasses;
  final String? initialJoinCode;

  const PendingClassesScreen({super.key, required this.pendingClasses, this.initialJoinCode});

  @override
  State<PendingClassesScreen> createState() => _PendingClassesScreenState();
}

class _PendingClassesScreenState extends State<PendingClassesScreen> {
  final ClassService _classService = ClassService();
  late List<Map<String, dynamic>> pendingList;

  @override
  void initState() {
    super.initState();
    pendingList = List.from(widget.pendingClasses);
    if (widget.initialJoinCode != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _joinClassDirectly(widget.initialJoinCode!);
      });
    }
  }

  bool _isJoining = false;

  void _joinClassDirectly(String code, [int? classId]) async {
    if (_isJoining) return;
    setState(() {
      _isJoining = true;
    });

    // Show a loading indicator in snackbar or overlay
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Joining class...'), duration: Duration(seconds: 1)),
    );

    final result = await _classService.joinClass(code);

    if (mounted) {
      setState(() {
        _isJoining = false;
      });

      if (result['success']) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(result['message']), backgroundColor: Colors.green),
        );
        if (classId != null) {
          setState(() {
            pendingList.removeWhere((c) => c['id'] == classId);
          });
        } else {
          // If no classId provided (e.g. from deep link), pop to refresh my classes
          Navigator.pop(context, true);
        }
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(result['message']), backgroundColor: Colors.redAccent),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [Color(0xFF007C91), Color(0xFF0097A7)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
        ),
        child: SafeArea(
          child: Column(
            children: [
              _buildAppBar(),
              Expanded(
                child: pendingList.isEmpty
                    ? _buildEmptyState()
                    : ListView.builder(
                        padding: const EdgeInsets.all(16),
                        itemCount: pendingList.length,
                        itemBuilder: (context, index) {
                          final cls = pendingList[index];
                          return _buildPendingClassCard(cls);
                        },
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildAppBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
      child: Row(
        children: [
          Container(
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.2),
              borderRadius: BorderRadius.circular(12),
            ),
            child: IconButton(
              icon: const Icon(
                Icons.arrow_back_ios_new_rounded,
                color: Colors.white,
                size: 20,
              ),
              onPressed: () => Navigator.pop(context),
            ),
          ),
          const SizedBox(width: 16),
          const Text(
            'Pending Classes',
            style: TextStyle(
              color: Colors.white,
              fontSize: 24,
              fontWeight: FontWeight.bold,
              letterSpacing: 0.5,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.inbox_rounded,
            size: 64,
            color: Colors.white.withOpacity(0.5),
          ),
          const SizedBox(height: 16),
          Text(
            'No pending classes.',
            style: TextStyle(
              color: Colors.white.withOpacity(0.8),
              fontSize: 18,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPendingClassCard(Map<String, dynamic> cls) {
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.15),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Colors.white.withOpacity(0.3), width: 1),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(20),
          onTap: () => _joinClassDirectly(cls['class_code'], cls['id']),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Row(
              children: [
                Container(
                  width: 50,
                  height: 50,
                  decoration: BoxDecoration(
                    color: Colors.white.withOpacity(0.2),
                    borderRadius: BorderRadius.circular(15),
                  ),
                  child: Center(
                    child: Text(
                      cls['class_name'].substring(0, 1).toUpperCase(),
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 24,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        cls['class_name'],
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'By: ${cls['teacher_name']}',
                        style: TextStyle(
                          color: Colors.white.withOpacity(0.8),
                          fontSize: 14,
                        ),
                      ),
                    ],
                  ),
                ),
                const Icon(
                  Icons.arrow_forward_ios_rounded,
                  color: Colors.white,
                  size: 16,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

