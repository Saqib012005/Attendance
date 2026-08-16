import json
import uuid
import re
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from datetime import timedelta


from .serializers import (
    RegistrationSerializer, 
    UserSerializer, 
    LoginSerializer,
    ClassSerializer,
    ClassListSerializer,
    CreateClassSerializer,
    StudentDetailSerializer,
    CreateSessionSerializer,  
    SessionSerializer,
    AttendanceRecordSerializer,
    TeacherAttendanceHistorySerializer,
    UpdateAttendanceStatusSerializer,
)
from .models import (Class, Enrollment, StudentProfile, AttendanceSession, AttendanceRecord,
                     RegisteredDevice, AttendanceVerification, AttendanceAuditEvent)
from .secure_attendance import issue_epoch, validate_qr, validate_captcha, validate_sensor_summary
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    """Public endpoint for new user registration"""
    permission_classes = (permissions.AllowAny,)
    serializer_class = RegistrationSerializer


class MeView(generics.RetrieveAPIView):
    """Returns details about currently authenticated user"""
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        """Generate JWT token with custom claims"""
        token = super().get_token(user)
        # Add custom claims
        token['role'] = user.role
        token['username'] = user.username
        return token

    def validate(self, attrs):
        """Authenticate user and return tokens + user data"""
        #Step 1: Validate credentials
        data = super().validate(attrs)
        # Add user data to response
        data['user'] = UserSerializer(self.user).data
        return data


class MyTokenObtainPairView(TokenObtainPairView):
    """Custom token view using our serializer"""
    serializer_class = MyTokenObtainPairSerializer


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def ping(request):
    return Response({"status": "ok", "message": "Server is running!"})


# ============================================
# ADMIN CLASS MANAGEMENT VIEWS
# ============================================

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def admin_classes_summary(request):
    """
    Admin: Get all classes grouped by semester with student counts.
    Returns a summary per semester: semester label + total students.
    """
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can access this endpoint'},
            status=status.HTTP_403_FORBIDDEN
        )

    from django.db.models import Count

    classes_by_semester = Class.objects.values('semester').annotate(
        student_count=Count('enrollments')
    ).order_by('semester')

    return Response({
        'semesters': list(classes_by_semester),
        'total_semesters': classes_by_semester.count(),
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def admin_semester_classes(request, semester):
    """
    Admin: Get all classes in a given semester with their enrolled students.
    """
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can access this endpoint'},
            status=status.HTTP_403_FORBIDDEN
        )

    classes = Class.objects.filter(semester=semester).prefetch_related(
        'enrollments__student__student_profile'
    )

    result = []
    for cls in classes:
        student_list = []
        for enrollment in cls.enrollments.all():
            student = enrollment.student
            try:
                profile = student.student_profile
                roll_no = profile.roll_no
            except StudentProfile.DoesNotExist:
                roll_no = 'N/A'
            student_list.append({
                'id': student.id,
                'username': student.username,
                'email': student.email,
                'roll_no': roll_no,
            })

        result.append({
            'id': cls.id,
            'class_code': cls.class_code,
            'class_name': cls.class_name,
            'teacher_name': cls.teacher_name,
            'semester': cls.semester,
            'student_count': len(student_list),
            'students': student_list,
        })

    return Response({
        'semester': semester,
        'classes': result,
        'total_classes': len(result),
        'total_students': sum(c['student_count'] for c in result),
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def admin_semester_students(request, semester):
    """
    Admin: Get all unique students in a given semester with their enrolled class codes.
    Deduplicates students who are enrolled in multiple classes.
    """
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can access this endpoint'},
            status=status.HTTP_403_FORBIDDEN
        )

    classes = Class.objects.filter(semester=semester).prefetch_related(
        'enrollments__student__student_profile'
    )

    students_map = {}
    for cls in classes:
        for enrollment in cls.enrollments.all():
            student = enrollment.student
            if student.id not in students_map:
                try:
                    profile = student.student_profile
                    roll_no = profile.roll_no
                except StudentProfile.DoesNotExist:
                    roll_no = 'N/A'
                students_map[student.id] = {
                    'id': student.id,
                    'username': student.username,
                    'email': student.email,
                    'roll_no': roll_no,
                    'classes': [],
                }
            students_map[student.id]['classes'].append({
                'id': cls.id,
                'class_code': cls.class_code,
            })

    students_list = list(students_map.values())

    return Response({
        'semester': semester,
        'total_students': len(students_list),
        'students': students_list,
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def admin_teachers_list(request):
    """
    Admin: Get all teachers with their class details.
    Returns each teacher's info + list of classes they teach.
    """
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can access this endpoint'},
            status=status.HTTP_403_FORBIDDEN
        )

    from django.db.models import Count

    teachers = User.objects.filter(role='teacher').annotate(
        class_count=Count('classes_taught')
    ).prefetch_related('classes_taught').order_by('username')

    result = []
    for teacher in teachers:
        classes_list = []
        for cls in teacher.classes_taught.all():
            classes_list.append({
                'id': cls.id,
                'class_code': cls.class_code,
                'class_name': cls.class_name,
                'student_count': cls.student_count,
            })

        result.append({
            'id': teacher.id,
            'username': teacher.username,
            'email': teacher.email,
            'date_joined': teacher.date_joined,
            'class_count': teacher.class_count,
            'classes': classes_list,
        })

    return Response({
        'teachers': result,
        'total_teachers': len(result),
    })


@api_view(['PATCH'])
@permission_classes([permissions.IsAuthenticated])
def admin_update_teacher(request, teacher_id):
    """Admin: Update teacher's name and email"""
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can update teachers'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        teacher = User.objects.get(id=teacher_id, role='teacher')
    except User.DoesNotExist:
        return Response(
            {'error': 'Teacher not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    username = request.data.get('username')
    email = request.data.get('email')

    if username is not None:
        username = username.strip()
        if not username:
            return Response(
                {'error': 'Name cannot be empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        teacher.username = username

    if email is not None:
        email = email.strip().lower()
        if not email:
            return Response(
                {'error': 'Email cannot be empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if User.objects.filter(email=email).exclude(id=teacher_id).exists():
            return Response(
                {'error': 'Email already in use by another user'},
                status=status.HTTP_400_BAD_REQUEST
            )
        teacher.email = email

    teacher.save()

    return Response({
        'message': 'Teacher updated successfully',
        'teacher': {
            'id': teacher.id,
            'username': teacher.username,
            'email': teacher.email,
        }
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def admin_stats(request):
    """Admin: Get aggregate counts for dashboard."""
    user = request.user

    if user.role != 'admin':
        return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

    return Response({
        'teachers_count': User.objects.filter(role='teacher').count(),
        'students_count': User.objects.filter(role='student').count(),
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def admin_users_list(request, role):
    """
    Admin: Get users by role for login-reset management.
    GET /api/v1/admin/users/teachers/ or /api/v1/admin/users/students/
    """
    user = request.user

    if user.role != 'admin':
        return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

    if role not in ('teachers', 'students'):
        return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)

    users = User.objects.filter(role=role[:-1]).order_by('username')

    if role == 'teachers':
        data = [{
            'id': u.id,
            'username': u.username,
            'full_name': u.get_full_name() or u.username,
            'email': u.email,
            'is_active': u.is_active,
        } for u in users]
    else:
        data = []
        for u in users:
            try:
                roll_no = u.student_profile.roll_no
            except StudentProfile.DoesNotExist:
                roll_no = 'N/A'
            data.append({
                'id': u.id,
                'username': u.username,
                'full_name': u.get_full_name() or u.username,
                'email': u.email,
                'roll_no': roll_no,
                'is_active': u.is_active,
            })

    return Response({
        role: data,
        'total': len(data),
    })


@api_view(['PATCH'])
@permission_classes([permissions.IsAuthenticated])
def admin_toggle_user_access(request, user_id):
    """Admin: Toggle is_active for a user."""
    user = request.user

    if user.role != 'admin':
        return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

    try:
        target = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    target.is_active = not target.is_active
    target.save(update_fields=['is_active'])

    return Response({
        'id': target.id,
        'username': target.username,
        'email': target.email,
        'role': target.role,
        'is_active': target.is_active,
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def admin_create_user(request):
    """Admin: Create a new user (student or teacher)"""
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can create users'},
            status=status.HTTP_403_FORBIDDEN
        )

    username = request.data.get('username', '').strip()
    email = request.data.get('email', '').strip().lower()
    password = request.data.get('password', '')
    role = request.data.get('role', '')
    roll_no = request.data.get('roll_no', '').strip()

    if not username:
        return Response({'error': 'Name is required'}, status=status.HTTP_400_BAD_REQUEST)
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    if not password or len(password) < 6:
        return Response({'error': 'Password must be at least 6 characters'}, status=status.HTTP_400_BAD_REQUEST)
    if role not in ('student', 'teacher'):
        return Response({'error': 'Role must be student or teacher'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({'error': 'Email already in use'}, status=status.HTTP_400_BAD_REQUEST)
    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already taken'}, status=status.HTTP_400_BAD_REQUEST)

    new_user = User(
        username=username,
        email=email,
        role=role,
    )
    new_user.set_password(password)
    new_user.save()

    if role == 'student':
        if not roll_no:
            roll_no = f'STU-{new_user.id}'
        StudentProfile.objects.create(student=new_user, roll_no=roll_no)

    return Response({
        'message': f'{role.capitalize()} created successfully',
        'user': {
            'id': new_user.id,
            'username': new_user.username,
            'email': new_user.email,
            'role': new_user.role,
            'roll_no': roll_no if role == 'student' else None,
        }
    }, status=status.HTTP_201_CREATED)


@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
def admin_delete_user(request, user_id):
    """Admin: Permanently delete a user"""
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can delete users'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        target = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    if target == user:
        return Response(
            {'error': 'You cannot delete yourself'},
            status=status.HTTP_400_BAD_REQUEST
        )

    if target.role == 'teacher':
        from django.db.models import Count
        class_count = target.classes_taught.count()
        if class_count > 0:
            return Response(
                {'error': f'Teacher still has {class_count} class(es) assigned. Reassign or delete classes first.'},
                status=status.HTTP_400_BAD_REQUEST
            )

    username = target.username
    role = target.role
    target.delete()

    return Response({
        'message': f'{role.capitalize()} "{username}" deleted permanently',
    })


# ============================================
# CLASS MANAGEMENT VIEWS
# ============================================

@api_view(['GET', 'POST'])
@permission_classes([permissions.IsAuthenticated])
def class_list_create(request):
    """
    GET: List all classes for the logged-in teacher
    POST: Create a new class with students
    """
    user = request.user
    
    # Verify user is a teacher
    if user.role != 'teacher':
        return Response(
            {'error': 'Only teachers can manage classes'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    if request.method == 'GET':
        # Get all classes taught by this teacher
        classes = Class.objects.filter(teacher=user).prefetch_related('enrollments')
        serializer = ClassListSerializer(classes, many=True)
        return Response({'classes': serializer.data})
    
    elif request.method == 'POST':
        # Create new class with students
        serializer = CreateClassSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            try:
                result = serializer.save()
                class_obj = result['class']
                
                # Return created class details
                class_serializer = ClassSerializer(class_obj)
                return Response({
                    'message': 'Class created successfully',
                    'class': class_serializer.data
                }, status=status.HTTP_201_CREATED)
            
            except Exception as e:
                return Response({
                    'error': f'Failed to create class: {str(e)}'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([permissions.IsAuthenticated])
def class_detail(request, class_id):
    """
    GET: Get class details with enrolled students
    PUT: Update class details
    DELETE: Delete class
    """
    user = request.user
    
    try:
        class_obj = Class.objects.get(id=class_id, teacher=user)
    except Class.DoesNotExist:
        return Response(
            {'error': 'Class not found or you do not have permission'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    if request.method == 'GET':
        serializer = ClassSerializer(class_obj)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        # Update class details
        class_code = request.data.get('code')
        class_name = request.data.get('name')
        semester = request.data.get('semester')
        
        if class_code:
            # Check if code is already taken by another class
            if Class.objects.filter(class_code=class_code).exclude(id=class_id).exists():
                return Response(
                    {'error': 'Class code already exists'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            class_obj.class_code = class_code
        
        if class_name:
            class_obj.class_name = class_name
        if semester:
            class_obj.semester = semester
        
        class_obj.save()
        serializer = ClassSerializer(class_obj)
        return Response({
            'message': 'Class updated successfully',
            'class': serializer.data
        })
    
    elif request.method == 'DELETE':
        class_name = class_obj.class_name
        class_obj.delete()
        return Response({
            'message': f'Class "{class_name}" deleted successfully'
        }, status=status.HTTP_204_NO_CONTENT)


@api_view(['PUT'])
@permission_classes([permissions.IsAuthenticated])
def admin_update_class(request, class_id):
    """Admin: Update class details (code, name, semester)"""
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can update classes'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        class_obj = Class.objects.get(id=class_id)
    except Class.DoesNotExist:
        return Response(
            {'error': 'Class not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    class_code = request.data.get('class_code')
    class_name = request.data.get('class_name')
    semester = request.data.get('semester')

    if class_code is not None:
        class_code = class_code.strip()
        if not class_code:
            return Response(
                {'error': 'Class code cannot be empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if Class.objects.filter(class_code=class_code).exclude(id=class_id).exists():
            return Response(
                {'error': 'Class code already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )
        class_obj.class_code = class_code

    if class_name is not None:
        class_name = class_name.strip()
        if not class_name:
            return Response(
                {'error': 'Class name cannot be empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        class_obj.class_name = class_name

    if semester is not None:
        semester = semester.strip()
        if not semester:
            return Response(
                {'error': 'Semester cannot be empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        class_obj.semester = semester

    class_obj.save()

    return Response({
        'message': 'Class updated successfully',
        'class': {
            'id': class_obj.id,
            'class_code': class_obj.class_code,
            'class_name': class_obj.class_name,
            'semester': class_obj.semester,
            'student_count': class_obj.student_count,
        }
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def admin_class_detail(request, class_id):
    """Admin: Get class details with enrolled students"""
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can access this endpoint'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        class_obj = Class.objects.get(id=class_id)
    except Class.DoesNotExist:
        return Response(
            {'error': 'Class not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    enrollments = class_obj.enrollments.select_related('student__student_profile')
    students_list = []
    for enrollment in enrollments:
        student = enrollment.student
        try:
            profile = student.student_profile
            roll_no = profile.roll_no
        except StudentProfile.DoesNotExist:
            roll_no = 'N/A'
        students_list.append({
            'id': student.id,
            'username': student.username,
            'email': student.email,
            'roll_no': roll_no,
        })

    return Response({
        'id': class_obj.id,
        'class_code': class_obj.class_code,
        'class_name': class_obj.class_name,
        'semester': class_obj.semester,
        'teacher_name': class_obj.teacher_name,
        'student_count': len(students_list),
        'students': students_list,
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_class_students(request, class_id):
    """Get all students enrolled in a class"""
    user = request.user
    
    try:
        class_obj = Class.objects.get(id=class_id, teacher=user)
    except Class.DoesNotExist:
        return Response(
            {'error': 'Class not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Get all enrollments with student profiles
    enrollments = Enrollment.objects.filter(
        class_obj=class_obj
    ).select_related('student__student_profile')
    
    students_data = []
    for enrollment in enrollments:
        student = enrollment.student
        try:
            profile = student.student_profile
            students_data.append({
                'id': student.id,
                'username': student.username,
                'email': student.email,
                'roll_no': profile.roll_no,
                'enrolled_at': enrollment.enrolled_at
            })
        except StudentProfile.DoesNotExist:
            students_data.append({
                'id': student.id,
                'username': student.username,
                'email': student.email,
                'roll_no': 'N/A',
                'enrolled_at': enrollment.enrolled_at
            })
    
    return Response({
        'class_code': class_obj.class_code,
        'class_name': class_obj.class_name,
        'semester': class_obj.semester,
        'students': students_data,
        'total': len(students_data)
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def add_student_to_class(request, class_id):
    """
    Add a student to an existing class
    - If student exists: just enroll them
    - If student is new: create user, profile, and enroll
    """
    user = request.user
    
    try:
        class_obj = Class.objects.get(id=class_id, teacher=user)
    except Class.DoesNotExist:
        return Response(
            {'error': 'Class not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    student_data = request.data
    
    # Validate required fields
    required_fields = ['email']
    for field in required_fields:
        if field not in student_data:
            return Response(
                {'error': f'Missing required field: {field}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    email = student_data['email']
    
    try:
        with transaction.atomic():
            # Check if user already exists
            existing_user = User.objects.filter(email=email).first()
            
            if existing_user:
                # User exists - just enroll them in this class
                if existing_user.role != 'student':
                    return Response(
                        {'error': f'{email} is not a student account'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Check if already enrolled
                if Enrollment.objects.filter(class_obj=class_obj, student=existing_user).exists():
                    return Response(
                        {'error': f'Student already enrolled in this class'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Enroll existing student
                Enrollment.objects.create(
                    class_obj=class_obj,
                    student=existing_user
                )
                
                try:
                    roll_no = existing_user.student_profile.roll_no
                except:
                    roll_no = 'N/A'
                
                return Response({
                    'message': f"Student {existing_user.username} enrolled successfully",
                    'student': {
                        'id': existing_user.id,
                        'username': existing_user.username,
                        'email': existing_user.email,
                        'roll_no': roll_no,
                        'status': 'existing'
                    }
                }, status=status.HTTP_201_CREATED)
            
            else:
                # New student - create user and profile
                required_for_new = ['name', 'password', 'rollNo']
                for field in required_for_new:
                    if field not in student_data:
                        return Response(
                            {'error': f'Missing required field for new student: {field}'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                
                # Check if roll number exists
                if StudentProfile.objects.filter(roll_no=student_data['rollNo']).exists():
                    return Response(
                        {'error': f"Roll number {student_data['rollNo']} already exists"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Generate unique username from email
                username = email.split('@')[0]
                base_username = username
                counter = 1
                while User.objects.filter(username=username).exists():
                    username = f"{base_username}{counter}"
                    counter += 1
                
                # Create user
                student = User.objects.create_user(
                    username=username,
                    email=email,
                    password=student_data['password'],
                    role='student'
                )
                
                # Create student profile (FIXED)
                StudentProfile.objects.create(
                    student=student,  # ✅ Correct field name
                    roll_no=student_data['rollNo']
                )
                
                # Enroll in class
                Enrollment.objects.create(
                    class_obj=class_obj,
                    student=student
                )
                
                return Response({
                    'message': f"New student {student_data['name']} created and enrolled",
                    'student': {
                        'id': student.id,
                        'username': student.username,
                        'email': student.email,
                        'roll_no': student_data['rollNo'],
                        'status': 'new'
                    }
                }, status=status.HTTP_201_CREATED)
    
    except Exception as e:
        return Response({
            'error': f'Failed to add student: {str(e)}'
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
def remove_student_from_class(request, class_id, student_id):
    """Remove a student from a class (unenroll)"""
    user = request.user
    
    try:
        class_obj = Class.objects.get(id=class_id, teacher=user)
    except Class.DoesNotExist:
        return Response(
            {'error': 'Class not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    try:
        enrollment = Enrollment.objects.get(
            class_obj=class_obj,
            student_id=student_id
        )
        student_username = enrollment.student.username
        enrollment.delete()
        
        return Response({
            'message': f'Student {student_username} removed from class'
        }, status=status.HTTP_200_OK)
    
    except Enrollment.DoesNotExist:
        return Response(
            {'error': 'Student not found in this class'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
def admin_remove_student_from_class(request, class_id, student_id):
    """Admin: Remove a student from a class"""
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can perform this action'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        class_obj = Class.objects.get(id=class_id)
    except Class.DoesNotExist:
        return Response(
            {'error': 'Class not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    try:
        enrollment = Enrollment.objects.get(
            class_obj=class_obj,
            student_id=student_id
        )
        student_username = enrollment.student.username
        enrollment.delete()
        return Response({
            'message': f'Student {student_username} removed from class'
        }, status=status.HTTP_200_OK)
    except Enrollment.DoesNotExist:
        return Response(
            {'error': 'Student not found in this class'},
            status=status.HTTP_404_NOT_FOUND
        )


# ============================================
#  SESSION MANAGEMENT VIEWS
# ============================================

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def create_session(request):
    """Create a new attendance session with QR code"""
    user = request.user
    
    if user.role != 'teacher':
        return Response(
            {'error': 'Only teachers can create sessions'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    serializer = CreateSessionSerializer(data=request.data, context={'request': request})
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    class_id = serializer.validated_data['class_id']
    duration_minutes = serializer.validated_data['duration_minutes']
    
    try:
        class_obj = Class.objects.get(id=class_id, teacher=user)
    except Class.DoesNotExist:
        return Response(
            {'error': 'Class not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Calculate end time
    start_time = timezone.now()
    end_time = start_time + timedelta(minutes=duration_minutes)
    
    # Generate session UUID
    session_uuid = uuid.uuid4()
    
    # Create QR code data (JSON string)
    qr_data = {
        'session_id': str(session_uuid),
        'class_id': class_obj.id,
        'class_code': class_obj.class_code,
        'class_name': class_obj.class_name,
        'semester': class_obj.semester,
        'teacher': user.username,
        'start_time': start_time.isoformat(),
        'end_time': end_time.isoformat(),
        'duration': duration_minutes,
    }
    
    # Create session
    session = AttendanceSession.objects.create(
        session_id=session_uuid,
        class_obj=class_obj,
        teacher=user,
        duration_minutes=duration_minutes,
        end_time=end_time,
        qr_code_data=json.dumps(qr_data),
        status='active'
    )
    
    response_serializer = SessionSerializer(session)
    return Response({
        'message': 'Session created successfully',
        'session': response_serializer.data
    }, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_active_sessions(request):
    """Get all active sessions for logged-in teacher"""
    user = request.user
    
    if user.role != 'teacher':
        return Response(
            {'error': 'Only teachers can view sessions'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Get active sessions
    sessions = AttendanceSession.objects.filter(
        teacher=user,
        status='active',
        end_time__gt=timezone.now()
    ).select_related('class_obj')
    
    serializer = SessionSerializer(sessions, many=True)
    return Response({
        'sessions': serializer.data,
        'total': sessions.count()
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_session_details(request, session_id):
    """Get session details with attendance records"""
    user = request.user
    
    try:
        session = AttendanceSession.objects.get(
            session_id=session_id,
            teacher=user
        )
    except AttendanceSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Get attendance records
    records = AttendanceRecord.objects.filter(session=session).select_related('student')
    
    session_data = SessionSerializer(session).data
    records_data = AttendanceRecordSerializer(records, many=True).data
    
    return Response({
        'session': session_data,
        'attendance': records_data,
        'total_present': records.filter(status='present').count(),
        'total_students': session.class_obj.student_count
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def mark_attendance(request, session_id):
    """Evaluate every required check; only the backend may mark present."""
    user = request.user
    
    if user.role != 'student':
        return Response(
            {'error': 'Only students can mark attendance'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        session = AttendanceSession.objects.get(session_id=session_id)
    except AttendanceSession.DoesNotExist:
        return Response(
            {'error': 'Invalid QR code - Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Check if session is active
    if session.status != 'active':
        return Response(
            {'error': 'This session has ended'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Check if session has expired
    if not session.is_active:
        return Response(
            {'error': f'Session expired at {session.end_time.strftime("%I:%M %p")}'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Check if student is enrolled in the class
    if not Enrollment.objects.filter(class_obj=session.class_obj, student=user).exists():
        return Response(
            {'error': f'You are not enrolled in {session.class_obj.class_code}'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Idempotent result: never create a second attendance for the same student/session.
    existing_record = AttendanceRecord.objects.filter(session=session, student=user).first()
    if existing_record:
        return Response({
            'message': 'Existing attendance result returned',
            'marked_at': existing_record.marked_at,
            'status': existing_record.status,
            'final_status': getattr(getattr(existing_record, 'verification', None), 'final_status', None),
        })

    qr_authentic, qr_fresh, epoch = validate_qr(request.data.get('qr_payload', ''), session)
    enrolled = Enrollment.objects.filter(class_obj=session.class_obj, student=user).exists()
    session_valid = session.status == 'active' and session.is_active
    raw_device_id = request.data.get('device_id', '')
    device_hash = __import__('hashlib').sha256(raw_device_id.encode()).hexdigest() if raw_device_id else ''
    device = RegisteredDevice.objects.filter(user=user, device_id_hash=device_hash, is_active=True).first()
    captcha_ok = validate_captcha(session, epoch, user.id, request.data.get('captcha')) if epoch is not None else False
    gyro = validate_sensor_summary(request.data.get('gyroscope'), 'gyroscope')
    accel = validate_sensor_summary(request.data.get('accelerometer'), 'accelerometer')
    matrix = {
        'qr_result': 'pass' if qr_authentic else 'fail',
        'qr_freshness_result': 'pass' if qr_fresh else 'fail',
        'session_result': 'pass' if session_valid else 'fail',
        'student_eligibility_result': 'pass' if enrolled else 'fail',
        'device_result': 'pass' if device else 'fail',
        'captcha_result': 'pass' if captcha_ok else 'fail',
        'gyroscope_result': gyro,
        'accelerometer_result': accel,
    }
    all_pass = all(value == 'pass' for value in matrix.values())
    with transaction.atomic():
        record = AttendanceRecord.objects.create(
            session=session, student=user, status='present' if all_pass else 'pending_review')
        verification = AttendanceVerification.objects.create(
            attendance=record, device=device, final_status='verified' if all_pass else 'teacher_review_required', **matrix)
        AttendanceAuditEvent.objects.create(
            attendance=record, actor=user, event_type='attendance.verified' if all_pass else 'attendance.cross_verification_requested',
            details={'matrix': matrix})
    return Response({
        'message': 'Attendance marked present' if all_pass else 'Additional verification required',
        'status': record.status, 'final_status': verification.final_status, 'verification': matrix,
    }, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_secure_epoch(request, session_id):
    if request.user.role != 'teacher':
        return Response({'error': 'Only teachers can display secure attendance codes'}, status=403)
    try:
        session = AttendanceSession.objects.get(session_id=session_id, teacher=request.user, status='active')
    except AttendanceSession.DoesNotExist:
        return Response({'error': 'Active session not found'}, status=404)
    return Response(issue_epoch(session))


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_pending_reviews(request, session_id):
    if request.user.role != 'teacher':
        return Response({'error': 'Only teachers can view reviews'}, status=403)
    reviews = AttendanceRecord.objects.filter(
        session__session_id=session_id,
        session__teacher=request.user,
        verification__final_status='teacher_review_required',
    ).select_related('student__student_profile', 'session__class_obj', 'verification')
    data = []
    for record in reviews:
        verification = record.verification
        matrix = {
            'qr_authenticity': verification.qr_result,
            'qr_freshness': verification.qr_freshness_result,
            'session': verification.session_result,
            'student_eligibility': verification.student_eligibility_result,
            'device': verification.device_result,
            'captcha': verification.captcha_result,
            'gyroscope': verification.gyroscope_result,
            'accelerometer': verification.accelerometer_result,
        }
        data.append({
            'record_id': record.id,
            'student_name': record.student.get_full_name() or record.student.username,
            'roll_no': getattr(getattr(record.student, 'student_profile', None), 'roll_no', ''),
            'subject': record.session.class_obj.class_name,
            'requested_at': record.marked_at,
            'verification': matrix,
        })
    return Response({'reviews': data})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def register_device(request):
    if request.user.role not in ('student', 'teacher', 'admin'):
        return Response({'error': 'Unsupported account role'}, status=403)
    raw_device_id = request.data.get('device_id', '')
    if len(raw_device_id) < 16:
        return Response({'error': 'A stable device identifier is required'}, status=400)
    device_hash = __import__('hashlib').sha256(raw_device_id.encode()).hexdigest()
    existing = RegisteredDevice.objects.filter(user=request.user, device_id_hash=device_hash).first()
    if existing:
        if not existing.is_active:
            return Response({'error': 'This device is inactive'}, status=403)
        return Response({'authorized': True})
    limit = 1 if request.user.role == 'student' else 2
    if RegisteredDevice.objects.filter(user=request.user, is_active=True).count() >= limit:
        return Response({'error': 'Device limit reached; existing devices are not replaced automatically'}, status=403)
    RegisteredDevice.objects.create(user=request.user, device_id_hash=device_hash,
                                    device_name=request.data.get('device_name', '')[:120])
    return Response({'authorized': True}, status=201)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def resolve_cross_verification(request, record_id):
    if request.user.role != 'teacher':
        return Response({'error': 'Only teachers can resolve reviews'}, status=403)
    decision = request.data.get('decision')
    if decision not in ('present', 'reject'):
        return Response({'error': 'decision must be present or reject'}, status=400)
    with transaction.atomic():
        try:
            record = AttendanceRecord.objects.select_for_update().select_related('verification').get(
                id=record_id, session__teacher=request.user,
                verification__final_status='teacher_review_required')
        except AttendanceRecord.DoesNotExist:
            return Response({'error': 'Pending review not found'}, status=404)
        record.status = 'present' if decision == 'present' else 'absent'
        record.save(update_fields=('status',))
        verification = record.verification
        verification.final_status = 'teacher_cross_verified' if decision == 'present' else 'teacher_rejected'
        verification.teacher = request.user
        verification.teacher_decision_at = timezone.now()
        verification.save()
        AttendanceAuditEvent.objects.create(attendance=record, actor=request.user,
                                            event_type='attendance.cross_verification_resolved', details={'decision': decision})
    return Response({'status': record.status, 'final_status': verification.final_status})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def end_session(request, session_id):
    """Teacher ends an active session and marks absent students"""
    user = request.user
    
    try:
        session = AttendanceSession.objects.get(
            session_id=session_id,
            teacher=user
        )
    except AttendanceSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    if session.status != 'active':
        return Response(
            {'error': 'Session is not active'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Mark all absent students before ending session
    with transaction.atomic():
        # Get all enrolled students in this class
        enrolled_students = Enrollment.objects.filter(
            class_obj=session.class_obj
        ).select_related('student')
        
        # Get students who already marked attendance
        already_marked = AttendanceRecord.objects.filter(
            session=session
        ).values_list('student_id', flat=True)
        
        # Find students who haven't marked attendance
        absent_students = enrolled_students.exclude(
            student_id__in=already_marked
        )
        
        # Create attendance records for absent students
        absent_records = []
        for enrollment in absent_students:
            absent_records.append(
                AttendanceRecord(
                    session=session,
                    student=enrollment.student,
                    status='absent'
                )
            )
        
        # Bulk create all absent records
        auto_marked_count = 0
        if absent_records:
            AttendanceRecord.objects.bulk_create(absent_records)
            auto_marked_count = len(absent_records)
        
        # Update session status
        session.status = 'completed'
        session.end_time = timezone.now()
        session.save()
    
    # Get final statistics
    total_students = enrolled_students.count()
    present_count = AttendanceRecord.objects.filter(
        session=session,
        status='present'
    ).count()
    absent_count = total_students - present_count
    attendance_rate = round((present_count / total_students * 100), 2) if total_students > 0 else 0
    
    return Response({
        'success': True,
        'message': 'Session ended successfully',
        'session': SessionSerializer(session).data,
        'statistics': {
            'total_students': total_students,
            'present': present_count,
            'absent': absent_count,
            'attendance_rate': attendance_rate,
            'auto_marked_absent': auto_marked_count
        }
    }, status=status.HTTP_200_OK)


# ============================================
#  STUDENT ENROLLED CLASSES VIEW
# ============================================

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_student_enrolled_classes(request):
    """Get all classes the logged-in student is enrolled in"""
    user = request.user
    
    if user.role != 'student':
        return Response(
            {'error': 'Only students can view enrolled classes'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Get all enrollments for this student
    enrollments = Enrollment.objects.filter(
        student=user
    ).select_related('class_obj__teacher')
    
    classes_data = []
    for enrollment in enrollments:
        class_obj = enrollment.class_obj
        classes_data.append({
            'id': class_obj.id,
            'class_code': class_obj.class_code,
            'class_name': class_obj.class_name,
            'semester': class_obj.semester,
            'teacher_name': class_obj.teacher.username,
            'teacher_email': class_obj.teacher.email,
            'student_count': class_obj.student_count,
            'enrolled_at': enrollment.enrolled_at,
            'created_at': class_obj.created_at,
        })
    
    return Response({
        'classes': classes_data,
        'total': len(classes_data)
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_student_attendance_history(request):
    """Get attendance history for logged-in student"""
    user = request.user
    
    if user.role != 'student':
        return Response(
            {'error': 'Only students can view attendance history'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Get all attendance records for this student
    records = AttendanceRecord.objects.filter(
        student=user
    ).select_related('session__class_obj').order_by('-marked_at')
    
    attendance_data = []
    for record in records:
        session = record.session
        attendance_data.append({
            'id': record.id,
            'class_code': session.class_obj.class_code,
            'class_name': session.class_obj.class_name,
            'semester': session.class_obj.semester,
            'date': session.start_time.date(),
            'time': session.start_time.time(),
            'status': record.status,
            'marked_at': record.marked_at,
        })
    
    return Response({
        'attendance': attendance_data,
        'total': len(attendance_data)
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def check_student_by_email(request):
    """
    Check if a student exists by email and return their details
    GET /api/v1/auth/check-student/?email=student@example.com
    """
    email = request.query_params.get('email')
    
    if not email:
        return Response(
            {'error': 'Email parameter is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Validate email format
    import re
    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_pattern, email):
        return Response(
            {'error': 'Invalid email format'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user = User.objects.get(email=email, role='student')
        
        # Try to get student profile
        try:
            profile = user.student_profile
            roll_no = profile.roll_no
        except StudentProfile.DoesNotExist:
            roll_no = None
        
        return Response({
            'exists': True,
            'student': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'roll_no': roll_no,
            }
        }, status=status.HTTP_200_OK)
        
    except User.DoesNotExist:
        return Response({
            'exists': False,
            'message': 'Student not found with this email'
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            'error': f'Error checking student: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['PUT'])
@permission_classes([permissions.IsAuthenticated])
def update_student_in_class(request, class_id, student_id):
    """Update student details in a class"""
    user = request.user
    
    try:
        class_obj = Class.objects.get(id=class_id, teacher=user)
        enrollment = Enrollment.objects.get(class_obj=class_obj, student_id=student_id)
        
        # Update student profile
        profile = enrollment.student.student_profile
        roll_no = request.data.get('roll_no')
        
        if roll_no:
            # Check if roll number already exists
            if StudentProfile.objects.filter(roll_no=roll_no).exclude(student=enrollment.student).exists():
                return Response(
                    {'error': 'Roll number already exists'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            profile.roll_no = roll_no
            profile.save()
        
        return Response({'message': 'Student updated successfully'})
    
    except Class.DoesNotExist:
        return Response({'error': 'Class not found'}, status=status.HTTP_404_NOT_FOUND)
    except Enrollment.DoesNotExist:
        return Response({'error': 'Student not enrolled'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['PATCH'])
@permission_classes([permissions.IsAuthenticated])
def admin_update_student(request, student_id):
    """Admin: Update student's name, email, and roll number"""
    user = request.user

    if user.role != 'admin':
        return Response(
            {'error': 'Only admins can update students'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        student = User.objects.get(id=student_id, role='student')
    except User.DoesNotExist:
        return Response(
            {'error': 'Student not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    username = request.data.get('username')
    email = request.data.get('email')
    roll_no = request.data.get('roll_no')

    if username is not None:
        username = username.strip()
        if not username:
            return Response(
                {'error': 'Name cannot be empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        student.username = username

    if email is not None:
        email = email.strip().lower()
        if not email:
            return Response(
                {'error': 'Email cannot be empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if User.objects.filter(email=email).exclude(id=student_id).exists():
            return Response(
                {'error': 'Email already in use by another user'},
                status=status.HTTP_400_BAD_REQUEST
            )
        student.email = email

    student.save()

    if roll_no is not None:
        roll_no = roll_no.strip()
        profile, created = StudentProfile.objects.get_or_create(student=student)
        if StudentProfile.objects.filter(roll_no=roll_no).exclude(student=student).exists():
            return Response(
                {'error': 'Roll number already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )
        profile.roll_no = roll_no
        profile.save()

    return Response({
        'message': 'Student updated successfully',
        'student': {
            'id': student.id,
            'username': student.username,
            'email': student.email,
            'roll_no': roll_no or (student.student_profile.roll_no if hasattr(student, 'student_profile') else 'N/A'),
        }
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_teacher_attendance_history(request):
    """
    Get attendance history for teacher's classes
    Query params:
    - class_id: Filter by specific class (optional)
    - session_id: Filter by specific session (optional)
    - date_from: Filter from date (YYYY-MM-DD) (optional)
    - date_to: Filter to date (YYYY-MM-DD) (optional)
    """
    user = request.user
    
    if user.role != 'teacher':
        return Response(
            {'error': 'Only teachers can view attendance history'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Base query: all attendance records for teacher's classes
    records = AttendanceRecord.objects.filter(
        session__teacher=user
    ).select_related(
        'student__student_profile',
        'session__class_obj'
    ).order_by('-marked_at')
    
    # Apply filters
    class_id = request.query_params.get('class_id')
    if class_id:
        records = records.filter(session__class_obj_id=class_id)
    
    session_id = request.query_params.get('session_id')
    if session_id:
        records = records.filter(session__session_id=session_id)
    
    date_from = request.query_params.get('date_from')
    if date_from:
        try:
            from_date = timezone.datetime.strptime(date_from, '%Y-%m-%d').date()
            records = records.filter(session__start_time__date__gte=from_date)
        except ValueError:
            pass
    
    date_to = request.query_params.get('date_to')
    if date_to:
        try:
            to_date = timezone.datetime.strptime(date_to, '%Y-%m-%d').date()
            records = records.filter(session__start_time__date__lte=to_date)
        except ValueError:
            pass
    
    serializer = TeacherAttendanceHistorySerializer(records, many=True)
    
    # Calculate statistics
    total_records = records.count()
    present_count = records.filter(status='present').count()
    absent_count = records.filter(status='absent').count()
    
    return Response({
        'attendance': serializer.data,
        'statistics': {
            'total': total_records,
            'present': present_count,
            'absent': absent_count,
            'attendance_rate': round((present_count / total_records * 100), 2) if total_records > 0 else 0
        }
    })


@api_view(['PUT'])
@permission_classes([permissions.IsAuthenticated])
def update_attendance_status(request, record_id):
    """Update attendance status (teacher only)"""
    user = request.user
    
    if user.role != 'teacher':
        return Response(
            {'error': 'Only teachers can update attendance'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        # Verify record belongs to teacher's class
        record = AttendanceRecord.objects.select_related('session').get(
            id=record_id,
            session__teacher=user
        )
    except AttendanceRecord.DoesNotExist:
        return Response(
            {'error': 'Attendance record not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    serializer = UpdateAttendanceStatusSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    new_status = serializer.validated_data['status']
    old_status = record.status
    
    record.status = new_status
    record.save()
    
    return Response({
        'message': f'Attendance updated from {old_status} to {new_status}',
        'record': TeacherAttendanceHistorySerializer(record).data
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def manual_mark_attendance(request, session_id):
    """
    Teacher manually marks attendance for a student
    POST /api/v1/sessions/{session_id}/mark-student/
    Body: {
        "student_id": 1,
        "status": "present" or "absent"
    }
    """
    user = request.user
    
    if user.role != 'teacher':
        return Response(
            {'error': 'Only teachers can manually mark attendance'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        session = AttendanceSession.objects.get(
            session_id=session_id,
            teacher=user
        )
    except AttendanceSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    student_id = request.data.get('student_id')
    new_status = request.data.get('status')
    
    if not student_id or not new_status:
        return Response(
            {'error': 'student_id and status are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if new_status not in ['present', 'absent']:
        return Response(
            {'error': 'status must be "present" or "absent"'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        student = User.objects.get(id=student_id, role='student')
    except User.DoesNotExist:
        return Response(
            {'error': 'Student not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Check if student is enrolled
    if not Enrollment.objects.filter(class_obj=session.class_obj, student=student).exists():
        return Response(
            {'error': 'Student not enrolled in this class'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Create or update attendance record
    record, created = AttendanceRecord.objects.update_or_create(
        session=session,
        student=student,
        defaults={'status': new_status}
    )
    
    action = 'marked' if created else 'updated'
    
    return Response({
        'success': True,
        'message': f'Attendance {action} as {new_status}',
        'record': {
            'id': record.id,
            'student_id': student.id,
            'student_name': student.username,
            'status': record.status,
            'marked_at': record.marked_at,
        }
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_session_attendance_details(request, session_id):
    """
    Get detailed attendance information for a specific session
    Returns session info + list of all enrolled students with their attendance status
    """
    user = request.user
    
    if user.role != 'teacher':
        return Response(
            {'error': 'Only teachers can view session attendance details'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        session = AttendanceSession.objects.select_related('class_obj').get(
            session_id=session_id,
            teacher=user
        )
    except AttendanceSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Get all enrolled students
    enrollments = Enrollment.objects.filter(
        class_obj=session.class_obj
    ).select_related('student__student_profile')
    
    # Get attendance records for this session
    attendance_records = AttendanceRecord.objects.filter(
        session=session
    ).select_related('student')
    
    # Create a map of student_id -> attendance record
    attendance_map = {record.student_id: record for record in attendance_records}
    
    # Build student list with attendance status
    students_data = []
    for enrollment in enrollments:
        student = enrollment.student
        record = attendance_map.get(student.id)
        
        try:
            roll_no = student.student_profile.roll_no
        except StudentProfile.DoesNotExist:
            roll_no = 'N/A'
        
        students_data.append({
            'id': student.id,
            'username': student.username,
            'email': student.email,
            'roll_no': roll_no,
            'status': record.status if record else 'absent',
            'marked_at': record.marked_at.isoformat() if record and record.marked_at else None,
            'record_id': record.id if record else None,
            'has_record': record is not None
        })
    
    # Calculate statistics
    total_students = len(students_data)
    present_count = sum(1 for s in students_data if s['status'] == 'present')
    absent_count = total_students - present_count
    attendance_rate = round((present_count / total_students * 100), 2) if total_students > 0 else 0
    
    return Response({
        'session': SessionSerializer(session).data,
        'students': students_data,
        'statistics': {
            'total': total_students,
            'present': present_count,
            'absent': absent_count,
            'attendance_rate': attendance_rate
        }
    })