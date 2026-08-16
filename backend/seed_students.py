import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'attend_backend.settings')
django.setup()

from attendance.models import User, Class, Enrollment, StudentProfile

# 1. Create Teacher
teacher, _ = User.objects.get_or_create(
    email='teacher@example.com',
    defaults={'username': 'teacher', 'role': 'teacher', 'first_name': 'Teacher', 'last_name': 'Account'}
)
teacher.set_password('admin123')
teacher.save()
print("Teacher account ready: teacher@example.com / admin123")

# 2. Create Admin
admin, _ = User.objects.get_or_create(
    email='admin@example.com',
    defaults={'username': 'admin', 'role': 'admin', 'is_staff': True, 'is_superuser': True}
)
admin.set_password('admin123')
admin.save()
print("Admin account ready: admin@example.com / admin123")

# 3. Create Sample Class if none exist
cls, _ = Class.objects.get_or_create(
    class_code='22cst',
    defaults={'class_name': 'full stack in java', 'semester': '5th Semester', 'teacher': teacher}
)
classes = list(Class.objects.all())
print(f"Active classes: {[c.class_code for c in classes]}")

# 4. Create 20 Students
for i in range(1, 21):
    email = f'student{i}@example.com'
    roll = f'1DA23CS{i:03d}'
    student, _ = User.objects.get_or_create(
        email=email,
        defaults={'username': f'student{i}', 'role': 'student', 'first_name': f'Student', 'last_name': str(i)}
    )
    student.set_password('admin123')
    student.save()
    StudentProfile.objects.update_or_create(student=student, defaults={'roll_no': roll})
    for c in classes:
        Enrollment.objects.update_or_create(student=student, class_obj=c, defaults={'status': 'enrolled'})

print("All 20 student accounts (student1@example.com to student20@example.com) created and enrolled!")
