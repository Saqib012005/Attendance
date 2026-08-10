<div align="center">
  
# 🎓 Attendance Management System

**A next-generation, seamless, and lightning-fast attendance tracking ecosystem.**

Built with **Django REST Framework** (Backend) and **Flutter** (Frontend), utilizing **PostgreSQL**, **Docker**, and modern **App Links / Deep Linking** to deliver a frictionless experience for both teachers and students.

</div>

---

## ✨ Features That Wow

### 👨‍🏫 For Teachers (The Command Center)
- **Instant Class Creation:** Generate and manage multiple classes with ease.
- **One-Click Joining Links:** Share a smart deep link (e.g., via WhatsApp) that instantly opens the app and enrolls students without them needing to type a code!
- **Dynamic QR Sessions:** Generate cryptographically secure QR codes for attendance sessions with real-time countdowns.
- **Live Analytics:** Watch attendance roll in live as students scan, and export detailed reports.
- **Full Enrollment Control:** Manually add, remove, or monitor student enrollments from your dashboard.

### 👩‍🎓 For Students (Frictionless UX)
- **Deep Link Magic:** Click a teacher's WhatsApp link, instantly bypass the login screen (if already logged in), and securely join the class directly inside the app.
- **Zero-Latency QR Scanning:** Mark attendance in milliseconds by scanning live session codes.
- **Smart Routing:** Rock-solid cold-start routing utilizing `SharedPreferences` guarantees you never get unexpectedly logged out when launching from external links.
- **Real-Time Status:** Instantly verify your attendance history and current class statuses.

### 🔐 Security & Infrastructure
- **Bulletproof Auth:** JWT-based authentication paired with Android Keystore/Flutter Secure Storage.
- **SingleTask Launch Mode:** Prevents multi-instance Android ghosting bugs, ensuring deep links always route perfectly to the active dashboard.
- **Role-Based Access Control (RBAC):** Strict boundaries between Student, Teacher, and Admin privileges.

---

## 🛠 Tech Stack

### Backend (The Brain)
- **Framework**: Django 5.2.7 + Django REST Framework 3.16.1
- **Database**: PostgreSQL 15
- **Authentication**: SimpleJWT (JSON Web Tokens)
- **QR Generation**: qrcode 7.4.2 + Pillow 10.4.0

### Frontend (The Beauty)
- **Framework**: Flutter 3.x (Material 3 Design)
- **State & Routing**: Custom intelligent deep link routing with `app_links`
- **Networking**: Dio with interceptors
- **Storage**: Hybrid `Flutter Secure Storage` (for tokens) + `SharedPreferences` (for robust OS routing)
- **Scanning**: qr_flutter & mobile_scanner

### DevOps (The Engine)
- **Containerization**: Docker & Docker Compose
- **Database Management**: pgAdmin 4
- **Hosting / CI**: Ready for zero-downtime deployment on **Railway** (`.up.railway.app`)

---

## 🚀 Quick Start Guide

### 1. Clone the Repository
```bash
git clone https://github.com/VIZZARD-X/Attendance.git
cd Attendance
```

### 2. Backend & Docker Setup
```bash
# Create Environment File
cp backend/.env.example backend/.env

# Build and start all services
docker-compose up -d --build

# Run Database Migrations
docker-compose exec web python manage.py makemigrations
docker-compose exec web python manage.py migrate

# Create Admin User (Follow prompts)
docker-compose exec web python manage.py createsuperuser
```
*Your backend is now running at `http://localhost:8000/api/v1/ping/` and pgAdmin at `http://localhost:5050/`.*

### 3. Frontend Setup
```bash
cd frontend/attendance_app

# Install Dependencies
flutter pub get

# Run on Android Emulator or connected device
flutter run -d android
```

---

## 📱 Mobile Deep Linking (App Links) Architecture

This project implements a highly advanced Android Intent routing system designed to bypass common Flutter routing pitfalls:

1. **`AndroidManifest.xml` Tuning:** Utilizes `android:launchMode="singleTask"` to prevent duplicate instances when opening external links.
2. **Native Interception Override:** Explicitly disables Flutter's default deep linking (`flutter_deeplinking_enabled="false"`) to prevent the Flutter engine from overriding manual URI parsing and mistakenly throwing the user to an `onUnknownRoute` login screen.
3. **Stateful App Links:** Employs the `app_links` package inside `StudentDashboard` to silently and seamlessly join classes in the background without interrupting the user's UI flow.
4. **Fallback Web Routing:** If the App Link domain verification fails (e.g., missing `assetlinks.json`), the backend automatically serves a polished fallback HTML page that bounces the user into the app via a custom scheme (`attendapp://join/`).

---

## 🏗 Project Architecture

```text
Attendance/
├── backend/                          # Django REST API
│   ├── attend_backend/               # Settings & URL config
│   ├── attendance/                   # Core App Models (User, Class, Sessions)
│   ├── Dockerfile                    # Container instructions
│   └── requirements.txt              # Dependencies
│
├── frontend/attendance_app/          # Flutter Client
│   ├── android/                      # Native Android config (Manifest, Intents)
│   ├── lib/                          
│   │   ├── config/api_config.dart    # Centralized endpoint management
│   │   ├── screens/                  # Auth, Dashboards, Scanner
│   │   └── services/                 # Dio Networking & Hybrid Storage
│   └── pubspec.yaml                  # Flutter dependencies
│
└── docker-compose.yml                # Full stack orchestration
```

---

## 🔒 Security Notes for Production (Railway Deployment)

When deploying to platforms like **Railway**:
1. **Domain Verification:** Ensure `.well-known/assetlinks.json` is correctly hosted on the Django backend with the exact SHA256 fingerprint of your release Keystore for native App Links to function without showing the browser fallback.
2. **Environment Variables:** Never commit `.env`. Set `SECRET_KEY`, `DATABASE_URL`, and `DJANGO_DEBUG=False` directly in the Railway dashboard.
3. **CORS:** Update `CORS_ALLOWED_ORIGINS` in `settings.py` to match your frontend domains.

---

## 🤝 Contributing

We welcome contributions to make this ecosystem even better! 
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

<div align="center">
  <i>Built with passion by the Vizzard Team and Sujan Bhat</i>
</div>
