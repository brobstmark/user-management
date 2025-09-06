# 🏆 User Management System - Enterprise Edition

**Production-ready user management system with FastAPI backend, PostgreSQL database, and enterprise-grade frontend featuring true httpOnly cookie authentication, secure logging, and professional deployment infrastructure.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue.svg)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docker.com)

## 🚀 **Enterprise Features**

### **🛡️ Maximum Security Architecture**
- **HttpOnly Cookie Authentication** - XSS-immune token storage
- **CSRF Protection** - Automatic token management for state-changing requests
- **Content Security Policy** - Comprehensive XSS/injection protection
- **PII Redaction Logging** - Secure audit trails with privacy protection
- **Rate Limiting** - API endpoint protection against abuse
- **Security Headers** - Frame protection, MIME-sniffing prevention

### **📧 Production Email Infrastructure**
- **Real Gmail SMTP Integration** - Production-ready email delivery
- **Email Verification Workflow** - Secure account activation
- **Password Reset System** - Secure password recovery with time-limited tokens
- **Username Recovery** - Account recovery via email
- **HTML & Text Email Templates** - Professional communication

### **🗄️ Enterprise Database Management**
- **PostgreSQL with Docker** - Containerized database with persistent storage
- **Alembic Migrations** - Version-controlled schema management
- **Connection Pooling** - Optimized database performance
- **Database Scripts** - Automated container management

### **🏗️ Professional Architecture**
- **Separation of Concerns** - Clean HTML/CSS/JavaScript separation
- **Environment-Aware Configuration** - Dev/staging/production ready
- **Comprehensive Logging** - API, security, and audit logging
- **Docker Deployment** - Production containerization
- **Static File Serving** - Integrated frontend hosting

## 📁 **Project Structure**

```
user-management-system/
├── backend/                    # FastAPI Application
│   ├── api/v1/                # API Routes
│   ├── config/                # Environment & Settings
│   ├── core/                  # Security Middleware
│   ├── models/                # Database Models
│   ├── utils/                 # Logging & Utilities
│   └── main.py               # Application Entry Point
├── frontend/                  # Enterprise Frontend
│   ├── assets/
│   │   ├── css/              # Styled Components
│   │   └── js/               # Secure JavaScript Modules
│   └── pages/
│       ├── auth/             # Authentication Pages
│       └── user/             # User Dashboard
├── scripts/                   # Development Scripts
│   ├── manage-db.sh          # Database Management
│   ├── start-database.sh     # Database Setup
│   └── setup-dev.sh          # Environment Setup
├── docker-compose.yml         # Container Orchestration
├── Dockerfile                # Application Container
├── alembic.ini               # Database Migrations
└── pyproject.toml            # Python Project Configuration
```

## 🚀 **Quick Start**

### **Prerequisites**
- Python 3.11+
- Docker & Docker Compose
- Git

### **1. Clone & Setup**
```bash
git clone <your-repo-url>
cd user-management-system

# Setup development environment
./scripts/setup-dev.sh
source venv/bin/activate
```

### **2. Configure Environment**
```bash
# Copy and customize environment settings
cp .env.example .env

# Edit .env with your settings:
# - Database credentials
# - Email configuration (Gmail SMTP)
# - Security keys
```

### **3. Start Database**
```bash
# Start PostgreSQL in Docker
./scripts/start-database.sh

# Or use the management script
./scripts/manage-db.sh start
```

### **4. Install Dependencies**
```bash
pip install -r requirements.txt

# Optional: Install development tools
pip install alembic pytest black isort
```

### **5. Run Database Migrations**
```bash
# Setup database schema
alembic upgrade head
```

### **6. Start Application**
```bash
# Start FastAPI server
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### **7. Access Your Application**
- **Frontend**: http://localhost:8000/frontend/index.html
- **Login**: http://localhost:8000/frontend/pages/auth/login.html
- **Register**: http://localhost:8000/frontend/pages/auth/register.html
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 🐳 **Docker Deployment**

### **Development with Docker Compose**
```bash
# Start all services (database + app)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### **Production Container**
```bash
# Build production image
docker build -t user-management-system .

# Run container
docker run -p 8000:8000 user-management-system
```

## 🔧 **Database Management**

### **Development Scripts**
```bash
# Start database
./scripts/manage-db.sh start

# Check status
./scripts/manage-db.sh status

# Connect to database
./scripts/manage-db.sh connect

# View logs
./scripts/manage-db.sh logs

# Stop database
./scripts/manage-db.sh stop
```

### **Migration Management**
```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

## 📧 **Email Configuration**

### **Gmail SMTP Setup**
1. Enable 2-Factor Authentication on Gmail
2. Generate App Password: Account → Security → App Passwords
3. Configure in `.env`:
   ```bash
   EMAIL_HOST=smtp.gmail.com
   EMAIL_PORT=587
   EMAIL_USE_TLS=true
   EMAIL_USERNAME=your-email@gmail.com
   EMAIL_PASSWORD=your-app-password
   EMAIL_FROM=your-email@gmail.com
   ```

## 🔐 **Security Features**

### **Authentication Security**
- **HttpOnly Cookies**: JavaScript-inaccessible authentication tokens
- **CSRF Protection**: Automatic cross-site request forgery prevention
- **Session Management**: Server-side authentication verification
- **Secure Headers**: Content Security Policy, frame protection

### **Data Protection**
- **PII Redaction**: Personal information automatically redacted from logs
- **Secure Logging**: Comprehensive audit trails with privacy protection
- **Input Sanitization**: Automatic XSS and injection prevention
- **Rate Limiting**: API abuse protection

## 📊 **API Endpoints**

### **Authentication**
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `GET /api/v1/auth/verification-status` - Check verification status

### **Password Management**
- `POST /api/v1/auth/forgot-password` - Request password reset
- `POST /api/v1/auth/reset-password` - Reset password with token
- `POST /api/v1/auth/forgot-username` - Username recovery

### **User Management**
- `GET /api/v1/users/me` - Current user profile
- `PUT /api/v1/users/me` - Update user profile

### **Configuration**
- `GET /api/config` - Frontend configuration

## 🧪 **Development**

### **Code Quality**
```bash
# Format code
black backend/
isort backend/

# Run tests
pytest

# Type checking
mypy backend/
```

### **Logging**
- **API Logging**: Request/response tracking
- **Security Logging**: Authentication attempts, suspicious activity
- **Audit Logging**: User actions, system events
- **Error Logging**: Application errors with correlation IDs

## 🚀 **Deployment**

### **Environment Configurations**
- **Development**: Debug enabled, verbose logging
- **Staging**: Production-like with extended logging
- **Production**: Optimized security, minimal debug output

### **Environment Variables**
```bash
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=your-super-secure-secret-key
DATABASE_URL=postgresql://user:pass@host:5432/db
EMAIL_USERNAME=your-production-email@domain.com
```

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes with tests
4. Run code quality checks: `black .` and `pytest`
5. Commit changes: `git commit -m 'Add amazing feature'`
6. Push to branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## 📝 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 **Enterprise Ready**

This system meets enterprise security standards with:
- ✅ **Maximum Authentication Security** (httpOnly cookies)
- ✅ **Production Email Infrastructure** (Gmail SMTP)
- ✅ **Comprehensive Security Logging** (PII redaction)
- ✅ **Container Deployment** (Docker/Docker Compose)
- ✅ **Database Migrations** (Alembic)
- ✅ **Professional Architecture** (Separation of concerns)

**Ready for production deployment with zero security compromises.** 🛡️