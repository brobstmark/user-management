#!/bin/bash

# User Management System - Project Setup Script
# Creates the complete directory structure and basic files

PROJECT_NAME="user-management"

echo "🚀 Creating User Management System project structure..."
echo "Project name: $PROJECT_NAME"



echo "📁 Creating directory structure..."

# Root level directories and files
mkdir -p {backend,frontend,tests,docs,scripts,integration}

# Backend directories
mkdir -p backend/{config,core,models,schemas,crud,api/v1,services,utils,migrations/versions}

# Frontend directories
mkdir -p frontend/{assets/{css,js,images/placeholders,icons},pages/{auth,user,admin},components/forms}

# Tests directories
mkdir -p tests/{backend,frontend,integration}

# Documentation directories
mkdir -p docs/{api,integration,deployment}

# Integration directories
mkdir -p integration/{sdk/{python/user_management_sdk,javascript/user-management-js},examples/{flask-integration,django-integration,react-integration,vue-integration}}

echo "📄 Creating Python __init__.py files..."

# Create __init__.py files for Python packages
touch backend/__init__.py
touch backend/config/__init__.py
touch backend/core/__init__.py
touch backend/models/__init__.py
touch backend/schemas/__init__.py
touch backend/crud/__init__.py
touch backend/api/__init__.py
touch backend/api/v1/__init__.py
touch backend/services/__init__.py
touch backend/utils/__init__.py
touch tests/__init__.py
touch tests/backend/__init__.py
touch tests/integration/__init__.py

echo "📝 Creating configuration files..."

# Create .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Database
*.db
*.sqlite3

# Logs
*.log
logs/

# OS
.DS_Store
Thumbs.db

# Coverage
.coverage
htmlcov/
.pytest_cache/

# Node modules (for any JS tools)
node_modules/
EOF

# Create .env.example
cat > .env.example << 'EOF'
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/user_management
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=user_management
DATABASE_USER=username
DATABASE_PASSWORD=password

# Security
SECRET_KEY=your-super-secret-key-change-this-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=your-email@gmail.com

# Redis (for session management)
REDIS_URL=redis://localhost:6379

# Environment
ENVIRONMENT=development
DEBUG=True

# CORS
ALLOWED_ORIGINS=["http://localhost:3000", "http://localhost:8080"]

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60

# Payment Processing (Stripe)
STRIPE_PUBLIC_KEY=pk_test_your_stripe_public_key
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
EOF

# Create requirements.txt
cat > requirements.txt << 'EOF'
fastapi==0.104.1
uvicorn[standard]==0.24.0
sqlalchemy==2.0.23
alembic==1.12.1
psycopg2-binary==2.9.9
pydantic[email]==2.5.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
python-decouple==3.8
redis==5.0.1
celery==5.3.4
stripe==7.8.0
jinja2==3.1.2
aiofiles==23.2.1
pytest==7.4.3
pytest-asyncio==0.21.1
httpx==0.25.2
faker==20.1.0
EOF

# Create requirements-dev.txt
cat > requirements-dev.txt << 'EOF'
-r requirements.txt
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.11.0
isort==5.12.0
flake8==6.1.0
mypy==1.7.1
pre-commit==3.6.0
httpx==0.25.2
faker==20.1.0
EOF

# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: user_management
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  backend:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/user_management
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - .:/app
    command: uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

volumes:
  postgres_data:
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

# Create alembic.ini
cat > alembic.ini << 'EOF'
[alembic]
script_location = backend/migrations
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql://username:password@localhost:5432/user_management

[post_write_hooks]

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
EOF

# Create pytest.ini
cat > pytest.ini << 'EOF'
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts =
    -v
    --tb=short
    --strict-markers
    --disable-warnings
    --cov=backend
    --cov-report=term-missing
    --cov-report=html
asyncio_mode = auto
EOF

# Create pyproject.toml
cat > pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools>=45", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "user-management-system"
version = "0.1.0"
description = "A comprehensive user management system with authentication"
authors = [{name = "Your Name", email = "your.email@example.com"}]
readme = "README.md"
requires-python = ">=3.9"
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
]

[tool.black]
line-length = 100
target-version = ['py39']
include = '\.pyi?$'

[tool.isort]
profile = "black"
line_length = 100
EOF

echo "📄 Creating basic backend files..."

# Create main.py
cat > backend/main.py << 'EOF'
"""
User Management System - FastAPI Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config.settings import settings
from backend.api.v1.router import api_router

app = FastAPI(
    title="User Management System API",
    description="A comprehensive user management system with authentication",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "User Management System API", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
EOF

# Create settings.py
cat > backend/config/settings.py << 'EOF'
"""
Application Settings and Configuration
"""
from typing import List
from pydantic_settings import BaseSettings
from decouple import config


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = config("DATABASE_URL", default="postgresql://postgres:password@localhost:5432/user_management")

    # Security
    SECRET_KEY: str = config("SECRET_KEY", default="your-super-secret-key-change-this")
    ALGORITHM: str = config("ALGORITHM", default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = config("ACCESS_TOKEN_EXPIRE_MINUTES", default=30, cast=int)

    # Environment
    ENVIRONMENT: str = config("ENVIRONMENT", default="development")
    DEBUG: bool = config("DEBUG", default=True, cast=bool)

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:8080"]

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = config("RATE_LIMIT_PER_MINUTE", default=60, cast=int)

    class Config:
        env_file = ".env"


settings = Settings()
EOF

# Create basic API router
cat > backend/api/v1/router.py << 'EOF'
"""
Main API Router for v1
"""
from fastapi import APIRouter

from backend.api.v1 import auth, users, health

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
EOF

# Create basic health endpoint
cat > backend/api/v1/health.py << 'EOF'
"""
Health Check Endpoints
"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def health_check():
    return {"status": "healthy", "service": "user-management-system"}

@router.get("/db")
async def database_health():
    # TODO: Add actual database health check
    return {"status": "healthy", "database": "connected"}
EOF

# Create placeholder auth endpoints
cat > backend/api/v1/auth.py << 'EOF'
"""
Authentication Endpoints
"""
from fastapi import APIRouter

router = APIRouter()

@router.post("/register")
async def register():
    # TODO: Implement user registration
    return {"message": "Registration endpoint - TODO"}

@router.post("/login")
async def login():
    # TODO: Implement user login
    return {"message": "Login endpoint - TODO"}

@router.post("/logout")
async def logout():
    # TODO: Implement user logout
    return {"message": "Logout endpoint - TODO"}
EOF

# Create placeholder users endpoints
cat > backend/api/v1/users.py << 'EOF'
"""
User Management Endpoints
"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/me")
async def get_current_user():
    # TODO: Get current user profile
    return {"message": "Get current user - TODO"}

@router.put("/me")
async def update_current_user():
    # TODO: Update current user profile
    return {"message": "Update current user - TODO"}
EOF

echo "🎨 Creating basic frontend files..."

# Create main HTML file
cat > frontend/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management System</title>
    <link rel="stylesheet" href="assets/css/main.css">
</head>
<body>
    <header>
        <nav>
            <h1>User Management System</h1>
            <div class="nav-links">
                <a href="pages/auth/login.html">Login</a>
                <a href="pages/auth/register.html">Register</a>
            </div>
        </nav>
    </header>

    <main>
        <section class="hero">
            <h2>Welcome to User Management System</h2>
            <p>A secure, scalable user authentication and management solution.</p>
            <div class="cta-buttons">
                <a href="pages/auth/register.html" class="btn btn-primary">Get Started</a>
                <a href="pages/auth/login.html" class="btn btn-secondary">Sign In</a>
            </div>
        </section>
    </main>

    <script src="assets/js/main.js"></script>
</body>
</html>
EOF

# Create basic CSS
cat > frontend/assets/css/main.css << 'EOF'
/* User Management System - Main Styles */

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.6;
    color: #333;
}

header {
    background-color: #2c3e50;
    color: white;
    padding: 1rem 0;
}

nav {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0 2rem;
}

.nav-links a {
    color: white;
    text-decoration: none;
    margin-left: 1rem;
}

.hero {
    text-align: center;
    padding: 4rem 2rem;
    max-width: 800px;
    margin: 0 auto;
}

.hero h2 {
    font-size: 2.5rem;
    margin-bottom: 1rem;
}

.cta-buttons {
    margin-top: 2rem;
}

.btn {
    display: inline-block;
    padding: 0.75rem 1.5rem;
    margin: 0 0.5rem;
    text-decoration: none;
    border-radius: 5px;
    font-weight: 500;
}

.btn-primary {
    background-color: #3498db;
    color: white;
}

.btn-secondary {
    background-color: #95a5a6;
    color: white;
}

.btn:hover {
    opacity: 0.9;
    transform: translateY(-1px);
}
EOF

# Create basic JavaScript
cat > frontend/assets/js/main.js << 'EOF'
/**
 * User Management System - Main JavaScript
 */

// API Base URL
const API_BASE_URL = 'http://localhost:8000/api/v1';

// Main application object
const UserManagementApp = {
    init() {
        console.log('User Management System initialized');
        this.setupEventListeners();
    },

    setupEventListeners() {
        // Add global event listeners here
        document.addEventListener('DOMContentLoaded', () => {
            console.log('DOM loaded');
        });
    },

    // API helper methods will be added here
    api: {
        async request(endpoint, options = {}) {
            const url = `${API_BASE_URL}${endpoint}`;
            const config = {
                headers: {
                    'Content-Type': 'application/json',
                },
                ...options,
            };

            try {
                const response = await fetch(url, config);
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.detail || 'Request failed');
                }

                return data;
            } catch (error) {
                console.error('API request failed:', error);
                throw error;
            }
        }
    }
};

// Initialize the application
UserManagementApp.init();
EOF

echo "📋 Creating placeholder files..."

# Create login page
cat > frontend/pages/auth/login.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - User Management System</title>
    <link rel="stylesheet" href="../../assets/css/main.css">
    <link rel="stylesheet" href="../../assets/css/auth.css">
</head>
<body>
    <div class="auth-container">
        <form class="auth-form" id="loginForm">
            <h2>Sign In</h2>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary">Sign In</button>
            <p><a href="register.html">Don't have an account? Register</a></p>
        </form>
    </div>
    <script src="../../assets/js/auth.js"></script>
</body>
</html>
EOF

# Create scripts
echo "🔧 Creating utility scripts..."

mkdir -p scripts

cat > scripts/start-dev.sh << 'EOF'
#!/bin/bash
echo "Starting development environment..."
source venv/bin/activate
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
EOF

cat > scripts/setup-dev.sh << 'EOF'
#!/bin/bash
echo "Setting up development environment..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

echo "Development environment setup complete!"
echo "Run 'source venv/bin/activate' to activate the virtual environment"
echo "Run 'scripts/start-dev.sh' to start the development server"
EOF

# Make scripts executable
chmod +x scripts/*.sh

# Create basic README
cat > README.md << 'EOF'
# User Management System

A comprehensive user management system with authentication, built with FastAPI and vanilla JavaScript.

## Features

- User registration and authentication
- Profile management
- Billing information handling
- JWT-based security
- RESTful API
- Responsive web interface

## Quick Start

1. **Setup development environment:**
   ```bash
   ./scripts/setup-dev.sh
   ```

2. **Activate virtual environment:**
   ```bash
   source venv/bin/activate
   ```

3. **Copy environment file:**
   ```bash
   cp .env.example .env
   ```

4. **Start development server:**
   ```bash
   ./scripts/start-dev.sh
   ```

5. **Visit the application:**
   - Frontend: http://localhost:8080
   - API Documentation: http://localhost:8000/docs

## Project Structure

See the complete directory structure in the repository.

## API Documentation

Once running, visit http://localhost:8000/docs for interactive API documentation.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License
EOF

echo "✅ Project structure created successfully!"
echo ""
echo "📁 Project directory: $PROJECT_NAME"
echo ""
echo "🚀 Next steps:"
echo "1. cd $PROJECT_NAME"
echo "2. ./scripts/setup-dev.sh"
echo "3. cp .env.example .env"
echo "4. Edit .env with your database credentials"
echo "5. ./scripts/start-dev.sh"
echo ""
echo "📖 Visit http://localhost:8000/docs for API documentation"
echo "🌐 Frontend will be at the location you serve from frontend/"
echo ""
echo "Happy coding! 🎉"
EOF