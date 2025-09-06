#!/bin/bash

# User Management System - Database Startup Script
# This script starts the PostgreSQL database and prepares it for development

echo "🚀 Starting User Management System Database..."
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
print_status "Checking if Docker is running..."
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker Desktop first."
    exit 1
fi
print_success "Docker is running"

# Check if docker-compose.yml exists
if [ ! -f "docker-compose.yml" ]; then
    print_error "docker-compose.yml not found. Please run this script from the project root directory."
    exit 1
fi

# Stop any existing containers (in case they're in a bad state)
print_status "Stopping any existing containers..."
docker-compose down > /dev/null 2>&1

# Start the database container
print_status "Starting PostgreSQL database container..."
if docker-compose up -d db; then
    print_success "Database container started"
else
    print_error "Failed to start database container"
    exit 1
fi

# Wait for database to be ready
print_status "Waiting for database to be ready..."
max_attempts=30
attempt=1

while [ $attempt -le $max_attempts ]; do
    if docker-compose exec -T db pg_isready -U postgres > /dev/null 2>&1; then
        print_success "Database is ready!"
        break
    fi

    if [ $attempt -eq $max_attempts ]; then
        print_error "Database failed to start after $max_attempts attempts"
        print_error "Try running: docker-compose logs db"
        exit 1
    fi

    echo -n "."
    sleep 2
    ((attempt++))
done

echo ""

# Check if alembic is available
if command -v alembic > /dev/null 2>&1; then
    print_status "Running database migrations..."
    if alembic upgrade head; then
        print_success "Database migrations completed"
    else
        print_warning "Database migrations failed - you may need to run them manually"
        print_warning "Run: alembic upgrade head"
    fi
else
    print_warning "Alembic not found - skipping migrations"
    print_warning "If you have migrations to run, execute: alembic upgrade head"
fi

# Show database status
print_status "Database connection details:"
echo "  Host: localhost"
echo "  Port: 5432"
echo "  Database: user_management"
echo "  Username: postgres"
echo "  Password: password"

# Check if we can connect to the database
print_status "Testing database connection..."
if docker-compose exec -T db psql -U postgres -d user_management -c "SELECT 1;" > /dev/null 2>&1; then
    print_success "Database connection successful!"
else
    print_warning "Could not connect to user_management database"
    print_status "Creating user_management database..."
    docker-compose exec -T db createdb -U postgres user_management 2>/dev/null || true

    if docker-compose exec -T db psql -U postgres -d user_management -c "SELECT 1;" > /dev/null 2>&1; then
        print_success "Database created and connection successful!"
    else
        print_error "Failed to create or connect to database"
    fi
fi

echo ""
print_success "✅ Database startup complete!"
echo ""
print_status "Next steps:"
echo "  1. Start the FastAPI server:"
echo "     python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "  2. Access your application:"
echo "     • API Documentation: http://localhost:8000/docs"
echo "     • Frontend: http://localhost:8000/frontend/index.html"
echo "     • Login: http://localhost:8000/frontend/pages/auth/login.html"
echo "     • Register: http://localhost:8000/frontend/pages/auth/register.html"
echo ""
echo "  3. To stop the database later:"
echo "     docker-compose down"
echo ""
print_success "🎉 Ready for development!"