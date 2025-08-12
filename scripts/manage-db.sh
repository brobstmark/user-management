#!/bin/bash

# Database Management Script
# Manages PostgreSQL Docker container for development

set -e  # Exit on any error

PROJECT_NAME="user-management-system"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
}

check_db_status() {
    print_status "Checking database status..."

    # Check if container exists and is running
    if docker-compose ps db | grep -q "Up"; then
        print_success "✅ Database is running"
        return 0
    elif docker-compose ps db | grep -q "Exit"; then
        print_warning "⚠️  Database container exists but is stopped"
        return 1
    else
        print_warning "⚠️  Database container does not exist"
        return 2
    fi
}

start_db() {
    print_status "Starting PostgreSQL database..."

    # Start only the database service
    docker-compose up -d db

    # Wait for database to be ready
    print_status "Waiting for database to be ready..."
    sleep 3

    # Check if it's actually running
    for i in {1..30}; do
        if docker-compose exec db pg_isready -U postgres &> /dev/null; then
            print_success "✅ Database is ready and accepting connections!"
            return 0
        fi
        echo -n "."
        sleep 1
    done

    print_error "❌ Database failed to start properly"
    return 1
}

stop_db() {
    print_status "Stopping database..."
    docker-compose stop db
    print_success "✅ Database stopped"
}

restart_db() {
    print_status "Restarting database..."
    stop_db
    sleep 2
    start_db
}

show_logs() {
    print_status "Showing database logs (press Ctrl+C to exit)..."
    docker-compose logs -f db
}

show_connection_info() {
    print_status "Database connection information:"
    echo -e "  ${GREEN}Host:${NC}     localhost"
    echo -e "  ${GREEN}Port:${NC}     5432"
    echo -e "  ${GREEN}Database:${NC} user_management"
    echo -e "  ${GREEN}Username:${NC} postgres"
    echo -e "  ${GREEN}Password:${NC} password"
    echo ""
    echo -e "  ${GREEN}Connection URL:${NC} postgresql://postgres:password@localhost:5432/user_management"
}

connect_to_db() {
    print_status "Connecting to database with psql..."
    if command -v psql &> /dev/null; then
        PGPASSWORD=password psql -h localhost -U postgres -d user_management
    else
        print_warning "psql not installed. Connecting via Docker..."
        docker-compose exec db psql -U postgres -d user_management
    fi
}

show_help() {
    echo "Database Management Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start      Start the database"
    echo "  stop       Stop the database"
    echo "  restart    Restart the database"
    echo "  status     Check database status"
    echo "  logs       Show database logs"
    echo "  connect    Connect to database with psql"
    echo "  info       Show connection information"
    echo "  help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start           # Start the database"
    echo "  $0 status          # Check if database is running"
    echo "  $0 logs            # View database logs"
}

# Main script logic
main() {
    # Check if Docker is available
    check_docker

    # Parse command line arguments
    case "${1:-status}" in
        "start")
            start_db
            ;;
        "stop")
            stop_db
            ;;
        "restart")
            restart_db
            ;;
        "status")
            check_db_status
            if [ $? -eq 0 ]; then
                show_connection_info
            fi
            ;;
        "logs")
            show_logs
            ;;
        "connect")
            connect_to_db
            ;;
        "info")
            show_connection_info
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"