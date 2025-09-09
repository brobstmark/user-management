"""
Production Health Check Endpoints
"""
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from backend.config.database import get_db
from backend.config.settings import settings

router = APIRouter()

@router.get("/")
async def health_check():
    """Basic liveness check - is the service running?"""
    return {
        "status": "healthy",
        "service": "user-management-system",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": settings.ENVIRONMENT
    }

@router.get("/ready")
async def readiness_check(db: Session = Depends(get_db)):
    """Comprehensive readiness check - is the service ready to handle requests?"""
    checks = {}
    overall_status = "healthy"

    # Database connectivity check
    try:
        start_time = time.time()
        result = db.execute(text("SELECT 1")).fetchone()
        db_response_time = round((time.time() - start_time) * 1000, 2)

        checks["database"] = {
            "status": "healthy" if result else "unhealthy",
            "response_time_ms": db_response_time
        }

        if not result or db_response_time > 1000:  # > 1 second is concerning
            overall_status = "degraded"

    except Exception as e:
        checks["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        overall_status = "unhealthy"

    # Database migrations check
    try:
        # Check if critical tables exist
        tables_result = db.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('users', 'platforms', 'rate_limits')
        """)).fetchall()

        expected_tables = {'users', 'platforms', 'rate_limits'}
        found_tables = {row[0] for row in tables_result}

        if expected_tables.issubset(found_tables):
            checks["migrations"] = {"status": "healthy"}
        else:
            missing = expected_tables - found_tables
            checks["migrations"] = {
                "status": "unhealthy",
                "missing_tables": list(missing)
            }
            overall_status = "unhealthy"

    except Exception as e:
        checks["migrations"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        overall_status = "unhealthy"

    # Email service check (if configured)
    if settings.EMAIL_USERNAME:
        try:
            # Basic email config validation
            checks["email"] = {
                "status": "healthy",
                "configured": True,
                "host": settings.EMAIL_HOST,
                "port": settings.EMAIL_PORT
            }
        except Exception as e:
            checks["email"] = {
                "status": "degraded",
                "error": str(e)
            }
    else:
        checks["email"] = {
            "status": "disabled",
            "configured": False
        }

    # Configuration validation
    config_issues = []
    if settings.SECRET_KEY == "your-super-secret-key-change-this":
        config_issues.append("default_secret_key")

    if settings.ENVIRONMENT == "production" and settings.DEBUG:
        config_issues.append("debug_enabled_in_production")

    checks["configuration"] = {
        "status": "healthy" if not config_issues else "degraded",
        "issues": config_issues
    }

    if config_issues and settings.ENVIRONMENT == "production":
        overall_status = "degraded"

    # System resources (basic)
    checks["system"] = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    response = {
        "status": overall_status,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Return appropriate HTTP status code
    if overall_status == "unhealthy":
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=response
        )
    elif overall_status == "degraded":
        return HTTPException(
            status_code=status.HTTP_200_OK,  # Still accepting traffic but with warnings
            detail=response
        )

    return response

@router.get("/db")
async def database_health(db: Session = Depends(get_db)):
    """Detailed database health check"""
    try:
        start_time = time.time()

        # Test basic connectivity
        db.execute(text("SELECT 1")).fetchone()
        basic_response_time = round((time.time() - start_time) * 1000, 2)

        # Test write capability (with rollback)
        start_time = time.time()
        db.execute(text("CREATE TEMP TABLE health_check_test (id INT)"))
        db.execute(text("INSERT INTO health_check_test VALUES (1)"))
        db.execute(text("SELECT * FROM health_check_test"))
        db.rollback()  # Clean up
        write_response_time = round((time.time() - start_time) * 1000, 2)

        # Get connection info
        connection_info = db.execute(text("""
            SELECT 
                current_database() as database_name,
                current_user as current_user,
                version() as version
        """)).fetchone()

        # Get table counts
        table_counts = {}
        for table in ['users', 'platforms', 'rate_limits']:
            try:
                count_result = db.execute(text(f"SELECT COUNT(*) FROM {table}")).fetchone()
                table_counts[table] = count_result[0] if count_result else 0
            except:
                table_counts[table] = "error"

        return {
            "status": "healthy",
            "database_name": connection_info[0] if connection_info else "unknown",
            "user": connection_info[1] if connection_info else "unknown",
            "version": connection_info[2] if connection_info else "unknown",
            "performance": {
                "read_response_time_ms": basic_response_time,
                "write_response_time_ms": write_response_time
            },
            "table_counts": table_counts,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

@router.get("/metrics")
async def basic_metrics(db: Session = Depends(get_db)):
    """Basic application metrics for monitoring"""
    try:
        # Get user statistics
        user_stats = db.execute(text("""
            SELECT 
                COUNT(*) as total_users,
                COUNT(*) FILTER (WHERE is_verified = true) as verified_users,
                COUNT(*) FILTER (WHERE is_active = true) as active_users,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as users_last_24h
            FROM users
        """)).fetchone()

        # Get rate limiting statistics
        rate_limit_stats = db.execute(text("""
            SELECT 
                COUNT(*) as active_rate_limits,
                COUNT(DISTINCT ip_address) as unique_ips_rate_limited
            FROM rate_limits 
            WHERE expires_at > NOW()
        """)).fetchone()

        # Get platform statistics
        platform_stats = db.execute(text("""
            SELECT 
                COUNT(*) as total_platforms
            FROM platforms
        """)).fetchone()

        return {
            "users": {
                "total": user_stats[0] if user_stats else 0,
                "verified": user_stats[1] if user_stats else 0,
                "active": user_stats[2] if user_stats else 0,
                "registered_last_24h": user_stats[3] if user_stats else 0
            },
            "rate_limiting": {
                "active_limits": rate_limit_stats[0] if rate_limit_stats else 0,
                "unique_ips_limited": rate_limit_stats[1] if rate_limit_stats else 0
            },
            "platforms": {
                "total": platform_stats[0] if platform_stats else 0
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        return {
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }