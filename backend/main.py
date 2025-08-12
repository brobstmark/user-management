"""
User Management System - FastAPI Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from backend.config.settings import settings
from backend.api.v1.router import api_router

app = FastAPI(
    title="User Management System API",
    description="A comprehensive user management system with authentication",
    version="1.0.0",
    debug=settings.DEBUG
)

# CORS middleware with dynamic origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add config endpoint before main API router
from backend.api.config import router as config_router

app.include_router(config_router, prefix="/api", tags=["config"])

# Include API router
app.include_router(api_router, prefix="/api/v1")

# Serve frontend static files
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")


@app.get("/")
async def root():
    """Root endpoint with environment info"""
    return {
        "message": "User Management System API",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "docs": "/docs" if settings.DEBUG else None
    }


@app.get("/health")
async def health_check():
    """System health check"""
    return {
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
        "debug": settings.DEBUG,
        "version": "1.0.0"
    }


@app.exception_handler(404)
async def custom_404_handler(request, exc):
    """Custom 404 handler for SPA routing"""
    # If it's an API request, return JSON 404
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=404,
            content={"detail": "API endpoint not found"}
        )

    # For frontend routes, you might want to serve index.html for SPA routing
    # This is useful if you implement client-side routing later
    return JSONResponse(
        status_code=404,
        content={"detail": "Page not found"}
    )


# Print startup info
@app.on_event("startup")
async def startup_event():
    """Print startup information"""
    print(f"🚀 User Management System starting...")
    print(f"📍 Environment: {settings.ENVIRONMENT}")
    print(f"🌐 Allowed Origins: {', '.join(settings.ALLOWED_ORIGINS)}")
    print(f"🔧 Debug Mode: {settings.DEBUG}")
    print(f"📧 Email: {'Configured' if settings.EMAIL_USERNAME else 'Not configured'}")
    if settings.DEBUG:
        print(f"📚 API Docs: http://localhost:8000/docs")
        print(f"🎯 Frontend: http://localhost:8000/frontend/")
        print(f"⚙️ Config: http://localhost:8000/api/config")