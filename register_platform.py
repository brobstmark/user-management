#!/usr/bin/env python3
"""
Platform Registration Script - CLI for Development
"""
import secrets
import hashlib
import re
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.models.platforms import Platform
from backend.config.settings import settings


def generate_api_key() -> str:
    """Generate a secure API key"""
    return f"pk_{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    """Hash API key for storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_platform_id(name: str) -> str:
    """Generate platform ID from name (e.g., 'Test Game' -> 'test-game')"""
    return re.sub(r'[^a-zA-Z0-9]+', '-', name.lower()).strip('-')


def create_db_session():
    """Create database session"""
    engine = create_engine(settings.DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()


def register_platform(name: str, domain: str):
    """Register a new platform"""
    platform_id = generate_platform_id(name)
    api_key = generate_api_key()
    api_key_hash = hash_api_key(api_key)

    db = create_db_session()

    try:
        # Check if already exists
        if db.query(Platform).filter(Platform.id == platform_id).first():
            print(f"❌ Platform ID '{platform_id}' already exists")
            return None, None

        if db.query(Platform).filter(Platform.domain == domain).first():
            print(f"❌ Domain '{domain}' already registered")
            return None, None

        # Create platform
        platform = Platform(
            id=platform_id,
            name=name,
            domain=domain,
            api_key=api_key_hash,
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        db.add(platform)
        db.commit()

        print("✅ Platform registered!")
        print(f"📝 ID: {platform_id}")
        print(f"📝 Name: {name}")
        print(f"📝 Domain: {domain}")
        print(f"\n🔑 API Key (save this):")
        print(f"   {api_key}")

        return platform_id, api_key

    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
        return None, None
    finally:
        db.close()


def list_platforms():
    """List all platforms"""
    db = create_db_session()
    try:
        platforms = db.query(Platform).all()
        if not platforms:
            print("📭 No platforms registered")
            return

        print("\n📋 Platforms:")
        for p in platforms:
            status = "🟢" if p.is_active else "🔴"
            print(f"{status} {p.id} - {p.name} ({p.domain})")
    finally:
        db.close()


def main():
    """Main CLI"""
    print("🔧 Platform Registration (Dev)")

    while True:
        print("\n1. Register platform")
        print("2. List platforms")
        print("3. Exit")

        choice = input("Choice: ").strip()

        if choice == "1":
            name = input("Platform name: ").strip()
            domain = input("Domain: ").strip()
            if name and domain:
                register_platform(name, domain)
        elif choice == "2":
            list_platforms()
        elif choice == "3":
            break


if __name__ == "__main__":
    main()