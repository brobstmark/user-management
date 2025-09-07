"""
Add test platform to database
"""
from backend.config.database import SessionLocal
from backend.models.platforms import Platform


def add_test_platform():
    db = SessionLocal()

    # Add test platform
    test_platform = Platform(
        id="test-microservice",
        name="Test Microservice",
        domain="localhost:8000",
        is_active=True
    )

    db.add(test_platform)
    db.commit()
    print("Test platform added!")
    db.close()


if __name__ == "__main__":
    add_test_platform()