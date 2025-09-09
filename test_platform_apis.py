"""
Test platform-controlled access APIs
"""
import requests
import json

BASE_URL = "http://localhost:8000/api/v1"


def test_platform_apis():
    # Test 1: Check if email exists
    print("Testing email check...")
    response = requests.get(f"{BASE_URL}/auth/check-email", params={
        "email": "brobstmark@yahoo.com"  # Use your actual email
    })
    print(f"Email check response: {response.json()}")

    # Test 2: Grant access to test platform
    # Replace the grant access test section with:
    print("\nTesting grant access...")
    response = requests.post(f"{BASE_URL}/auth/grant-access", json={
        "user_id": 4,
        "platform_id": "test-microservice",
        "platform_api_key": "test-key"
    })

    print(f"Status code: {response.status_code}")
    print(f"Response text: {response.text}")

    if response.status_code == 200:
        print(f"Grant access response: {response.json()}")
    else:
        print("Grant access failed")

    # Test 3: Check if you can now validate with platform access
    print("\nTesting validation with platform access...")
    # You'll need to be logged in for this one


if __name__ == "__main__":
    test_platform_apis()