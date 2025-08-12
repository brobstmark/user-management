#!/bin/bash
echo "Starting development environment..."
source venv/bin/activate
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
