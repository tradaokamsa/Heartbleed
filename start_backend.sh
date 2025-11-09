#!/bin/bash
# Start the FastAPI backend server

echo "Starting Heartbleed Demo Backend..."
echo "Backend will be available at http://localhost:8000"
echo "API docs will be available at http://localhost:8000/docs"
echo ""
uvicorn backend:app --reload --host 0.0.0.0 --port 8000

