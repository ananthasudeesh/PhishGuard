

#!/bin/bash

set -e

cd "$HOME/PhishGuard"

echo "Starting PhishGuard..."

# Activate Python virtual environment
source .venv/bin/activate

# Set Python module path
export PYTHONPATH="$PWD/src"

# Start FastAPI backend
python -m uvicorn backend.main:app \
    --reload \
    --host 127.0.0.1 \
    --port 8000 &

BACKEND_PID=$!

# Stop backend when exiting
cleanup() {
    kill "$BACKEND_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Start frontend
cd "$HOME/PhishGuard/frontend"

# Open UI automatically
(sleep 5; xdg-open http://localhost:5173) &

npm run dev
