#!/bin/bash
set -e
echo "Running init_db..."
python -m iam_guardian.init_db
echo "Starting server..."
uvicorn iam_guardian.main:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1