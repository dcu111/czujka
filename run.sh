#!/usr/bin/env bash
set -e
python -m pip install -r requirements.txt
echo ""
echo "Czujka startuje na http://localhost:8000"
uvicorn app:app --port 8000
