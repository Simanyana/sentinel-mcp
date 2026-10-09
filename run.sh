#!/bin/bash
exec python3 -m uvicorn --host 127.0.0.1 --port ${AWS_LWA_PORT:-8000} app:app
