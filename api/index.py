"""Vercel serverless entry point — imports FastAPI app"""
import sys
import os

# Add backend directory to Python path so 'app' module is importable
backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(backend_dir))

from app.main import app
