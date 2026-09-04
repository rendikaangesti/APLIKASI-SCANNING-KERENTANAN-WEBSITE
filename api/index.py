import sys
import os

# Add backend directory to sys.path so app modules can be imported
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Ensure writable SQLite path on Vercel Serverless environment
if os.getenv("VERCEL") or not os.getenv("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:////tmp/scanner.db"

# Import FastAPI app from main module
from app.main import app
