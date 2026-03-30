import os
from dotenv import load_dotenv

load_dotenv()

LAB_HOST = os.getenv("LAB_HOST", "localhost")
IOT_PORT = int(os.getenv("IOT_PORT", "9081"))
PORTAL_PORT = int(os.getenv("PORTAL_PORT", "9082"))
API_PORT = int(os.getenv("API_PORT", "9083"))

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///chainsentinel.db")
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
