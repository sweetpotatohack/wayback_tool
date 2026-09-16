from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
DATA_DIR = ROOT_DIR / "data"
AVATAR_DIR = DATA_DIR / "avatars"
SECRET_FILE = DATA_DIR / ".secret_key"
ADMIN_FILE = DATA_DIR / ".admin_credentials"
DB_FILE = DATA_DIR / "ghostindex.db"
