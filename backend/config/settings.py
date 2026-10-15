"""
Pipeline Configuration Settings
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data alert"
RULES_DIR = BASE_DIR / "ruleset" / "rules"
LISTS_DIR = BASE_DIR / "ruleset" / "lists"
REPORTS_DIR = BASE_DIR / "reports"

# Database connection defaults
# Load .env file if available
env_file = BASE_DIR / ".env"
if env_file.exists():
    try:
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
    except Exception:
        pass

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "wazuh_soc_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_MINCONN = int(os.getenv("DB_MINCONN", "2"))
DB_MAXCONN = int(os.getenv("DB_MAXCONN", "30"))
DB_SYNCHRONOUS_COMMIT = os.getenv("DB_SYNCHRONOUS_COMMIT", "off")


# API Security Settings
SOC_API_KEY = os.getenv("SOC_API_KEY", "wazuh-soc-secure-key-2026")
raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000")
ALLOWED_ORIGINS = [o.strip() for o in raw_origins.split(",") if o.strip()]

# Streaming & Evasion Defense settings
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "10000"))
DEDUP_WINDOW_SECONDS = int(os.getenv("DEDUP_WINDOW_SECONDS", "900"))  # 15 mins
CORRELATION_WINDOW_SECONDS = int(os.getenv("CORRELATION_WINDOW_SECONDS", "1800"))  # 30 mins
LOW_AND_SLOW_THRESHOLD = int(os.getenv("LOW_AND_SLOW_THRESHOLD", "15"))  # Cumulative threshold
LOW_AND_SLOW_WINDOW_HOURS = int(os.getenv("LOW_AND_SLOW_WINDOW_HOURS", "6"))  # 6-hour evaluation window

# Simulated / Fallback Model Detection
# Model name substrings that indicate a verdict came from a heuristic fallback
# or offline simulation, NOT from a real trained model or live LLM API.
# Verdicts from these sources are excluded from ground_truth_dataset to prevent
# model drift and contaminated confusion matrices.
SIMULATED_MODEL_PATTERNS = [
    s.strip().lower()
    for s in os.getenv(
        "SIMULATED_MODEL_PATTERNS",
        "simulated,heuristic-fallback,LightGBM-Fallback"
    ).split(",")
    if s.strip()
]

# In-Flight State Persistence
PERSISTENCE_DIR = BASE_DIR / os.getenv("PERSISTENCE_DIR", "config/state")
PERSISTENCE_DIR.mkdir(parents=True, exist_ok=True)

# Collector / SIEM infrastructure hostnames to ignore when resolving actor/target entities.
# Override via comma-separated IGNORED_COLLECTOR_HOSTS env var.
_default_ignored = "wazuh_soc,manager,wazuh-remoted,localhost,127.0.0.1,none,unknown"
IGNORED_COLLECTOR_HOSTS = frozenset(
    h.strip().lower()
    for h in os.getenv("IGNORED_COLLECTOR_HOSTS", _default_ignored).split(",")
    if h.strip()
)

# Tier-2 Local / Private LLM Settings (Ollama)
LOCAL_LLM_URL = os.getenv("LOCAL_LLM_URL", "http://192.168.30.178:11434")
_raw_local_model = os.getenv("LOCAL_LLM_MODEL", "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:latest")
LOCAL_LLM_MODEL = "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:latest" if _raw_local_model in ("qwen2.5-coder:7B", "qwen2.5:14b-instruct-q4_K_M", "") else _raw_local_model
LOCAL_LLM_TIMEOUT = int(os.getenv("LOCAL_LLM_TIMEOUT", "60"))
LOCAL_LLM_CONFIDENCE_THRESHOLD = float(os.getenv("LOCAL_LLM_CONFIDENCE_THRESHOLD", "85.0"))

# Tier-3 Cloud LLM Settings (Google Gemini)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", os.getenv("GOOGLE_API_KEY", ""))
_raw_cloud_model = os.getenv("CLOUD_LLM_MODEL", "gemini-3-flash-preview")
CLOUD_LLM_MODEL = "gemini-3-flash-preview" if _raw_cloud_model in ("gemini-3.5-flash", "gemini-flash-latest", "") else _raw_cloud_model
CLOUD_LLM_TIMEOUT = int(os.getenv("CLOUD_LLM_TIMEOUT", "30"))
CLOUD_LLM_CONFIDENCE_THRESHOLD = float(os.getenv("CLOUD_LLM_CONFIDENCE_THRESHOLD", "85.0"))

# Active Learning Ground Truth Settings
AUTO_GT_CONFIDENCE_FLOOR = float(os.getenv("AUTO_GT_CONFIDENCE_FLOOR", "95.0"))


