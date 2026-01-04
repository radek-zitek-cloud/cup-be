import logging
import sys
import re
from typing import Any

# Remove all existing handlers from root logger
for h in logging.root.handlers[:]:
    logging.root.removeHandler(h)

# Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
    force=True
)

def log_info(message: str):
    """Directly print to stdout with timestamp and prefix."""
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    print(f"{timestamp} - cup-be - INFO - {message}", flush=True)

logger = logging.getLogger("cup-be")
log_info("Logging system initialized")

SENSITIVE_FIELDS = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "current_password",
    "new_password",
    "authorization",
}


def mask_sensitive_data(data: Any) -> Any:
    """
    Recursively mask sensitive fields in a dictionary or list.
    """
    if isinstance(data, dict):
        return {
            k: "***MASKED***"
            if k.lower() in SENSITIVE_FIELDS
            else mask_sensitive_data(v)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    elif isinstance(data, str):
        # Also try to mask tokens in strings (e.g. Bearer tokens)
        if any(field in data.lower() for field in ["bearer", "token"]):
            # Simple regex to mask after 'Bearer ' or similar
            return re.sub(
                r"(Bearer\s+)\S+", r"\1***MASKED***", data, flags=re.IGNORECASE
            )
    return data
