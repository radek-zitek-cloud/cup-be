import logging
import sys
import re
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)

# Also ensure uvicorn loggers are at INFO level
for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
    logging.getLogger(logger_name).setLevel(logging.INFO)

logger = logging.getLogger("cup-be")
logger.setLevel(logging.INFO)
# Ensure it propagates to root if not already
logger.propagate = True

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
