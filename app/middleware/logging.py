import time
import json
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.logging import mask_sensitive_data, log_info


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        # Log request details
        method = request.method
        url = str(request.url)
        client_host = request.client.host if request.client else "unknown"

        # Mask headers
        headers = dict(request.headers)
        masked_headers = mask_sensitive_data(headers)
        headers_log = f" - Headers: {json.dumps(masked_headers)}"

        # Extract and mask body if possible
        body_log = ""
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                # We need to read the body, but doing so will consume the stream
                body = await request.body()
                if body:
                    try:
                        body_json = json.loads(body)
                        masked_body = mask_sensitive_data(body_json)
                        body_log = f" - Body: {json.dumps(masked_body)}"
                    except json.JSONDecodeError:
                        body_log = " - Body: [non-json or binary data]"

                # Replace the request body stream so it can be read again by the endpoint
                async def receive():
                    return {"type": "http.request", "body": body}

                request._receive = receive

            except Exception as e:
                log_info(f"Error reading body in logging middleware: {e}")

        log_info(
            f"Incoming request: {method} {url} from {client_host}{headers_log}{body_log}"
        )

        response = await call_next(request)

        process_time = (time.time() - start_time) * 1000
        log_info(
            f"Completed request: {method} {url} - Status: {response.status_code} - Duration: {process_time:.2f}ms"
        )

        return response
