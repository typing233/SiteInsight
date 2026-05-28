import time
from typing import Any

import httpx


async def measure_performance(url: str) -> dict[str, Any]:
    result = {}
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=15.0,
            verify=False,
        ) as client:
            start = time.perf_counter()
            response = await client.get(url)
            total_time = time.perf_counter() - start

            headers_raw = b""
            for name, value in response.headers.raw:
                headers_raw += name + b": " + value + b"\r\n"

            result["status_code"] = response.status_code
            result["total_time_ms"] = round(total_time * 1000, 2)
            result["response_headers_size_bytes"] = len(headers_raw)
            result["content_length"] = int(response.headers.get("content-length", 0)) or len(response.content)
            result["url_final"] = str(response.url)
            result["redirects"] = len(response.history)
            result["http_version"] = response.http_version
            result["server"] = response.headers.get("server", "N/A")
            result["content_type"] = response.headers.get("content-type", "N/A")

    except httpx.TimeoutException:
        result["error"] = "Request timed out (15s limit)"
    except httpx.ConnectError as e:
        result["error"] = f"Connection failed: {e}"
    except Exception as e:
        result["error"] = f"Performance measurement failed: {e}"

    return result
