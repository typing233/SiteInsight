from typing import Any

import httpx


async def get_cookies(url: str) -> list[dict[str, Any]]:
    cookies = []
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            verify=False,
        ) as client:
            response = await client.get(url)
            raw_cookies = response.headers.get_list("set-cookie")

            for raw in raw_cookies:
                parsed = _parse_set_cookie(raw)
                if parsed:
                    cookies.append(parsed)
    except httpx.TimeoutException:
        return [{"error": "Request timed out"}]
    except Exception as e:
        return [{"error": str(e)}]

    return cookies


def _parse_set_cookie(header: str) -> dict[str, Any] | None:
    if not header:
        return None

    parts = header.split(";")
    if not parts:
        return None

    name_value = parts[0].strip()
    if "=" not in name_value:
        return None

    name, value = name_value.split("=", 1)
    cookie = {
        "name": name.strip(),
        "value": value.strip(),
        "attributes": {},
    }

    for part in parts[1:]:
        part = part.strip()
        if "=" in part:
            attr_name, attr_value = part.split("=", 1)
            cookie["attributes"][attr_name.strip().lower()] = attr_value.strip()
        else:
            cookie["attributes"][part.lower()] = True

    return cookie
