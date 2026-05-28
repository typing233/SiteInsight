import asyncio
from typing import Any

import whois


async def get_whois(domain: str) -> dict[str, Any]:
    loop = asyncio.get_event_loop()
    try:
        w = await loop.run_in_executor(None, whois.whois, domain)
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}

    if not w or not w.domain_name:
        return {"error": "No WHOIS data available for this domain"}

    result = {}

    def safe_str(val):
        if val is None:
            return None
        if isinstance(val, list):
            return [str(v) for v in val]
        return str(val)

    result["domain_name"] = safe_str(w.domain_name)
    result["registrar"] = safe_str(w.registrar)
    result["creation_date"] = safe_str(w.creation_date)
    result["expiration_date"] = safe_str(w.expiration_date)
    result["updated_date"] = safe_str(w.updated_date)
    result["name_servers"] = safe_str(w.name_servers)
    result["status"] = safe_str(w.status)
    result["registrant"] = safe_str(getattr(w, "name", None))
    result["org"] = safe_str(getattr(w, "org", None))
    result["country"] = safe_str(getattr(w, "country", None))

    return result
