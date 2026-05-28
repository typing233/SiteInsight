import asyncio
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.utils.helpers import normalize_url, extract_domain
from app.services.dns_service import resolve_dns
from app.services.tls_service import get_tls_info
from app.services.cookie_service import get_cookies
from app.services.whois_service import get_whois
from app.services.geoip_service import get_geoip
from app.services.performance_service import measure_performance

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


class AnalyzeRequest(BaseModel):
    url: str


class ModuleResult(BaseModel):
    success: bool
    data: Any = None
    error: str | None = None


@router.post("/api/analyze")
@limiter.limit("10/minute")
async def analyze(request: Request, body: AnalyzeRequest):
    url = normalize_url(body.url)
    domain = extract_domain(url)

    if not domain:
        return {"error": "Invalid URL provided"}

    dns_task = resolve_dns(domain)
    tls_task = get_tls_info(domain)
    cookie_task = get_cookies(url)
    whois_task = get_whois(domain)
    perf_task = measure_performance(url)

    results = await asyncio.gather(
        dns_task, tls_task, cookie_task, whois_task, perf_task,
        return_exceptions=True,
    )

    dns_result, tls_result, cookie_result, whois_result, perf_result = results

    primary_ip = None
    if not isinstance(dns_result, Exception) and dns_result.get("A"):
        primary_ip = dns_result["A"][0]

    geoip_result = None
    if primary_ip:
        geoip_result = await get_geoip(primary_ip)

    def wrap(result) -> dict:
        if isinstance(result, Exception):
            return {"success": False, "error": str(result)}
        if isinstance(result, dict) and "error" in result:
            return {"success": False, "error": result["error"], "data": result}
        return {"success": True, "data": result}

    response = {
        "url": url,
        "domain": domain,
        "dns": wrap(dns_result),
        "tls": wrap(tls_result),
        "cookies": wrap(cookie_result) if not isinstance(cookie_result, list) or (cookie_result and "error" in cookie_result[0]) else {"success": True, "data": cookie_result},
        "whois": wrap(whois_result),
        "geoip": wrap(geoip_result) if geoip_result else {"success": False, "error": "No IP address resolved for GeoIP lookup"},
        "performance": wrap(perf_result),
    }

    return response
