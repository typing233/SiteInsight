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


def _wrap_result(result, module_name: str) -> dict:
    """
    Strict wrapping logic:
    - Exception from gather → fail
    - dict with only an "error" key (no meaningful data) → fail
    - dict with "error" key but also meaningful data → fail with data attached
    - list where first item has "error" → fail
    - everything else → success
    """
    if isinstance(result, Exception):
        return {"success": False, "error": str(result), "data": None}

    if isinstance(result, dict):
        has_error = "error" in result
        has_data = any(k != "error" for k in result)

        if has_error and not has_data:
            return {"success": False, "error": result["error"], "data": None}

        if has_error and has_data:
            return {"success": False, "error": result["error"], "data": result}

        return {"success": True, "data": result, "error": None}

    if isinstance(result, list):
        if result and isinstance(result[0], dict) and "error" in result[0]:
            return {"success": False, "error": result[0]["error"], "data": None}
        return {"success": True, "data": result, "error": None}

    return {"success": True, "data": result, "error": None}


def _wrap_tls(result) -> dict:
    """
    TLS-specific logic:
    - Exception → fail (connection error)
    - valid=True → success
    - valid=False → fail, data still included for inspection
    """
    if isinstance(result, Exception):
        return {"success": False, "error": str(result), "data": None}

    if isinstance(result, dict):
        is_valid = result.get("valid", False)
        if is_valid:
            return {"success": True, "data": result, "error": None}
        else:
            error_msg = result.get("validation_error") or result.get("connection_error") or "证书验证失败"
            return {"success": False, "error": error_msg, "data": result}

    return {"success": True, "data": result, "error": None}


def _wrap_dns(result) -> dict:
    """
    DNS-specific: success only if we got at least one record of any type.
    """
    if isinstance(result, Exception):
        return {"success": False, "error": str(result), "data": None}

    if isinstance(result, dict):
        has_any_record = any(
            bool(records) for records in result.values()
            if isinstance(records, list)
        )
        if has_any_record:
            return {"success": True, "data": result, "error": None}
        else:
            return {"success": False, "error": "未找到任何DNS记录", "data": result}

    return {"success": True, "data": result, "error": None}


def _wrap_cookies(result) -> dict:
    """
    Cookies: list of cookies → success (even if empty means no cookies set).
    Only fail on actual errors.
    """
    if isinstance(result, Exception):
        return {"success": False, "error": str(result), "data": None}

    if isinstance(result, list):
        if result and isinstance(result[0], dict) and "error" in result[0]:
            return {"success": False, "error": result[0]["error"], "data": None}
        return {"success": True, "data": result, "error": None}

    return {"success": True, "data": result, "error": None}


def _wrap_whois(result) -> dict:
    """WHOIS: has "error" key → fail, otherwise success."""
    if isinstance(result, Exception):
        return {"success": False, "error": str(result), "data": None}

    if isinstance(result, dict) and "error" in result:
        return {"success": False, "error": result["error"], "data": None}

    return {"success": True, "data": result, "error": None}


def _wrap_geoip(result) -> dict:
    """GeoIP: has "error" key → fail, otherwise success."""
    if result is None:
        return {"success": False, "error": "无法解析IP地址，跳过GeoIP查询", "data": None}

    if isinstance(result, Exception):
        return {"success": False, "error": str(result), "data": None}

    if isinstance(result, dict) and "error" in result:
        return {"success": False, "error": result["error"], "data": None}

    return {"success": True, "data": result, "error": None}


def _wrap_performance(result) -> dict:
    """Performance: has "error" key → fail, otherwise success."""
    if isinstance(result, Exception):
        return {"success": False, "error": str(result), "data": None}

    if isinstance(result, dict) and "error" in result:
        return {"success": False, "error": result["error"], "data": None}

    return {"success": True, "data": result, "error": None}


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
    if not isinstance(dns_result, Exception) and isinstance(dns_result, dict):
        a_records = dns_result.get("A", [])
        if a_records:
            primary_ip = a_records[0]

    geoip_result = None
    if primary_ip:
        try:
            geoip_result = await get_geoip(primary_ip)
        except Exception as e:
            geoip_result = e

    return {
        "url": url,
        "domain": domain,
        "dns": _wrap_dns(dns_result),
        "tls": _wrap_tls(tls_result),
        "cookies": _wrap_cookies(cookie_result),
        "whois": _wrap_whois(whois_result),
        "geoip": _wrap_geoip(geoip_result),
        "performance": _wrap_performance(perf_result),
    }
