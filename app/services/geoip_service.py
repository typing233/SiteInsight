import os
from typing import Any

import httpx
import geoip2.database
import geoip2.errors

_reader = None
_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "GeoLite2-City.mmdb")


def _get_reader():
    global _reader
    if _reader is None:
        db_path = os.path.abspath(_DB_PATH)
        if not os.path.exists(db_path):
            return None
        _reader = geoip2.database.Reader(db_path)
    return _reader


async def _fallback_ip_api(ip: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?lang=zh-CN")
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                }
            return {"error": f"IP API returned: {data.get('message', 'unknown error')}"}
    except Exception as e:
        return {"error": f"GeoIP fallback failed: {e}"}


async def get_geoip(ip: str) -> dict[str, Any]:
    reader = _get_reader()
    if reader is None:
        return await _fallback_ip_api(ip)

    try:
        response = reader.city(ip)
        return {
            "ip": ip,
            "country": response.country.name,
            "country_code": response.country.iso_code,
            "region": response.subdivisions.most_specific.name if response.subdivisions else None,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "timezone": response.location.time_zone,
            "postal_code": response.postal.code,
        }
    except geoip2.errors.AddressNotFoundError:
        return {"error": f"No GeoIP data found for IP: {ip}"}
    except Exception as e:
        return {"error": f"GeoIP lookup failed: {e}"}
