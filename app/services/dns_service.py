import asyncio
from typing import Any

import dns.resolver
import dns.exception


RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]


async def resolve_dns(domain: str) -> dict[str, Any]:
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    async def query_type(rtype: str):
        try:
            loop = asyncio.get_event_loop()
            answer = await loop.run_in_executor(None, lambda: resolver.resolve(domain, rtype))
            records = []
            for rdata in answer:
                if rtype == "MX":
                    records.append({"priority": rdata.preference, "exchange": str(rdata.exchange)})
                elif rtype == "SOA":
                    records.append({
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum,
                    })
                else:
                    records.append(str(rdata))
            return rtype, records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return rtype, []
        except dns.exception.Timeout:
            return rtype, []
        except Exception:
            return rtype, []

    tasks = [query_type(rt) for rt in RECORD_TYPES]
    answers = await asyncio.gather(*tasks)
    for rtype, records in answers:
        results[rtype] = records

    return results
