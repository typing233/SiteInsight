import asyncio
import ssl
import socket
from typing import Any
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID


async def get_tls_info(hostname: str, port: int = 443) -> dict[str, Any]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_tls_sync, hostname, port)


def _get_tls_sync(hostname: str, port: int) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        ctx_noverify = ssl.create_default_context()
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx_noverify.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert() or {}
        except Exception:
            return {"error": f"SSL error: {e}", "valid": False}
        return _parse_cert(cert_der, cert_dict, valid=False, reason=str(e))
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return {"error": f"Connection failed: {e}"}

    return _parse_cert(cert_der, cert_dict, valid=True)


def _parse_cert(cert_der: bytes, cert_dict: dict, valid: bool, reason: str = "") -> dict[str, Any]:
    result = {"valid": valid}
    if reason:
        result["validation_error"] = reason

    try:
        cert = x509.load_der_x509_certificate(cert_der)

        result["subject"] = _name_to_dict(cert.subject)
        result["issuer"] = _name_to_dict(cert.issuer)
        result["serial_number"] = format(cert.serial_number, "x")
        result["not_before"] = cert.not_valid_before_utc.isoformat()
        result["not_after"] = cert.not_valid_after_utc.isoformat()
        result["signature_algorithm"] = cert.signature_algorithm_oid._name

        now = datetime.now(timezone.utc)
        result["expired"] = now > cert.not_valid_after_utc
        result["not_yet_valid"] = now < cert.not_valid_before_utc

        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            result["san"] = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            result["san"] = []

        if cert.signature_hash_algorithm:
            result["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex(":")
    except Exception as e:
        result["parse_error"] = str(e)

    if cert_dict:
        result["subject_alt_from_dict"] = cert_dict.get("subjectAltName", [])

    return result


def _name_to_dict(name: x509.Name) -> dict[str, str]:
    mapping = {
        NameOID.COMMON_NAME: "CN",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.COUNTRY_NAME: "C",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.LOCALITY_NAME: "L",
    }
    result = {}
    for attr in name:
        key = mapping.get(attr.oid, attr.oid.dotted_string)
        result[key] = attr.value
    return result
