import asyncio
import ssl
import socket
import select
from typing import Any
from datetime import datetime, timezone

from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID


async def get_tls_info(hostname: str, port: int = 443) -> dict[str, Any]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_tls_sync, hostname, port)


def _get_tls_sync(hostname: str, port: int) -> dict[str, Any]:
    chain_certs = []
    valid = True
    validation_error = ""
    protocol_version = ""

    try:
        chain_certs, protocol_version = _connect_and_get_chain(hostname, port, verify=True)
    except SSL.Error as e:
        valid = False
        validation_error = str(e)
        try:
            chain_certs, protocol_version = _connect_and_get_chain(hostname, port, verify=False)
        except Exception as e2:
            return {
                "valid": False,
                "validation_error": validation_error,
                "connection_error": str(e2),
                "chain": [],
                "chain_length": 0,
            }
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        raise ConnectionError(f"无法连接到 {hostname}:{port} — {e}")
    except Exception as e:
        raise ConnectionError(f"TLS连接失败: {e}")

    chain = []
    for i, cert_pem in enumerate(chain_certs):
        parsed = _parse_single_cert(cert_pem, index=i)
        chain.append(parsed)

    result = {
        "valid": valid,
        "chain_length": len(chain),
        "protocol": protocol_version,
        "chain": chain,
    }
    if validation_error:
        result["validation_error"] = validation_error

    return result


def _connect_and_get_chain(hostname: str, port: int, verify: bool) -> tuple[list[bytes], str]:
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)

    if verify:
        ctx.set_default_verify_paths()
        ctx.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: ok)
    else:
        ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)

    sock = socket.create_connection((hostname, port), timeout=10)
    sock.setblocking(True)
    conn = SSL.Connection(ctx, sock)
    conn.set_tlsext_host_name(hostname.encode())
    conn.set_connect_state()

    try:
        for _ in range(10):
            try:
                conn.do_handshake()
                break
            except SSL.WantReadError:
                select.select([sock], [], [], 5)
                continue
        else:
            raise ConnectionError("TLS握手超时")

        chain_certs = []
        peer_chain = conn.get_peer_cert_chain()
        if peer_chain:
            for cert in peer_chain:
                cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                chain_certs.append(cert_pem)

        protocol_version = conn.get_protocol_version_name()
    finally:
        try:
            conn.shutdown()
        except Exception:
            pass
        sock.close()

    return chain_certs, protocol_version


def _parse_single_cert(cert_pem: bytes, index: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        return {"index": index, "parse_error": str(e)}

    result = {
        "index": index,
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "expired": now > cert.not_valid_after_utc,
        "not_yet_valid": now < cert.not_valid_before_utc,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "version": cert.version.value,
    }

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        result["san"] = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        result["is_ca"] = basic.value.ca
    except x509.ExtensionNotFound:
        result["is_ca"] = False

    if cert.signature_hash_algorithm:
        result["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex(":")

    if index == 0:
        result["role"] = "leaf"
    elif result.get("is_ca"):
        if result["subject"] == result["issuer"]:
            result["role"] = "root"
        else:
            result["role"] = "intermediate"
    else:
        result["role"] = "intermediate"

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
