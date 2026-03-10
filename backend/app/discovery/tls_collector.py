"""
CyberIntel Platform — TLS Certificate Discovery

Connects to target hosts, extracts certificate details including
fingerprint, issuer, subject, SAN domains.
"""
import ssl
import socket
import hashlib
import logging
from typing import Optional
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

logger = logging.getLogger("cyberintel.discovery.tls")


class TLSCollector:
    """Extract TLS certificate information from target hosts."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def collect(self, domain: str, port: int = 443) -> dict:
        """Connect to host and extract certificate information."""
        result = {
            "domain": domain,
            "port": port,
            "fingerprint_sha256": None,
            "fingerprint_sha1": None,
            "issuer": None,
            "subject": None,
            "san_domains": [],
            "not_before": None,
            "not_after": None,
            "serial_number": None,
            "version": None,
        }

        try:
            cert_pem = self._fetch_cert(domain, port)
            if cert_pem is None:
                result["error"] = "Could not retrieve certificate"
                return result

            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            # Fingerprints
            result["fingerprint_sha256"] = cert.fingerprint(
                cert.signature_hash_algorithm or hashlib.sha256()
            ).hex() if cert.signature_hash_algorithm else hashlib.sha256(
                cert.public_bytes(encoding=__import__('cryptography.hazmat.primitives.serialization',
                    fromlist=['Encoding']).Encoding.DER)
            ).hexdigest()

            der_bytes = cert.public_bytes(
                __import__('cryptography.hazmat.primitives.serialization',
                    fromlist=['Encoding']).Encoding.DER
            )
            result["fingerprint_sha256"] = hashlib.sha256(der_bytes).hexdigest()
            result["fingerprint_sha1"] = hashlib.sha1(der_bytes).hexdigest()

            # Issuer
            issuer = cert.issuer
            result["issuer"] = self._extract_name(issuer)

            # Subject
            subject = cert.subject
            result["subject"] = self._extract_name(subject)

            # SAN domains
            try:
                san_ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                result["san_domains"] = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn:
                    result["san_domains"] = [cn[0].value]

            # Validity
            result["not_before"] = cert.not_valid_before_utc.isoformat()
            result["not_after"] = cert.not_valid_after_utc.isoformat()
            result["serial_number"] = str(cert.serial_number)
            result["version"] = cert.version.value

            logger.info(
                f"TLS cert for {domain}: fp={result['fingerprint_sha256'][:16]}... "
                f"SANs={len(result['san_domains'])}"
            )

        except Exception as e:
            result["error"] = str(e)
            logger.warning(f"TLS collection failed for {domain}: {e}")

        return result

    def _fetch_cert(self, domain: str, port: int) -> Optional[bytes]:
        """Retrieve the PEM-encoded certificate from a host."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        pem = ssl.DER_cert_to_PEM_cert(der_cert)
                        return pem.encode()
            return None
        except Exception as e:
            logger.debug(f"TLS connection to {domain}:{port} failed: {e}")
            return None

    @staticmethod
    def _extract_name(name: x509.Name) -> dict:
        result = {}
        for attr in name:
            oid_name = attr.oid._name
            result[oid_name] = attr.value
        return result
