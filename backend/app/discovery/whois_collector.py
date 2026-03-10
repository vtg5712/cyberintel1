"""
CyberIntel Platform — WHOIS / Domain Registration Discovery
"""
import logging
from datetime import datetime
from typing import Optional

import whois

logger = logging.getLogger("cyberintel.discovery.whois")


class WhoisCollector:
    """Collect domain registration data via WHOIS."""

    async def collect(self, domain: str) -> dict:
        """Query WHOIS for domain registration information."""
        result = {
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "nameservers": [],
            "registrant_country": None,
            "dnssec": None,
            "status": [],
        }

        try:
            w = whois.whois(domain)

            result["registrar"] = w.registrar
            result["creation_date"] = self._normalize_date(w.creation_date)
            result["expiration_date"] = self._normalize_date(w.expiration_date)
            result["updated_date"] = self._normalize_date(w.updated_date)
            result["registrant_country"] = getattr(w, "country", None)
            result["dnssec"] = getattr(w, "dnssec", None)

            # Nameservers
            ns = w.name_servers
            if ns:
                if isinstance(ns, list):
                    result["nameservers"] = [str(n).lower() for n in ns]
                else:
                    result["nameservers"] = [str(ns).lower()]

            # Status
            status = w.status
            if status:
                if isinstance(status, list):
                    result["status"] = status
                else:
                    result["status"] = [status]

            logger.info(f"WHOIS collected for {domain}: registrar={result['registrar']}")

        except Exception as e:
            result["error"] = str(e)
            logger.warning(f"WHOIS failed for {domain}: {e}")

        return result

    @staticmethod
    def _normalize_date(date_val) -> Optional[str]:
        if date_val is None:
            return None
        if isinstance(date_val, list):
            date_val = date_val[0]
        if isinstance(date_val, datetime):
            return date_val.isoformat()
        return str(date_val)
