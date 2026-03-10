"""
CyberIntel Platform — Infrastructure Discovery Engine

Orchestrates DNS, WHOIS, TLS, and Hosting collectors.
Given a starting artifact, runs all collection pipelines and
feeds results into the graph database.
"""
import logging
from typing import Optional

from app.discovery.dns_collector import DNSCollector
from app.discovery.whois_collector import WhoisCollector
from app.discovery.tls_collector import TLSCollector
from app.discovery.hosting_collector import HostingCollector
from app.core.config import settings

logger = logging.getLogger("cyberintel.discovery.engine")


class DiscoveryEngine:
    """
    Main discovery orchestrator.
    Runs all collectors against a domain and returns combined intelligence.
    """

    def __init__(self):
        self.dns = DNSCollector(timeout=settings.DNS_TIMEOUT)
        self.whois = WhoisCollector()
        self.tls = TLSCollector(timeout=settings.TLS_TIMEOUT)
        self.hosting = HostingCollector()

    async def investigate_domain(self, domain: str) -> dict:
        """Run full infrastructure discovery on a domain."""
        logger.info(f"Starting infrastructure discovery for: {domain}")

        result = {
            "domain": domain,
            "dns": {},
            "whois": {},
            "tls": {},
            "hosting": {},
            "related_domains": [],
            "errors": [],
        }

        # 1. DNS resolution
        try:
            result["dns"] = await self.dns.collect(domain)
        except Exception as e:
            result["errors"].append(f"DNS: {str(e)}")
            logger.error(f"DNS collection failed for {domain}: {e}")

        # 2. WHOIS registration data
        try:
            result["whois"] = await self.whois.collect(domain)
        except Exception as e:
            result["errors"].append(f"WHOIS: {str(e)}")
            logger.error(f"WHOIS collection failed for {domain}: {e}")

        # 3. TLS certificate
        try:
            result["tls"] = await self.tls.collect(domain)
            # SAN domains are potential related infrastructure
            san_domains = result["tls"].get("san_domains", [])
            for san in san_domains:
                if san != domain and san not in result["related_domains"]:
                    result["related_domains"].append(san)
        except Exception as e:
            result["errors"].append(f"TLS: {str(e)}")
            logger.error(f"TLS collection failed for {domain}: {e}")

        # 4. Hosting / IP data
        try:
            ip_list = self.dns.get_a_records(result.get("dns", {}))
            if ip_list:
                result["hosting"] = await self.hosting.collect(ip_list[0])
                result["hosting"]["all_ips"] = ip_list
            else:
                result["hosting"] = await self.hosting.collect_for_domain(domain)
        except Exception as e:
            result["errors"].append(f"Hosting: {str(e)}")
            logger.error(f"Hosting collection failed for {domain}: {e}")

        logger.info(
            f"Discovery complete for {domain}: "
            f"dns={'ok' if result['dns'] else 'fail'} "
            f"whois={'ok' if result['whois'] else 'fail'} "
            f"tls={'ok' if result['tls'] else 'fail'} "
            f"hosting={'ok' if result['hosting'] else 'fail'} "
            f"related={len(result['related_domains'])}"
        )

        return result

    async def investigate_ip(self, ip_address: str) -> dict:
        """Investigate an IP address — hosting info + reverse DNS."""
        logger.info(f"Investigating IP: {ip_address}")
        result = {
            "ip": ip_address,
            "hosting": {},
            "reverse_dns": [],
            "errors": [],
        }

        try:
            result["hosting"] = await self.hosting.collect(ip_address)
        except Exception as e:
            result["errors"].append(f"Hosting: {str(e)}")

        try:
            result["reverse_dns"] = await self.hosting.reverse_dns(ip_address)
        except Exception as e:
            result["errors"].append(f"Reverse DNS: {str(e)}")

        return result

    async def investigate_tls_fingerprint(self, fingerprint: str) -> dict:
        """Placeholder: search graph for domains sharing this cert fingerprint."""
        logger.info(f"Investigating TLS fingerprint: {fingerprint[:16]}...")
        return {
            "fingerprint": fingerprint,
            "note": "Search graph for USES_CERTIFICATE relationships",
        }
