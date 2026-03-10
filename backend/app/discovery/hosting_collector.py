"""
CyberIntel Platform — Hosting / IP / ASN Discovery

Resolves IP geolocation, ASN, and hosting provider information.
"""
import logging
import socket
from typing import Optional

from app.core.network import network

logger = logging.getLogger("cyberintel.discovery.hosting")


class HostingCollector:
    """Collect IP, ASN, geolocation, and hosting provider data."""

    # Free IP info APIs (no key required)
    IP_INFO_URLS = [
        "https://ipapi.co/{ip}/json/",
        "http://ip-api.com/json/{ip}",
    ]

    async def collect(self, ip_address: str) -> dict:
        """Collect hosting infrastructure data for an IP address."""
        result = {
            "ip": ip_address,
            "asn": None,
            "asn_org": None,
            "hosting_provider": None,
            "country": None,
            "country_code": None,
            "city": None,
            "region": None,
            "latitude": None,
            "longitude": None,
        }

        # Try IP info APIs
        for url_template in self.IP_INFO_URLS:
            try:
                url = url_template.format(ip=ip_address)
                response = await network.get(url)
                if response.status_code == 200:
                    data = response.json()
                    result.update(self._parse_ip_info(data))
                    logger.info(f"Hosting info for {ip_address}: ASN={result['asn']}, country={result['country_code']}")
                    break
            except Exception as e:
                logger.debug(f"IP info API failed for {ip_address}: {e}")
                continue

        return result

    async def collect_for_domain(self, domain: str) -> dict:
        """Resolve domain to IP then collect hosting data."""
        try:
            ip = socket.gethostbyname(domain)
            result = await self.collect(ip)
            result["resolved_domain"] = domain
            return result
        except socket.gaierror as e:
            logger.warning(f"Could not resolve {domain}: {e}")
            return {"ip": None, "error": str(e), "resolved_domain": domain}

    @staticmethod
    def _parse_ip_info(data: dict) -> dict:
        """Normalize IP info API response."""
        parsed = {}

        # ipapi.co format
        if "asn" in data:
            parsed["asn"] = data.get("asn")
            parsed["asn_org"] = data.get("org", "")
            parsed["hosting_provider"] = data.get("org", "")
            parsed["country"] = data.get("country_name", "")
            parsed["country_code"] = data.get("country_code", "")
            parsed["city"] = data.get("city", "")
            parsed["region"] = data.get("region", "")
            parsed["latitude"] = data.get("latitude")
            parsed["longitude"] = data.get("longitude")
        # ip-api.com format
        elif "as" in data:
            as_info = data.get("as", "")
            parsed["asn"] = as_info.split(" ")[0] if as_info else None
            parsed["asn_org"] = " ".join(as_info.split(" ")[1:]) if as_info else ""
            parsed["hosting_provider"] = data.get("isp", data.get("org", ""))
            parsed["country"] = data.get("country", "")
            parsed["country_code"] = data.get("countryCode", "")
            parsed["city"] = data.get("city", "")
            parsed["region"] = data.get("regionName", "")
            parsed["latitude"] = data.get("lat")
            parsed["longitude"] = data.get("lon")

        return parsed

    async def reverse_dns(self, ip_address: str) -> list[str]:
        """Attempt reverse DNS lookup."""
        try:
            hostnames = socket.gethostbyaddr(ip_address)
            return [hostnames[0]] + list(hostnames[1])
        except (socket.herror, socket.gaierror):
            return []
