"""
CyberIntel Platform — DNS Discovery Module

Collects A, MX, NS, TXT, CNAME, AAAA records for a given domain.
"""
import logging
from typing import Optional

import dns.resolver
import dns.exception

logger = logging.getLogger("cyberintel.discovery.dns")


class DNSCollector:
    """Resolve DNS records for investigation targets."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def __init__(self, timeout: float = 10.0, nameservers: Optional[list[str]] = None):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if nameservers:
            self.resolver.nameservers = nameservers

    async def collect(self, domain: str) -> dict:
        """Collect all DNS records for a domain."""
        results = {"domain": domain, "records": {}}

        for rtype in self.RECORD_TYPES:
            try:
                answers = self.resolver.resolve(domain, rtype)
                records = []
                for rdata in answers:
                    if rtype == "MX":
                        records.append({
                            "priority": rdata.preference,
                            "exchange": str(rdata.exchange).rstrip(".")
                        })
                    elif rtype == "SOA":
                        records.append({
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                        })
                    else:
                        records.append(str(rdata).strip('"'))

                if records:
                    results["records"][rtype] = records
                    logger.info(f"DNS {rtype} for {domain}: {len(records)} records")

            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                results["error"] = "NXDOMAIN"
                logger.warning(f"DNS NXDOMAIN: {domain}")
                break
            except dns.exception.DNSException as e:
                logger.debug(f"DNS {rtype} failed for {domain}: {e}")
                continue

        return results

    def get_a_records(self, dns_data: dict) -> list[str]:
        """Extract IP addresses from collected DNS data."""
        ips = []
        for rtype in ["A", "AAAA"]:
            ips.extend(dns_data.get("records", {}).get(rtype, []))
        return ips

    def get_mx_domains(self, dns_data: dict) -> list[str]:
        mx_records = dns_data.get("records", {}).get("MX", [])
        return [r["exchange"] for r in mx_records if isinstance(r, dict)]

    def get_ns_servers(self, dns_data: dict) -> list[str]:
        return dns_data.get("records", {}).get("NS", [])
