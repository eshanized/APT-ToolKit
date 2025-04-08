"""
Subdomain Enumeration Module for APT Toolkit

Features:
- Multi-technique enumeration (DNS, scraping, APIs)
- Rate limiting and retry mechanisms
- Result deduplication and validation
- Integration with core systems
"""

import asyncio
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import dns.resolver
import aiodns
import requests
from concurrent.futures import ThreadPoolExecutor
from src.core.engine import ScanModule
from src.core.event_system import event_system
from src.utils.helpers import ErrorHelpers, DataHelpers
from src.utils.logger import get_logger
from src.utils.network import NetworkHelpers
from src.utils.config import config
from src.utils.threading_utils import net_pool

logger = get_logger(__name__)

class SubdomainEnumerator(ScanModule):
    """Subdomain discovery module using multiple techniques"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "subdomain_enum"
        self._dns_resolver = dns.resolver.Resolver()
        self._dns_resolver.nameservers = config.network.dns_servers
        self._aiodns = aiodns.DNSResolver()
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': config.network.user_agent
        })
        self._wordlist = self._load_wordlist()
        self._rate_limit = threading.Semaphore(config.network.max_dns_queries)

    def _load_wordlist(self) -> List[str]:
        """Load subdomain wordlist from file"""
        wordlist_path = Path(config.wordlist_dir) / "subdomains.txt"
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Failed to load wordlist: {str(e)}")
            return []

    async def _dns_query_async(self, domain: str, record_type: str = 'A') -> List[str]:
        """Asynchronous DNS query with rate limiting"""
        async with self._rate_limit:
            try:
                result = await self._aiodns.query(domain, record_type)
                return [str(r.host) for r in result] if result else []
            except aiodns.error.DNSError as e:
                if e.args[0] != 4:  # Ignore NXDOMAIN errors
                    logger.debug(f"DNS query failed for {domain}: {str(e)}")
                return []
            except Exception as e:
                logger.warning(f"Unexpected DNS error for {domain}: {str(e)}")
                return []

    def _dns_query_sync(self, domain: str) -> bool:
        """Synchronous DNS verification"""
        try:
            with self._rate_limit:
                self._dns_resolver.resolve(domain, 'A')
                return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception as e:
            logger.debug(f"DNS verification failed for {domain}: {str(e)}")
            return False

    async def _bruteforce_subdomains(self, domain: str) -> Set[str]:
        """Perform DNS bruteforcing with wordlist"""
        tasks = []
        found = set()
        
        # Generate candidate subdomains
        candidates = {f"{word}.{domain}" for word in self._wordlist}
        candidates.add(domain)  # Check base domain
        
        # Create async tasks
        for candidate in candidates:
            tasks.append(self._dns_query_async(candidate))
        
        # Process results
        results = await asyncio.gather(*tasks)
        for candidate, records in zip(candidates, results):
            if records:
                found.add(candidate)
                logger.debug(f"Discovered subdomain: {candidate} => {records}")
                
        return found

    async def _query_cert_transparency(self, domain: str) -> Set[str]:
        """Query certificate transparency logs"""
        found = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await net_pool.submit(
                lambda: self._session.get(url, timeout=10)
            ).result()
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name and domain in name:
                        # Clean and validate names
                        clean_name = name.strip().lower()
                        if clean_name.startswith('*.'):
                            clean_name = clean_name[2:]
                        if clean_name.endswith(f".{domain}"):
                            found.add(clean_name)
        except Exception as e:
            logger.warning(f"CT log query failed: {str(e)}")
        return found

    async def _query_security_apis(self, domain: str) -> Set[str]:
        """Query security APIs for subdomains"""
        found = set()
        apis = [
            ("https://api.sublist3r.com/search.php?domain={}", 'domains'),
            ("https://www.virustotal.com/api/v3/domains/{}/subdomains", 'data')
        ]
        
        for endpoint, key in apis:
            try:
                url = endpoint.format(domain)
                response = await net_pool.submit(
                    lambda: self._session.get(url, timeout=15)
                ).result()
                
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get(key, []):
                        if isinstance(item, str) and domain in item:
                            found.add(item.strip().lower())
            except Exception as e:
                logger.debug(f"API query failed ({endpoint}): {str(e)}")
                
        return found

    def _validate_subdomains(self, domain: str, candidates: Set[str]) -> Set[str]:
        """Verify discovered subdomains"""
        valid = set()
        with ThreadPoolExecutor(max_workers=config.network.max_dns_verifiers) as executor:
            futures = {
                executor.submit(self._dns_query_sync, subdomain): subdomain
                for subdomain in candidates
            }
            for future in futures:
                subdomain = futures[future]
                try:
                    if future.result():
                        valid.add(subdomain)
                except Exception as e:
                    logger.debug(f"Validation failed for {subdomain}: {str(e)}")
        return valid

    async def execute_async(self, target: str) -> Dict[str, List[str]]:
        """Asynchronous subdomain enumeration"""
        domain = target.lower().strip()
        if not NetworkHelpers.validate_domain(domain):
            logger.error(f"Invalid target domain: {domain}")
            return {'error': 'Invalid domain'}
            
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        # Run all discovery techniques in parallel
        tasks = [
            self._bruteforce_subdomains(domain),
            self._query_cert_transparency(domain),
            self._query_security_apis(domain)
        ]
        
        results = await asyncio.gather(*tasks)
        all_candidates = set().union(*results)
        
        # Validate discovered subdomains
        valid_subdomains = await net_pool.submit(
            lambda: self._validate_subdomains(domain, all_candidates)
        ).result()
        
        # Prepare final results
        subdomains = sorted(valid_subdomains)
        logger.info(f"Found {len(subdomains)} valid subdomains for {domain}")
        
        return {
            'target': domain,
            'subdomains': subdomains,
            'techniques': ['dns_bruteforce', 'ct_logs', 'security_apis'],
            'count': len(subdomains)
        }

    def execute(self, target: str) -> Dict[str, Any]:
        """Synchronous wrapper for async execution"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self.execute_async(target))
            loop.close()
            return result
        except Exception as e:
            loop.close()
            logger.error(f"Subdomain enumeration failed: {str(e)}")
            return {'error': str(e)}

# Module registration
def init_module():
    return SubdomainEnumerator()

# Example usage:
# enumerator = SubdomainEnumerator()
# results = enumerator.execute("example.com")