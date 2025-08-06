"""
VirusTotal API Integration for CerebralGuard
Checks reputation of URLs, domains, and file hashes.
"""

import requests
import time
import hashlib
import json
from typing import Dict, List, Optional
import os
from dotenv import load_dotenv
from loguru import logger
import redis
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Load environment variables
load_dotenv()

class VirusTotalAPI:
    """VirusTotal API client for reputation checking."""
    
    def __init__(self):
        """Initialize VirusTotal API client."""
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/vtapi/v2'
        self.headers = {
            'x-apikey': self.api_key,
            'Content-Type': 'application/json'
        }
        
        # Initialize Redis cache
        self.redis_client = None
        self._initialize_cache()
        
        if not self.api_key:
            logger.warning("VirusTotal API key not found in environment variables")
    
    def _initialize_cache(self):
        """Initialize Redis cache connection."""
        try:
            redis_host = os.getenv('REDIS_HOST', 'localhost')
            redis_port = int(os.getenv('REDIS_PORT', 6379))
            redis_db = int(os.getenv('REDIS_DB', 0))
            
            self.redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            
            # Test connection
            self.redis_client.ping()
            logger.info("Redis cache initialized successfully")
            
        except Exception as e:
            logger.warning(f"Redis cache not available: {e}")
            self.redis_client = None
    
    def _get_cache_key(self, check_type: str, value: str) -> str:
        """Generate cache key for API response."""
        return f"virustotal:{check_type}:{hashlib.sha256(value.encode()).hexdigest()}"
    
    def _get_cached_result(self, cache_key: str) -> Optional[Dict]:
        """Get cached result from Redis."""
        if not self.redis_client:
            return None
        
        try:
            cached_data = self.redis_client.get(cache_key)
            if cached_data:
                result = json.loads(cached_data)
                logger.info(f"Cache hit for {cache_key}")
                return result
        except Exception as e:
            logger.warning(f"Cache error: {e}")
        
        return None
    
    def _set_cached_result(self, cache_key: str, result: Dict, ttl: int = 3600):
        """Cache result in Redis with TTL."""
        if not self.redis_client:
            return
        
        try:
            self.redis_client.setex(cache_key, ttl, json.dumps(result))
            logger.info(f"Cached result for {cache_key} (TTL: {ttl}s)")
        except Exception as e:
            logger.warning(f"Cache set error: {e}")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((requests.RequestException, ConnectionError))
    )
    def _make_api_request(self, endpoint: str, params: Dict) -> requests.Response:
        """Make API request with retry logic."""
        response = requests.get(endpoint, params=params, headers=self.headers, timeout=10)
        response.raise_for_status()
        return response
    
    def check_url_reputation(self, url: str) -> Dict:
        """
        Check reputation of a URL.
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with reputation data
        """
        if not self.api_key:
            return {'error': 'API key not configured'}
        
        # Check cache first
        cache_key = self._get_cache_key('url', url)
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            return cached_result
        
        try:
            # URL endpoint
            endpoint = f"{self.base_url}/url/report"
            params = {'apikey': self.api_key, 'resource': url}
            
            response = self._make_api_request(endpoint, params)
            data = response.json()
            
            # Extract relevant information
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            scan_date = data.get('scan_date')
            permalink = data.get('permalink')
            
            # Calculate reputation score (0-100, higher = more malicious)
            reputation_score = (positives / total * 100) if total > 0 else 0
            
            result = {
                'url': url,
                'positives': positives,
                'total': total,
                'reputation_score': reputation_score,
                'scan_date': scan_date,
                'permalink': permalink,
                'status': 'success'
            }
            
            # Cache the result
            self._set_cached_result(cache_key, result, ttl=3600)  # 1 hour cache
            
            return result
                
        except Exception as e:
            logger.error(f"Error checking URL reputation: {e}")
            return {'error': str(e)}
    
    def check_domain_reputation(self, domain: str) -> Dict:
        """
        Check reputation of a domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with reputation data
        """
        if not self.api_key:
            return {'error': 'API key not configured'}
        
        # Check cache first
        cache_key = self._get_cache_key('domain', domain)
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            return cached_result
        
        try:
            # Domain endpoint
            endpoint = f"{self.base_url}/domain/report"
            params = {'apikey': self.api_key, 'domain': domain}
            
            response = self._make_api_request(endpoint, params)
            data = response.json()
            
            # Extract relevant information
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            categories = data.get('categories', {})
            
            # Calculate reputation score
            reputation_score = (positives / total * 100) if total > 0 else 0
            
            result = {
                'domain': domain,
                'positives': positives,
                'total': total,
                'reputation_score': reputation_score,
                'categories': categories,
                'status': 'success'
            }
            
            # Cache the result
            self._set_cached_result(cache_key, result, ttl=7200)  # 2 hour cache
            
            return result
                
        except Exception as e:
            logger.error(f"Error checking domain reputation: {e}")
            return {'error': str(e)}
    
    def check_file_hash(self, file_hash: str) -> Dict:
        """
        Check reputation of a file hash.
        
        Args:
            file_hash: SHA256 hash of the file
            
        Returns:
            Dictionary with reputation data
        """
        if not self.api_key:
            return {'error': 'API key not configured'}
        
        # Check cache first
        cache_key = self._get_cache_key('hash', file_hash)
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            return cached_result
        
        try:
            # File report endpoint
            endpoint = f"{self.base_url}/file/report"
            params = {'apikey': self.api_key, 'resource': file_hash}
            
            response = self._make_api_request(endpoint, params)
            data = response.json()
            
            # Extract relevant information
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            scan_date = data.get('scan_date')
            permalink = data.get('permalink')
            
            # Calculate reputation score
            reputation_score = (positives / total * 100) if total > 0 else 0
            
            result = {
                'file_hash': file_hash,
                'positives': positives,
                'total': total,
                'reputation_score': reputation_score,
                'scan_date': scan_date,
                'permalink': permalink,
                'status': 'success'
            }
            
            # Cache the result
            self._set_cached_result(cache_key, result, ttl=14400)  # 4 hour cache
            
            return result
                
        except Exception as e:
            logger.error(f"Error checking file hash: {e}")
            return {'error': str(e)}
    
    def check_multiple_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        """
        Check reputation for multiple IOCs at once.
        
        Args:
            iocs: Dictionary with IOC types and values
                {
                    'urls': ['http://malicious.com'],
                    'domains': ['malicious.com'],
                    'hashes': ['abc123...']
                }
                
        Returns:
            Dictionary with results for each IOC type
        """
        results = {}
        
        # Check URLs
        if 'urls' in iocs:
            results['urls'] = []
            for url in iocs['urls']:
                result = self.check_url_reputation(url)
                results['urls'].append(result)
                # Rate limiting - VirusTotal has limits
                time.sleep(1)
        
        # Check domains
        if 'domains' in iocs:
            results['domains'] = []
            for domain in iocs['domains']:
                result = self.check_domain_reputation(domain)
                results['domains'].append(result)
                time.sleep(1)
        
        # Check file hashes
        if 'hashes' in iocs:
            results['hashes'] = []
            for file_hash in iocs['hashes']:
                result = self.check_file_hash(file_hash)
                results['hashes'].append(result)
                time.sleep(1)
        
        logger.info(f"Checked reputation for {sum(len(v) for v in results.values())} IOCs")
        return results
    
    def get_overall_score(self, ioc_results: Dict[str, List[Dict]]) -> int:
        """
        Calculate overall reputation score from multiple IOC results.
        
        Args:
            ioc_results: Results from check_multiple_iocs
            
        Returns:
            Overall score (0-100, higher = more malicious)
        """
        scores = []
        
        for ioc_type, results in ioc_results.items():
            for result in results:
                if 'reputation_score' in result and result['status'] == 'success':
                    scores.append(result['reputation_score'])
        
        if scores:
            # Return average score
            return int(sum(scores) / len(scores))
        else:
            return 0

# Global instance for easy access
virustotal_api = VirusTotalAPI() 