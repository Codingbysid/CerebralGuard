"""
VirusTotal API Integration for CerebralGuard
Checks reputation of URLs, domains, and file hashes.
"""

import requests
import time
from typing import Dict, List, Optional
import os
from dotenv import load_dotenv
from loguru import logger

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
        
        if not self.api_key:
            logger.warning("VirusTotal API key not found in environment variables")
    
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
        
        try:
            # URL endpoint
            endpoint = f"{self.base_url}/url/report"
            params = {'apikey': self.api_key, 'resource': url}
            
            response = requests.get(endpoint, params=params)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant information
                positives = data.get('positives', 0)
                total = data.get('total', 0)
                scan_date = data.get('scan_date')
                permalink = data.get('permalink')
                
                # Calculate reputation score (0-100, higher = more malicious)
                reputation_score = (positives / total * 100) if total > 0 else 0
                
                return {
                    'url': url,
                    'positives': positives,
                    'total': total,
                    'reputation_score': reputation_score,
                    'scan_date': scan_date,
                    'permalink': permalink,
                    'status': 'success'
                }
            else:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return {'error': f'API error: {response.status_code}'}
                
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
        
        try:
            # Domain endpoint
            endpoint = f"{self.base_url}/domain/report"
            params = {'apikey': self.api_key, 'domain': domain}
            
            response = requests.get(endpoint, params=params)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant information
                positives = data.get('positives', 0)
                total = data.get('total', 0)
                categories = data.get('categories', {})
                
                # Calculate reputation score
                reputation_score = (positives / total * 100) if total > 0 else 0
                
                return {
                    'domain': domain,
                    'positives': positives,
                    'total': total,
                    'reputation_score': reputation_score,
                    'categories': categories,
                    'status': 'success'
                }
            else:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return {'error': f'API error: {response.status_code}'}
                
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
        
        try:
            # File report endpoint
            endpoint = f"{self.base_url}/file/report"
            params = {'apikey': self.api_key, 'resource': file_hash}
            
            response = requests.get(endpoint, params=params)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant information
                positives = data.get('positives', 0)
                total = data.get('total', 0)
                scan_date = data.get('scan_date')
                permalink = data.get('permalink')
                
                # Calculate reputation score
                reputation_score = (positives / total * 100) if total > 0 else 0
                
                return {
                    'file_hash': file_hash,
                    'positives': positives,
                    'total': total,
                    'reputation_score': reputation_score,
                    'scan_date': scan_date,
                    'permalink': permalink,
                    'status': 'success'
                }
            else:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return {'error': f'API error: {response.status_code}'}
                
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