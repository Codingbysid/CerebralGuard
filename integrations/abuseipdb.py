"""
AbuseIPDB API Integration for CerebralGuard
Checks reputation of IP addresses for malicious activity.
"""

import requests
import time
from typing import Dict, List, Optional
import os
from dotenv import load_dotenv
from loguru import logger

# Load environment variables
load_dotenv()

class AbuseIPDBAPI:
    """AbuseIPDB API client for IP reputation checking."""
    
    def __init__(self):
        """Initialize AbuseIPDB API client."""
        self.api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.base_url = 'https://api.abuseipdb.com/api/v2'
        self.headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        if not self.api_key:
            logger.warning("AbuseIPDB API key not found in environment variables")
    
    def check_ip_reputation(self, ip_address: str) -> Dict:
        """
        Check reputation of an IP address.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with reputation data
        """
        if not self.api_key:
            return {'error': 'API key not configured'}
        
        try:
            # Check endpoint
            endpoint = f"{self.base_url}/check"
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90'  # Check last 90 days
            }
            
            response = requests.get(endpoint, params=params, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant information
                abuse_confidence_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                country_code = data.get('data', {}).get('countryCode', 'Unknown')
                usage_type = data.get('data', {}).get('usageType', 'Unknown')
                isp = data.get('data', {}).get('isp', 'Unknown')
                
                # Calculate reputation score (0-100, higher = more malicious)
                reputation_score = abuse_confidence_score
                
                return {
                    'ip_address': ip_address,
                    'abuse_confidence_score': abuse_confidence_score,
                    'reputation_score': reputation_score,
                    'country_code': country_code,
                    'usage_type': usage_type,
                    'isp': isp,
                    'status': 'success'
                }
            else:
                logger.error(f"AbuseIPDB API error: {response.status_code}")
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Error checking IP reputation: {e}")
            return {'error': str(e)}
    
    def check_multiple_ips(self, ip_addresses: List[str]) -> Dict[str, Dict]:
        """
        Check reputation for multiple IP addresses.
        
        Args:
            ip_addresses: List of IP addresses to check
            
        Returns:
            Dictionary with results for each IP
        """
        results = {}
        
        for ip in ip_addresses:
            result = self.check_ip_reputation(ip)
            results[ip] = result
            # Rate limiting - AbuseIPDB has limits
            time.sleep(1)
        
        logger.info(f"Checked reputation for {len(ip_addresses)} IP addresses")
        return results
    
    def get_overall_score(self, ip_results: Dict[str, Dict]) -> int:
        """
        Calculate overall reputation score from multiple IP results.
        
        Args:
            ip_results: Results from check_multiple_ips
            
        Returns:
            Overall score (0-100, higher = more malicious)
        """
        scores = []
        
        for ip, result in ip_results.items():
            if 'reputation_score' in result and result['status'] == 'success':
                scores.append(result['reputation_score'])
        
        if scores:
            # Return average score
            return int(sum(scores) / len(scores))
        else:
            return 0

# Global instance for easy access
abuseipdb_api = AbuseIPDBAPI() 