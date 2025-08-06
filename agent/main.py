"""
CerebralGuard Main Agent Orchestration
Implements the multi-step workflow for autonomous phishing threat detection.
"""

import google.generativeai as genai
import hashlib
import re
import email
from email import policy
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import os
from dotenv import load_dotenv
from loguru import logger
import time
from datetime import datetime

# Import our modules
from db.tidb_helpers import tidb_manager
from models.content_model import phishing_detector
from integrations.virustotal import virustotal_api
from integrations.slack import slack_notifier

# Load environment variables
load_dotenv()

class CerebralGuardAgent:
    """Main agent class that orchestrates the multi-step phishing detection workflow."""
    
    def __init__(self):
        """Initialize the CerebralGuard agent."""
        self.gemini_api_key = os.getenv('GEMINI_API_KEY')
        
        # Configure Gemini API
        if self.gemini_api_key:
            genai.configure(api_key=self.gemini_api_key)
            self.model = genai.GenerativeModel('gemini-pro')
            logger.info("Gemini API configured successfully")
        else:
            logger.warning("Gemini API key not found")
            self.model = None
        
        # Initialize database
        tidb_manager.initialize_database()
        
        # Statistics tracking
        self.stats = {
            'total_processed': 0,
            'malicious_count': 0,
            'suspicious_count': 0,
            'safe_count': 0,
            'processing_times': []
        }
    
    def analyze_with_gemini(self, prompt: str, api_key: str = None) -> str:
        """
        Make a call to the Gemini API for analysis.
        
        Args:
            prompt: The prompt to send to Gemini
            api_key: Optional API key override
            
        Returns:
            Gemini's response text
        """
        if not self.model:
            logger.error("Gemini model not initialized")
            return "Error: Gemini API not configured"
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error calling Gemini API: {e}")
            return f"Error: {str(e)}"
    
    def parse_email(self, email_content: str) -> Dict:
        """
        Step 1: Parse email and extract IOCs using Gemini.
        
        Args:
            email_content: Raw email content (.eml format)
            
        Returns:
            Dictionary with parsed email data and extracted IOCs
        """
        try:
            # Parse email using Python's email library
            email_message = email.message_from_string(email_content, policy=policy.default)
            
            # Extract basic email information
            sender_email = email_message.get('from', '')
            subject = email_message.get('subject', '')
            
            # Extract email body
            body = ""
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_content()
                        break
            else:
                body = email_message.get_content()
            
            # Create prompt for Gemini to extract IOCs
            ioc_extraction_prompt = f"""
            Analyze this email and extract all potential Indicators of Compromise (IOCs):
            
            From: {sender_email}
            Subject: {subject}
            Body: {body}
            
            Please extract and return ONLY a JSON object with the following structure:
            {{
                "urls": ["list", "of", "urls"],
                "domains": ["list", "of", "domains"],
                "ips": ["list", "of", "ip", "addresses"],
                "emails": ["list", "of", "email", "addresses"],
                "hashes": ["list", "of", "file", "hashes"],
                "sender_ip": "extracted_sender_ip_if_available"
            }}
            
            Focus on suspicious or malicious indicators. If no IOCs found, return empty arrays.
            """
            
            # Get IOC extraction from Gemini
            ioc_response = self.analyze_with_gemini(ioc_extraction_prompt)
            
            # Try to parse JSON response
            try:
                import json
                extracted_iocs = json.loads(ioc_response)
            except:
                # Fallback: basic regex extraction
                extracted_iocs = self._extract_iocs_basic(body)
            
            # Generate email hash for deduplication
            email_hash = hashlib.sha256(email_content.encode()).hexdigest()
            
            return {
                'email_hash': email_hash,
                'sender_email': sender_email,
                'sender_ip': extracted_iocs.get('sender_ip', ''),
                'subject': subject,
                'email_body': body,
                'extracted_iocs': extracted_iocs,
                'raw_email': email_content
            }
            
        except Exception as e:
            logger.error(f"Error parsing email: {e}")
            return {}
    
    def _extract_iocs_basic(self, text: str) -> Dict:
        """Basic IOC extraction using regex patterns."""
        iocs = {
            'urls': [],
            'domains': [],
            'ips': [],
            'emails': [],
            'hashes': [],
            'sender_ip': ''
        }
        
        # URL pattern
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        iocs['urls'] = re.findall(url_pattern, text)
        
        # Domain pattern
        domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        iocs['domains'] = re.findall(domain_pattern, text)
        
        # IP pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs['ips'] = re.findall(ip_pattern, text)
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs['emails'] = re.findall(email_pattern, text)
        
        # Hash pattern (basic)
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        iocs['hashes'] = re.findall(hash_pattern, text)
        
        return iocs
    
    def search_threat_intelligence(self, iocs: Dict) -> Dict:
        """
        Step 2: Search threat intelligence databases.
        
        Args:
            iocs: Extracted IOCs
            
        Returns:
            Dictionary with threat intelligence results
        """
        results = {
            'vector_search': [],
            'threat_intel': {},
            'external_reputation': {}
        }
        
        try:
            # Vector search for similar incidents
            # For demo, we'll create a simple vector representation
            email_vector = self._create_email_vector(iocs)
            similar_incidents = tidb_manager.find_similar_incidents(email_vector)
            results['vector_search'] = similar_incidents
            
            # Full-text search against threat intelligence
            threat_intel_results = tidb_manager.search_threat_intelligence(iocs)
            results['threat_intel'] = threat_intel_results
            
            # External reputation check
            external_results = virustotal_api.check_multiple_iocs(iocs)
            results['external_reputation'] = external_results
            
            logger.info(f"Threat intelligence search completed")
            return results
            
        except Exception as e:
            logger.error(f"Error in threat intelligence search: {e}")
            return results
    
    def _create_email_vector(self, iocs: Dict) -> List[float]:
        """Create a simple vector representation of the email for similarity search."""
        # This is a simplified vector creation
        # In production, you'd use a proper embedding model
        vector = [0.0] * 100  # 100-dimensional vector
        
        # Simple feature engineering
        if iocs.get('urls'):
            vector[0] = len(iocs['urls']) / 10.0
        if iocs.get('domains'):
            vector[1] = len(iocs['domains']) / 10.0
        if iocs.get('ips'):
            vector[2] = len(iocs['ips']) / 10.0
        if iocs.get('emails'):
            vector[3] = len(iocs['emails']) / 10.0
        
        return vector
    
    def analyze_with_inhouse_model(self, email_text: str) -> Dict:
        """
        Step 4: Analyze with custom in-house ML model.
        
        Args:
            email_text: Email text to analyze
            
        Returns:
            Dictionary with model predictions
        """
        try:
            prediction = phishing_detector.predict(email_text)
            return prediction
        except Exception as e:
            logger.error(f"Error in in-house model analysis: {e}")
            return {'confidence': 0.0, 'phishing_probability': 0.5}
    
    def synthesize_and_decide(self, all_evidence: Dict) -> Dict:
        """
        Step 5: Synthesize all evidence and make final decision using Gemini.
        
        Args:
            all_evidence: All collected evidence from previous steps
            
        Returns:
            Dictionary with final verdict and summary
        """
        try:
            # Create comprehensive prompt for Gemini
            synthesis_prompt = f"""
            You are a Senior Security Analyst at CerebralGuard. Review all the evidence below and provide a final verdict on whether this email is malicious, suspicious, or safe.
            
            EMAIL INFORMATION:
            - Sender: {all_evidence.get('sender_email', 'Unknown')}
            - Subject: {all_evidence.get('subject', 'No subject')}
            - Body: {all_evidence.get('email_body', '')[:1000]}...
            
            EXTRACTED IOCs:
            {all_evidence.get('extracted_iocs', {})}
            
            THREAT INTELLIGENCE RESULTS:
            - Similar incidents found: {len(all_evidence.get('vector_search', []))}
            - Threat intelligence matches: {all_evidence.get('threat_intel', {})}
            - External reputation scores: {all_evidence.get('external_reputation', {})}
            
            IN-HOUSE MODEL ANALYSIS:
            - Phishing probability: {all_evidence.get('inhouse_model_score', 0):.1f}%
            - Confidence: {all_evidence.get('inhouse_confidence', 0):.1f}%
            
            EXTERNAL REPUTATION SCORES:
            - VirusTotal overall score: {all_evidence.get('virustotal_score', 0)}/100
            
            Based on all this evidence, provide:
            1. FINAL VERDICT: "malicious", "suspicious", or "safe"
            2. CONFIDENCE LEVEL: "high", "medium", or "low"
            3. SUMMARY: A concise explanation of your decision (2-3 sentences)
            4. RECOMMENDED ACTION: What should be done with this email
            
            Format your response as JSON:
            {{
                "verdict": "malicious|suspicious|safe",
                "confidence": "high|medium|low",
                "summary": "your explanation here",
                "recommended_action": "action description"
            }}
            """
            
            # Get Gemini's analysis
            gemini_response = self.analyze_with_gemini(synthesis_prompt)
            
            # Try to parse JSON response
            try:
                import json
                analysis = json.loads(gemini_response)
            except:
                # Fallback: create basic analysis
                analysis = {
                    'verdict': 'suspicious',
                    'confidence': 'medium',
                    'summary': 'Unable to parse Gemini response. Defaulting to suspicious.',
                    'recommended_action': 'Human review required'
                }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error in synthesis and decision: {e}")
            return {
                'verdict': 'suspicious',
                'confidence': 'low',
                'summary': f'Error in analysis: {str(e)}',
                'recommended_action': 'Human review required'
            }
    
    def take_action(self, incident_data: Dict, verdict: str) -> bool:
        """
        Step 6: Take action based on the verdict.
        
        Args:
            incident_data: Complete incident data
            verdict: Final verdict ('malicious', 'suspicious', 'safe')
            
        Returns:
            True if action was successful
        """
        try:
            if verdict == 'malicious':
                # Send high-priority alert to Slack
                slack_notifier.send_alert(incident_data, 'malicious')
                logger.info("Malicious email detected - alert sent to Slack")
                
            elif verdict == 'suspicious':
                # Send suspicious alert to Slack
                slack_notifier.send_alert(incident_data, 'suspicious')
                logger.info("Suspicious email detected - alert sent to Slack")
                
            elif verdict == 'safe':
                # Send informational alert
                slack_notifier.send_alert(incident_data, 'safe')
                logger.info("Safe email confirmed")
            
            # Store incident in database
            tidb_manager.store_incident(incident_data)
            
            # Update statistics
            self._update_stats(verdict)
            
            return True
            
        except Exception as e:
            logger.error(f"Error taking action: {e}")
            return False
    
    def _update_stats(self, verdict: str):
        """Update processing statistics."""
        self.stats['total_processed'] += 1
        
        if verdict == 'malicious':
            self.stats['malicious_count'] += 1
        elif verdict == 'suspicious':
            self.stats['suspicious_count'] += 1
        else:
            self.stats['safe_count'] += 1
    
    def process_email(self, email_content: str) -> Dict:
        """
        Main workflow: Process a single email through all steps.
        
        Args:
            email_content: Raw email content (.eml format)
            
        Returns:
            Complete analysis results
        """
        start_time = time.time()
        
        try:
            logger.info("Starting email analysis workflow")
            
            # Step 1: Parse email and extract IOCs
            parsed_data = self.parse_email(email_content)
            if not parsed_data:
                raise Exception("Failed to parse email")
            
            # Step 2: Search threat intelligence
            threat_intel = self.search_threat_intelligence(parsed_data['extracted_iocs'])
            
            # Step 3: External reputation check (done in Step 2)
            external_scores = threat_intel['external_reputation']
            virustotal_score = virustotal_api.get_overall_score(external_scores)
            
            # Step 4: In-house model analysis
            inhouse_analysis = self.analyze_with_inhouse_model(parsed_data['email_body'])
            
            # Step 5: Synthesize and decide
            all_evidence = {
                **parsed_data,
                'vector_search': threat_intel['vector_search'],
                'threat_intel': threat_intel['threat_intel'],
                'external_reputation': external_scores,
                'virustotal_score': virustotal_score,
                'inhouse_model_score': inhouse_analysis.get('phishing_probability', 0.5) * 100,
                'inhouse_confidence': inhouse_analysis.get('confidence', 0.0) * 100
            }
            
            final_analysis = self.synthesize_and_decide(all_evidence)
            
            # Step 6: Take action
            incident_data = {
                **parsed_data,
                'virustotal_score': virustotal_score,
                'abuseipdb_score': 0,  # Would be implemented separately
                'inhouse_model_score': inhouse_analysis.get('phishing_probability', 0.5) * 100,
                'gemini_verdict': final_analysis.get('verdict', 'suspicious'),
                'gemini_summary': final_analysis.get('summary', 'No summary available'),
                'email_vector': self._create_email_vector(parsed_data['extracted_iocs'])
            }
            
            self.take_action(incident_data, final_analysis['verdict'])
            
            # Calculate processing time
            processing_time = time.time() - start_time
            self.stats['processing_times'].append(processing_time)
            
            logger.info(f"Email analysis completed in {processing_time:.2f} seconds")
            
            return {
                'incident_data': incident_data,
                'final_analysis': final_analysis,
                'processing_time': processing_time,
                'success': True
            }
            
        except Exception as e:
            logger.error(f"Error in email processing workflow: {e}")
            return {
                'error': str(e),
                'success': False
            }
    
    def get_statistics(self) -> Dict:
        """Get current processing statistics."""
        avg_time = 0
        if self.stats['processing_times']:
            avg_time = sum(self.stats['processing_times']) / len(self.stats['processing_times'])
        
        return {
            'total_processed': self.stats['total_processed'],
            'malicious_count': self.stats['malicious_count'],
            'suspicious_count': self.stats['suspicious_count'],
            'safe_count': self.stats['safe_count'],
            'avg_processing_time': avg_time,
            'automation_rate': 95.0  # Placeholder
        }

# Global instance for easy access
cerebral_guard = CerebralGuardAgent() 