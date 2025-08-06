"""
Slack Integration for CerebralGuard
Sends security alerts and notifications to Slack channels.
"""

import requests
import json
from typing import Dict, List, Optional
import os
from dotenv import load_dotenv
from loguru import logger
from datetime import datetime

# Load environment variables
load_dotenv()

class SlackNotifier:
    """Slack notification client for CerebralGuard."""
    
    def __init__(self):
        """Initialize Slack notifier."""
        self.webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        self.channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
        
        if not self.webhook_url:
            logger.warning("Slack webhook URL not found in environment variables")
    
    def send_alert(self, incident_data: Dict, alert_type: str = 'malicious') -> bool:
        """
        Send a security alert to Slack.
        
        Args:
            incident_data: Dictionary containing incident information
            alert_type: Type of alert ('malicious', 'suspicious', 'safe')
            
        Returns:
            True if successful, False otherwise
        """
        if not self.webhook_url:
            logger.error("Slack webhook URL not configured")
            return False
        
        try:
            # Create message based on alert type
            if alert_type == 'malicious':
                message = self._create_malicious_alert(incident_data)
            elif alert_type == 'suspicious':
                message = self._create_suspicious_alert(incident_data)
            else:
                message = self._create_info_alert(incident_data)
            
            # Send to Slack
            response = requests.post(
                self.webhook_url,
                json=message,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                logger.info(f"Slack alert sent successfully: {alert_type}")
                return True
            else:
                logger.error(f"Slack API error: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
            return False
    
    def _create_malicious_alert(self, incident_data: Dict) -> Dict:
        """Create a malicious email alert message."""
        return {
            "channel": self.channel,
            "username": "CerebralGuard",
            "icon_emoji": ":warning:",
            "attachments": [
                {
                    "color": "#ff0000",
                    "title": "🚨 MALICIOUS EMAIL DETECTED",
                    "title_link": "#",
                    "fields": [
                        {
                            "title": "Sender",
                            "value": incident_data.get('sender_email', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Subject",
                            "value": incident_data.get('subject', 'No subject'),
                            "short": True
                        },
                        {
                            "title": "VirusTotal Score",
                            "value": f"{incident_data.get('virustotal_score', 0)}/100",
                            "short": True
                        },
                        {
                            "title": "In-House Model Score",
                            "value": f"{incident_data.get('inhouse_model_score', 0):.1f}%",
                            "short": True
                        },
                        {
                            "title": "Analysis Summary",
                            "value": incident_data.get('gemini_summary', 'No summary available'),
                            "short": False
                        }
                    ],
                    "footer": "CerebralGuard Security System",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
    
    def _create_suspicious_alert(self, incident_data: Dict) -> Dict:
        """Create a suspicious email alert message."""
        return {
            "channel": self.channel,
            "username": "CerebralGuard",
            "icon_emoji": ":question:",
            "attachments": [
                {
                    "color": "#ffa500",
                    "title": "⚠️ SUSPICIOUS EMAIL DETECTED",
                    "title_link": "#",
                    "fields": [
                        {
                            "title": "Sender",
                            "value": incident_data.get('sender_email', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Subject",
                            "value": incident_data.get('subject', 'No subject'),
                            "short": True
                        },
                        {
                            "title": "VirusTotal Score",
                            "value": f"{incident_data.get('virustotal_score', 0)}/100",
                            "short": True
                        },
                        {
                            "title": "In-House Model Score",
                            "value": f"{incident_data.get('inhouse_model_score', 0):.1f}%",
                            "short": True
                        },
                        {
                            "title": "Analysis Summary",
                            "value": incident_data.get('gemini_summary', 'No summary available'),
                            "short": False
                        }
                    ],
                    "footer": "CerebralGuard Security System - Human review required",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
    
    def _create_info_alert(self, incident_data: Dict) -> Dict:
        """Create an informational alert message."""
        return {
            "channel": self.channel,
            "username": "CerebralGuard",
            "icon_emoji": ":white_check_mark:",
            "attachments": [
                {
                    "color": "#00ff00",
                    "title": "✅ SAFE EMAIL CONFIRMED",
                    "title_link": "#",
                    "fields": [
                        {
                            "title": "Sender",
                            "value": incident_data.get('sender_email', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Subject",
                            "value": incident_data.get('subject', 'No subject'),
                            "short": True
                        },
                        {
                            "title": "Analysis Summary",
                            "value": incident_data.get('gemini_summary', 'No summary available'),
                            "short": False
                        }
                    ],
                    "footer": "CerebralGuard Security System",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
    
    def send_daily_report(self, stats: Dict) -> bool:
        """
        Send a daily security report to Slack.
        
        Args:
            stats: Dictionary with daily statistics
                {
                    'total_emails': 100,
                    'malicious_count': 5,
                    'suspicious_count': 10,
                    'safe_count': 85,
                    'avg_processing_time': 1.5
                }
                
        Returns:
            True if successful, False otherwise
        """
        if not self.webhook_url:
            logger.error("Slack webhook URL not configured")
            return False
        
        try:
            message = {
                "channel": self.channel,
                "username": "CerebralGuard",
                "icon_emoji": ":bar_chart:",
                "attachments": [
                    {
                        "color": "#36a64f",
                        "title": "📊 Daily Security Report",
                        "title_link": "#",
                        "fields": [
                            {
                                "title": "Total Emails Processed",
                                "value": str(stats.get('total_emails', 0)),
                                "short": True
                            },
                            {
                                "title": "Malicious Emails",
                                "value": str(stats.get('malicious_count', 0)),
                                "short": True
                            },
                            {
                                "title": "Suspicious Emails",
                                "value": str(stats.get('suspicious_count', 0)),
                                "short": True
                            },
                            {
                                "title": "Safe Emails",
                                "value": str(stats.get('safe_count', 0)),
                                "short": True
                            },
                            {
                                "title": "Average Processing Time",
                                "value": f"{stats.get('avg_processing_time', 0):.2f} minutes",
                                "short": True
                            },
                            {
                                "title": "Automation Rate",
                                "value": f"{stats.get('automation_rate', 0):.1f}%",
                                "short": True
                            }
                        ],
                        "footer": "CerebralGuard Security System",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.webhook_url,
                json=message,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                logger.info("Daily report sent successfully")
                return True
            else:
                logger.error(f"Slack API error: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending daily report: {e}")
            return False
    
    def send_emergency_alert(self, message: str, severity: str = 'high') -> bool:
        """
        Send an emergency alert to Slack.
        
        Args:
            message: Emergency message
            severity: Severity level ('low', 'medium', 'high', 'critical')
            
        Returns:
            True if successful, False otherwise
        """
        if not self.webhook_url:
            logger.error("Slack webhook URL not configured")
            return False
        
        try:
            # Color based on severity
            colors = {
                'low': '#00ff00',
                'medium': '#ffff00',
                'high': '#ffa500',
                'critical': '#ff0000'
            }
            
            emojis = {
                'low': ':information_source:',
                'medium': ':warning:',
                'high': ':rotating_light:',
                'critical': ':fire:'
            }
            
            color = colors.get(severity, '#ff0000')
            emoji = emojis.get(severity, ':warning:')
            
            slack_message = {
                "channel": self.channel,
                "username": "CerebralGuard Emergency",
                "icon_emoji": emoji,
                "attachments": [
                    {
                        "color": color,
                        "title": f"{emoji} EMERGENCY ALERT - {severity.upper()}",
                        "text": message,
                        "footer": "CerebralGuard Security System",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.webhook_url,
                json=slack_message,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                logger.info(f"Emergency alert sent: {severity}")
                return True
            else:
                logger.error(f"Slack API error: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending emergency alert: {e}")
            return False

# Global instance for easy access
slack_notifier = SlackNotifier() 