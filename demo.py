"""
CerebralGuard Demo Script
Demonstrates the complete multi-step agentic workflow with sample phishing emails.
"""

import requests
import json
import time
from pathlib import Path
from loguru import logger

# Sample phishing emails for demonstration
SAMPLE_EMAILS = [
    {
        "name": "Microsoft Account Compromise",
        "content": """From: security@microsoft-support.com
Subject: URGENT: Your Microsoft Account Has Been Compromised
Date: Mon, 15 Jan 2024 10:30:00 +0000

Dear Microsoft User,

We have detected suspicious activity on your Microsoft account. Your account has been temporarily suspended for security reasons.

To restore access to your account immediately, please click the link below and verify your identity:

https://microsoft-verify.secure-login.com/account/verify

If you do not verify within 24 hours, your account will be permanently deleted.

This is an automated security message. Please do not reply to this email.

Microsoft Security Team"""
    },
    {
        "name": "PayPal Security Alert",
        "content": """From: security@paypal-alerts.com
Subject: Security Alert: Unusual Activity Detected
Date: Mon, 15 Jan 2024 11:45:00 +0000

Dear PayPal User,

We have detected unusual activity on your PayPal account. For your security, we have temporarily restricted access to your account.

To restore access, please verify your identity by clicking the link below:

https://paypal-verify.secure-login.net/account/restore

If you do not verify within 12 hours, your account will be permanently suspended.

Best regards,
PayPal Security Team"""
    },
    {
        "name": "Legitimate Newsletter",
        "content": """From: newsletter@techcrunch.com
Subject: Weekly Tech News Roundup
Date: Mon, 15 Jan 2024 09:00:00 +0000

Hi there,

Here's your weekly roundup of the latest tech news:

1. AI Breakthroughs in 2024
2. New Startup Funding Rounds
3. Tech Industry Trends

Read more at: https://techcrunch.com/weekly-roundup

Best regards,
TechCrunch Team"""
    }
]

def test_api_health():
    """Test if the API is running and healthy."""
    try:
        response = requests.get("http://localhost:8000/health")
        if response.status_code == 200:
            logger.info("✅ API is healthy and running")
            return True
        else:
            logger.error(f"❌ API health check failed: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        logger.error("❌ Cannot connect to API. Make sure it's running on http://localhost:8000")
        return False

def process_email(email_content, email_name):
    """Process a single email through CerebralGuard."""
    logger.info(f"🔍 Processing: {email_name}")
    
    try:
        response = requests.post(
            "http://localhost:8000/process-email",
            json={"email_content": email_content},
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            
            if result['success']:
                verdict = result['final_analysis']['verdict']
                summary = result['final_analysis']['summary']
                processing_time = result['processing_time']
                
                logger.info(f"✅ {email_name} - Verdict: {verdict.upper()}")
                logger.info(f"📝 Summary: {summary}")
                logger.info(f"⏱️ Processing time: {processing_time:.2f} seconds")
                
                return {
                    'success': True,
                    'verdict': verdict,
                    'summary': summary,
                    'processing_time': processing_time
                }
            else:
                logger.error(f"❌ {email_name} - Processing failed")
                return {'success': False}
        else:
            logger.error(f"❌ {email_name} - API error: {response.status_code}")
            return {'success': False}
            
    except Exception as e:
        logger.error(f"❌ {email_name} - Error: {str(e)}")
        return {'success': False}

def get_statistics():
    """Get current processing statistics."""
    try:
        response = requests.get("http://localhost:8000/statistics")
        if response.status_code == 200:
            stats = response.json()
            logger.info("📊 Current Statistics:")
            logger.info(f"   Total processed: {stats['total_processed']}")
            logger.info(f"   Malicious: {stats['malicious_count']}")
            logger.info(f"   Suspicious: {stats['suspicious_count']}")
            logger.info(f"   Safe: {stats['safe_count']}")
            logger.info(f"   Avg processing time: {stats['avg_processing_time']:.2f}s")
            logger.info(f"   Automation rate: {stats['automation_rate']:.1f}%")
            return stats
        else:
            logger.error(f"Failed to get statistics: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return None

def test_model_status():
    """Test the status of ML models and integrations."""
    try:
        response = requests.get("http://localhost:8000/model-status")
        if response.status_code == 200:
            status = response.json()
            logger.info("🤖 Model Status:")
            logger.info(f"   Gemini model: {'✅' if status['gemini_model_loaded'] else '❌'}")
            logger.info(f"   Phishing detector: {'✅' if status['phishing_detector_loaded'] else '❌'}")
            logger.info(f"   Database connected: {'✅' if status['database_connected'] else '❌'}")
            logger.info(f"   Slack configured: {'✅' if status['slack_configured'] else '❌'}")
            logger.info(f"   VirusTotal configured: {'✅' if status['virustotal_configured'] else '❌'}")
            return status
        else:
            logger.error(f"Failed to get model status: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"Error getting model status: {e}")
        return None

def run_demo():
    """Run the complete CerebralGuard demo."""
    logger.info("🚀 Starting CerebralGuard Demo")
    logger.info("=" * 50)
    
    # Test API health
    if not test_api_health():
        logger.error("Demo cannot continue - API is not available")
        return
    
    # Test model status
    test_model_status()
    logger.info("")
    
    # Get initial statistics
    initial_stats = get_statistics()
    logger.info("")
    
    # Process sample emails
    results = []
    for email_data in SAMPLE_EMAILS:
        result = process_email(email_data['content'], email_data['name'])
        results.append({
            'name': email_data['name'],
            'result': result
        })
        logger.info("")
        time.sleep(1)  # Brief pause between emails
    
    # Get final statistics
    final_stats = get_statistics()
    logger.info("")
    
    # Summary
    logger.info("📋 Demo Summary:")
    logger.info("=" * 50)
    
    successful_processing = sum(1 for r in results if r['result']['success'])
    logger.info(f"✅ Successfully processed: {successful_processing}/{len(results)} emails")
    
    if final_stats and initial_stats:
        new_processed = final_stats['total_processed'] - initial_stats['total_processed']
        logger.info(f"📈 New emails processed in this demo: {new_processed}")
    
    # Show verdicts
    logger.info("\n🎯 Verdicts:")
    for result in results:
        if result['result']['success']:
            verdict = result['result']['verdict']
            emoji = "🚨" if verdict == "malicious" else "⚠️" if verdict == "suspicious" else "✅"
            logger.info(f"   {emoji} {result['name']}: {verdict.upper()}")
    
    logger.info("\n🎉 Demo completed successfully!")
    logger.info("CerebralGuard is ready to defend your organization!")

def run_quick_test():
    """Run a quick test with the built-in test endpoint."""
    logger.info("🧪 Running Quick Test")
    
    try:
        response = requests.post("http://localhost:8000/test-email")
        if response.status_code == 200:
            result = response.json()
            logger.info("✅ Quick test completed successfully")
            logger.info(f"Verdict: {result['final_analysis']['verdict']}")
            logger.info(f"Summary: {result['final_analysis']['summary']}")
            return True
        else:
            logger.error(f"❌ Quick test failed: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ Quick test error: {e}")
        return False

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "quick":
        run_quick_test()
    else:
        run_demo() 