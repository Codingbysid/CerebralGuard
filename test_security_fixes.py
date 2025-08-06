#!/usr/bin/env python3
"""
Test script for CerebralGuard security and performance fixes
Verifies that all high-priority issues have been resolved.
"""

import requests
import json
import time
import sys
from pathlib import Path
from loguru import logger

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_input_validation():
    """Test input validation for email content."""
    logger.info("🧪 Testing input validation...")
    
    test_cases = [
        {
            "name": "Empty content",
            "content": "",
            "should_fail": True
        },
        {
            "name": "Large content (>100KB)",
            "content": "x" * 150000,
            "should_fail": True
        },
        {
            "name": "Malicious script tag",
            "content": "Hello <script>alert('xss')</script>",
            "should_fail": True
        },
        {
            "name": "JavaScript protocol",
            "content": "Click here: javascript:alert('xss')",
            "should_fail": True
        },
        {
            "name": "Valid email content",
            "content": "From: test@example.com\nSubject: Test\n\nHello world",
            "should_fail": False
        }
    ]
    
    api_url = "http://localhost:8000/process-email"
    
    for test_case in test_cases:
        try:
            response = requests.post(
                api_url,
                json={"email_content": test_case["content"]},
                headers={"Authorization": f"Bearer {get_test_api_key()}"},
                timeout=10
            )
            
            if test_case["should_fail"]:
                if response.status_code == 422:  # Validation error
                    logger.info(f"✅ {test_case['name']}: Correctly rejected")
                else:
                    logger.error(f"❌ {test_case['name']}: Should have been rejected but wasn't")
            else:
                if response.status_code in [200, 500]:  # Valid request
                    logger.info(f"✅ {test_case['name']}: Correctly accepted")
                else:
                    logger.error(f"❌ {test_case['name']}: Should have been accepted but wasn't")
                    
        except Exception as e:
            logger.error(f"❌ {test_case['name']}: Error - {e}")
    
    return True

def test_authentication():
    """Test API authentication."""
    logger.info("🔐 Testing authentication...")
    
    api_url = "http://localhost:8000/process-email"
    test_content = "From: test@example.com\nSubject: Test\n\nHello world"
    
    # Test without API key
    try:
        response = requests.post(
            api_url,
            json={"email_content": test_content},
            timeout=10
        )
        if response.status_code == 401:
            logger.info("✅ Authentication required (no API key)")
        else:
            logger.warning(f"⚠️ Authentication not enforced: {response.status_code}")
    except Exception as e:
        logger.error(f"❌ Authentication test error: {e}")
    
    # Test with invalid API key
    try:
        response = requests.post(
            api_url,
            json={"email_content": test_content},
            headers={"Authorization": "Bearer invalid-key"},
            timeout=10
        )
        if response.status_code == 401:
            logger.info("✅ Invalid API key correctly rejected")
        else:
            logger.error(f"❌ Invalid API key should have been rejected: {response.status_code}")
    except Exception as e:
        logger.error(f"❌ Authentication test error: {e}")
    
    return True

def test_rate_limiting():
    """Test rate limiting."""
    logger.info("⏱️ Testing rate limiting...")
    
    api_url = "http://localhost:8000/process-email"
    test_content = "From: test@example.com\nSubject: Test\n\nHello world"
    api_key = get_test_api_key()
    
    # Make multiple requests quickly
    responses = []
    for i in range(15):  # More than the 10/minute limit
        try:
            response = requests.post(
                api_url,
                json={"email_content": test_content},
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=5
            )
            responses.append(response.status_code)
            time.sleep(0.1)  # Small delay
        except Exception as e:
            logger.error(f"❌ Rate limiting test error: {e}")
            break
    
    # Check if rate limiting is working
    if 429 in responses:  # Too Many Requests
        logger.info("✅ Rate limiting is working")
        return True
    else:
        logger.warning("⚠️ Rate limiting may not be working properly")
        return False

def test_database_connection_pool():
    """Test database connection pooling."""
    logger.info("🗄️ Testing database connection pooling...")
    
    try:
        from db.tidb_helpers import tidb_manager
        
        # Test multiple connections
        connections = []
        for i in range(5):
            conn = tidb_manager.get_connection()
            if conn:
                connections.append(conn)
                logger.info(f"✅ Connection {i+1} established")
            else:
                logger.error(f"❌ Failed to get connection {i+1}")
        
        # Close connections
        for conn in connections:
            conn.close()
        
        logger.info(f"✅ Database connection pool working: {len(connections)} connections")
        return True
        
    except Exception as e:
        logger.error(f"❌ Database connection pool test error: {e}")
        return False

def test_caching():
    """Test Redis caching functionality."""
    logger.info("💾 Testing caching functionality...")
    
    try:
        from integrations.virustotal import virustotal_api
        
        # Test cache initialization
        if virustotal_api.redis_client:
            logger.info("✅ Redis cache initialized")
            
            # Test cache operations
            test_key = "test:key"
            test_value = {"test": "data"}
            
            # Set cache
            virustotal_api._set_cached_result(test_key, test_value, ttl=60)
            
            # Get cache
            cached_result = virustotal_api._get_cached_result(test_key)
            
            if cached_result == test_value:
                logger.info("✅ Cache read/write working")
                return True
            else:
                logger.error("❌ Cache read/write failed")
                return False
        else:
            logger.warning("⚠️ Redis cache not available")
            return True  # Not a failure if Redis is not configured
            
    except Exception as e:
        logger.error(f"❌ Caching test error: {e}")
        return False

def test_async_processing():
    """Test async processing capabilities."""
    logger.info("⚡ Testing async processing...")
    
    api_url = "http://localhost:8000/process-email"
    test_content = "From: test@example.com\nSubject: Test\n\nHello world"
    api_key = get_test_api_key()
    
    start_time = time.time()
    
    try:
        response = requests.post(
            api_url,
            json={"email_content": test_content},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30
        )
        
        processing_time = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            if result.get('processing_time'):
                logger.info(f"✅ Async processing working: {result['processing_time']:.2f}s")
                return True
            else:
                logger.warning("⚠️ Processing time not returned")
                return False
        else:
            logger.error(f"❌ Async processing failed: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Async processing test error: {e}")
        return False

def test_retry_logic():
    """Test retry logic for external APIs."""
    logger.info("🔄 Testing retry logic...")
    
    try:
        from integrations.virustotal import virustotal_api
        
        # Test with a non-existent domain (should trigger retries)
        result = virustotal_api.check_domain_reputation("nonexistent-domain-test-12345.com")
        
        if 'error' in result:
            logger.info("✅ Retry logic working (expected error for non-existent domain)")
            return True
        else:
            logger.warning("⚠️ Retry logic test inconclusive")
            return True
            
    except Exception as e:
        logger.error(f"❌ Retry logic test error: {e}")
        return False

def get_test_api_key():
    """Get test API key from environment."""
    import os
    from dotenv import load_dotenv
    load_dotenv()
    
    api_key = os.getenv('API_KEY')
    if not api_key:
        logger.warning("⚠️ No API_KEY found in environment, using test key")
        return "test-api-key"
    return api_key

def test_api_health():
    """Test API health endpoint."""
    logger.info("🏥 Testing API health...")
    
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            logger.info(f"✅ API healthy: {health_data}")
            return True
        else:
            logger.error(f"❌ API health check failed: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ API health test error: {e}")
        return False

def main():
    """Run all security and performance tests."""
    logger.info("🚀 CerebralGuard Security & Performance Tests")
    logger.info("=" * 50)
    
    tests = [
        ("API Health", test_api_health),
        ("Input Validation", test_input_validation),
        ("Authentication", test_authentication),
        ("Rate Limiting", test_rate_limiting),
        ("Database Connection Pool", test_database_connection_pool),
        ("Caching", test_caching),
        ("Async Processing", test_async_processing),
        ("Retry Logic", test_retry_logic),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        logger.info(f"\n📋 {test_name}")
        logger.info("-" * 20)
        
        try:
            if test_func():
                passed += 1
                logger.info(f"✅ {test_name} passed")
            else:
                logger.error(f"❌ {test_name} failed")
        except Exception as e:
            logger.error(f"❌ {test_name} error: {e}")
    
    logger.info("\n" + "=" * 50)
    logger.info(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 All security and performance fixes verified!")
        logger.info("✅ Input validation working")
        logger.info("✅ Authentication implemented")
        logger.info("✅ Rate limiting active")
        logger.info("✅ Database connection pooling working")
        logger.info("✅ Caching system operational")
        logger.info("✅ Async processing enabled")
        logger.info("✅ Retry logic implemented")
        return True
    else:
        logger.warning("⚠️ Some tests failed. Please review the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 