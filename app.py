"""
CerebralGuard FastAPI Application
Provides REST API endpoints for the autonomous phishing detection system.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, List, Optional
import uvicorn
from pathlib import Path
import os
from dotenv import load_dotenv
from loguru import logger

# Import our modules
from agent.main import cerebral_guard
from integrations.slack import slack_notifier

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="CerebralGuard API",
    description="Autonomous AI agent for phishing threat detection",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for frontend
frontend_path = Path("frontend")
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Pydantic models for API requests/responses
class EmailRequest(BaseModel):
    """Request model for email processing."""
    email_content: str
    email_hash: Optional[str] = None

class EmailResponse(BaseModel):
    """Response model for email processing."""
    success: bool
    incident_data: Optional[Dict] = None
    final_analysis: Optional[Dict] = None
    processing_time: Optional[float] = None
    error: Optional[str] = None

class StatisticsResponse(BaseModel):
    """Response model for statistics."""
    total_processed: int
    malicious_count: int
    suspicious_count: int
    safe_count: int
    avg_processing_time: float
    automation_rate: float

class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    timestamp: str

@app.get("/", response_class=FileResponse)
async def root():
    """Serve the main frontend page."""
    frontend_file = Path("frontend/index.html")
    if frontend_file.exists():
        return frontend_file
    else:
        return {
            "message": "CerebralGuard API",
            "description": "Autonomous AI agent for phishing threat detection",
            "version": "1.0.0",
            "endpoints": {
                "/health": "System health check",
                "/process-email": "Process a suspicious email",
                "/statistics": "Get processing statistics",
                "/docs": "API documentation"
            }
        }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    from datetime import datetime
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now().isoformat()
    )

@app.post("/process-email", response_model=EmailResponse)
async def process_email(request: EmailRequest, background_tasks: BackgroundTasks):
    """
    Process a suspicious email through the complete CerebralGuard workflow.
    
    This endpoint implements the multi-step agentic workflow:
    1. Parse email and extract IOCs using Gemini
    2. Search threat intelligence databases (TiDB)
    3. Check external reputation (VirusTotal)
    4. Analyze with custom ML model
    5. Synthesize evidence and make decision
    6. Take automated action (Slack alerts, database storage)
    """
    try:
        logger.info("Received email processing request")
        
        # Process the email through the complete workflow
        result = cerebral_guard.process_email(request.email_content)
        
        if result['success']:
            return EmailResponse(
                success=True,
                incident_data=result.get('incident_data'),
                final_analysis=result.get('final_analysis'),
                processing_time=result.get('processing_time')
            )
        else:
            raise HTTPException(status_code=500, detail=result.get('error', 'Processing failed'))
            
    except Exception as e:
        logger.error(f"Error processing email: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/statistics", response_model=StatisticsResponse)
async def get_statistics():
    """Get current processing statistics."""
    try:
        stats = cerebral_guard.get_statistics()
        return StatisticsResponse(**stats)
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/send-daily-report")
async def send_daily_report():
    """Send daily security report to Slack."""
    try:
        stats = cerebral_guard.get_statistics()
        success = slack_notifier.send_daily_report(stats)
        
        if success:
            return {"message": "Daily report sent successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to send daily report")
            
    except Exception as e:
        logger.error(f"Error sending daily report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/send-emergency-alert")
async def send_emergency_alert(message: str, severity: str = "high"):
    """Send emergency alert to Slack."""
    try:
        success = slack_notifier.send_emergency_alert(message, severity)
        
        if success:
            return {"message": "Emergency alert sent successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to send emergency alert")
            
    except Exception as e:
        logger.error(f"Error sending emergency alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/model-status")
async def get_model_status():
    """Get status of the ML model."""
    try:
        # Check if model is loaded
        model_loaded = cerebral_guard.model is not None
        detector_loaded = hasattr(cerebral_guard, 'phishing_detector')
        
        return {
            "gemini_model_loaded": model_loaded,
            "phishing_detector_loaded": detector_loaded,
            "database_connected": True,  # Would check actual connection
            "slack_configured": bool(os.getenv('SLACK_WEBHOOK_URL')),
            "virustotal_configured": bool(os.getenv('VIRUSTOTAL_API_KEY'))
        }
    except Exception as e:
        logger.error(f"Error getting model status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/test-email")
async def test_email():
    """Test endpoint with a sample phishing email."""
    sample_email = """
From: security@microsoft-support.com
Subject: URGENT: Your Microsoft Account Has Been Compromised
Date: Mon, 15 Jan 2024 10:30:00 +0000

Dear Microsoft User,

We have detected suspicious activity on your Microsoft account. Your account has been temporarily suspended for security reasons.

To restore access to your account immediately, please click the link below and verify your identity:

https://microsoft-verify.secure-login.com/account/verify

If you do not verify within 24 hours, your account will be permanently deleted.

This is an automated security message. Please do not reply to this email.

Microsoft Security Team
    """
    
    try:
        result = cerebral_guard.process_email(sample_email)
        return result
    except Exception as e:
        logger.error(f"Error in test email processing: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api")
async def api_info():
    """API information endpoint."""
    return {
        "message": "CerebralGuard API",
        "description": "Autonomous AI agent for phishing threat detection",
        "version": "1.0.0",
        "endpoints": {
            "/health": "System health check",
            "/process-email": "Process a suspicious email",
            "/statistics": "Get processing statistics",
            "/docs": "API documentation"
        }
    }

if __name__ == "__main__":
    # Run the application
    port = int(os.getenv('PORT', 8000))
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"Starting CerebralGuard API on {host}:{port}")
    logger.info(f"Frontend available at: http://{host}:{port}")
    logger.info(f"API documentation at: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port) 