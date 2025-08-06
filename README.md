# CerebralGuard: Autonomous AI Agent for Phishing Threat Detection

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![TiDB](https://img.shields.io/badge/TiDB-Serverless-orange.svg)](https://tidbcloud.com/)
[![Gemini](https://img.shields.io/badge/Gemini-API-purple.svg)](https://ai.google.dev/)

## 🧠 Vision

CerebralGuard is an autonomous, multi-step AI agent designed to automate the detection, analysis, and response to email-based phishing threats. In a world where phishing attacks are increasingly sophisticated, CerebralGuard acts as a force multiplier for security teams and provides an essential defensive layer for organizations lacking dedicated cybersecurity staff.

Our vision is to create a self-improving security agent that not only identifies threats with high accuracy but also learns from every interaction, building a unique, organization-specific threat intelligence database.

## 🎯 The Problem

Phishing remains the #1 entry vector for cyberattacks. Security teams are overwhelmed by the volume of suspicious emails reported by employees, leading to:

- **Analyst Burnout**: Manually analyzing hundreds of similar emails is tedious and inefficient
- **Slow Response Times**: The delay between a report and an analysis can be the window an attacker needs to succeed
- **Inconsistent Analysis**: Different analysts may come to different conclusions based on the same evidence
- **Resource Scarcity**: Small to medium-sized businesses (SMBs) often lack the budget or personnel to manage a phishing triage program effectively

## 🏗️ Architecture

CerebralGuard implements a sophisticated multi-step agentic workflow:

### Step 1: Ingest & Parse (Data Ingestion)
- Email listener service picks up new emails
- Gemini API parses raw email (.eml file), including headers, body, and attachments
- Extracts key Indicators of Compromise (IOCs): URLs, domains, sender IP address, email addresses, and attachment file hashes

### Step 2: Dual-Threat Search (Database Search)
- Connects to TiDB Serverless instance
- **Vector Search**: Email body converted to vector embedding, queried for semantically similar emails
- **Full-Text Search**: Extracted IOCs used for precise, full-text search against database

### Step 3: External Reputation Check (External Tool Invocation)
- Uses extracted IOCs to query external APIs for real-time reputation data
- **VirusTotal API**: Check reputation of URLs, domains, and file hashes
- **AbuseIPDB API**: Check reputation of sender's IP address

### Step 4: In-House AI Analysis (Custom ML Model)
- Full, cleaned text passed to custom-trained machine learning model
- Provides phishing probability score based on deep textual patterns learned from training data
- Acts as independent verification step

### Step 5: Synthesize & Decide (LLM Chaining)
- All collected evidence compiled into single context prompt
- Final call to Gemini API with comprehensive prompt
- LLM acts as "Senior Security Analyst," reviews all evidence, provides final verdict

### Step 6: Act & Learn (Automated Action & Feedback Loop)
- **Malicious**: Send high-priority alert to security Slack channel, block sender/domain
- **Suspicious**: Create ticket in Jira for human review
- **Safe**: Automatically reply to reporting employee, confirm email is safe
- **Learn**: Entire analysis vectorized and logged in TiDB Serverless database

## 🛠️ Technical Stack

- **Database**: TiDB Serverless (for vector and full-text search)
- **AI / LLM**: Google Gemini API
- **In-House AI**: Python, PyTorch, BERT-based transformer model
- **External APIs**: VirusTotal, AbuseIPDB, Slack
- **Backend**: Python (FastAPI)
- **Email Handling**: Python imaplib

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- TiDB Serverless account
- Google Gemini API key
- VirusTotal API key (optional)
- Slack webhook URL (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cerebralguard
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   cp env.example .env
   # Edit .env with your API keys and configuration
   ```

4. **Initialize the database**
   ```bash
   python -c "from db.tidb_helpers import tidb_manager; tidb_manager.initialize_database()"
   ```

5. **Start the application**
   ```bash
   python app.py
   ```

The API will be available at `http://localhost:8000`

### Environment Variables

Create a `.env` file with the following variables:

```env
# TiDB Serverless Configuration
TIDB_HOST=your-tidb-host.tidbcloud.com
TIDB_PORT=4000
TIDB_USER=your-username
TIDB_PASSWORD=your-password
TIDB_DATABASE=cerebralguard

# Google Gemini API
GEMINI_API_KEY=your-gemini-api-key

# External API Keys
VIRUSTOTAL_API_KEY=your-virustotal-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-api-key

# Slack Integration
SLACK_WEBHOOK_URL=your-slack-webhook-url
SLACK_CHANNEL=#security-alerts

# Email Configuration
EMAIL_HOST=imap.gmail.com
EMAIL_PORT=993
EMAIL_USER=phishing@yourcompany.com
EMAIL_PASSWORD=your-app-password

# Model Configuration
MODEL_SAVE_PATH=./models/saved/
TRAINING_DATA_PATH=./data/
```

## 📊 API Endpoints

### Core Endpoints

- `GET /` - API information and available endpoints
- `GET /health` - System health check
- `POST /process-email` - Process a suspicious email through the complete workflow
- `GET /statistics` - Get processing statistics
- `GET /model-status` - Check status of ML models and integrations

### Utility Endpoints

- `POST /test-email` - Test with a sample phishing email
- `POST /send-daily-report` - Send daily security report to Slack
- `POST /send-emergency-alert` - Send emergency alert to Slack

### Example Usage

```python
import requests

# Process a suspicious email
email_content = """
From: suspicious@malicious.com
Subject: URGENT: Your account has been compromised
Date: Mon, 15 Jan 2024 10:30:00 +0000

Dear user,

Your account has been compromised. Click here to verify:
https://malicious-site.com/verify

Best regards,
Security Team
"""

response = requests.post(
    "http://localhost:8000/process-email",
    json={"email_content": email_content}
)

result = response.json()
print(f"Verdict: {result['final_analysis']['verdict']}")
print(f"Summary: {result['final_analysis']['summary']}")
```

## 🧪 Testing

### Test with Sample Email

```bash
curl -X POST "http://localhost:8000/test-email"
```

### Check System Health

```bash
curl "http://localhost:8000/health"
```

### Get Statistics

```bash
curl "http://localhost:8000/statistics"
```

## 📈 Success Metrics

- **Automation Rate**: >95% of reported emails triaged without human intervention
- **Accuracy**: False Positive Rate < 2%, False Negative Rate < 1%
- **Processing Time**: Average time from email receipt to final verdict < 2 minutes

## 🔧 Customization

### Training Your Own Model

1. **Prepare training data**:
   ```python
   from models.content_model import phishing_detector
   
   # Generate synthetic data
   synthetic_data = phishing_detector.generate_synthetic_data(1000)
   
   # Train the model
   phishing_detector.train(synthetic_data, epochs=3)
   ```

2. **Add custom threat intelligence**:
   ```python
   from db.tidb_helpers import tidb_manager
   
   # Add known malicious indicators
   tidb_manager.add_threat_intelligence(
       ioc_type='domain',
       value='malicious.com',
       threat_level='high',
       source='manual'
   )
   ```

### Customizing Alerts

Modify the Slack integration in `integrations/slack.py` to customize alert formats and channels.

## 🏆 Hackathon Features

This project demonstrates:

1. **Multi-Step Agentic Workflow**: Complete 6-step autonomous process
2. **LLM Chaining**: Gemini API used for both IOC extraction and final synthesis
3. **Custom ML Model**: BERT-based transformer for independent analysis
4. **Vector Search**: TiDB Serverless for semantic similarity search
5. **External Tool Integration**: VirusTotal and AbuseIPDB APIs
6. **Automated Actions**: Slack alerts and database storage
7. **Learning Loop**: Continuous improvement through data collection

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Google Gemini API for advanced language understanding
- TiDB Cloud for scalable vector and full-text search
- VirusTotal for comprehensive threat intelligence
- The open-source community for the amazing tools that make this possible

---

**CerebralGuard**: Defending organizations with autonomous AI intelligence. 