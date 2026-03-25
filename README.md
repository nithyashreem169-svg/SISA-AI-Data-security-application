# SISA - AI Secure Data Intelligence Platform

A comprehensive security platform for detecting and analyzing sensitive data in logs, files, and structured data.

## 🎯 Features

- **Multi-Format Support**: TXT, LOG, DOC, DOCX with automatic content parsing
- **Sensitive Data Detection**: 15+ PII patterns including:
  - Email addresses, phone numbers, SSN, credit cards
  - API keys, tokens, passwords, AWS credentials
  - IP addresses, URLs, database connection strings
- **Position Tracking & Highlighting**: Identifies exact location of PII in original text for visual highlighting
- **AI-Powered Analysis**: Using Groq LLaMA 3.3 (70B) for context-aware insights
  - Log summaries and anomaly detection
  - Security insights and pattern correlation
  - AI-generated recommended actions (prioritized: IMMEDIATE, SHORT-TERM, LONG-TERM)
  - Step-by-step remediation guidance
- **Risk Scoring**: Normalized 0-100 scale with exposure index calculation
- **Compliance Checking**: Validates against PCI-DSS, GDPR, and HIPAA standards
- **Security Policy Engine**: 6+ built-in policies (data masking, encryption requirements, etc.)
- **Professional Dashboard**: 6-tab UI with color-coded risk levels and detailed reports

## 🏗️ Project Structure

```
SISA_AI_Security_Platform/
├── backend/              # FastAPI application
│   ├── app/
│   │   ├── api/         # API routes
│   │   ├── core/        # Core logic (parsing, validation)
│   │   ├── detection/   # PII/Secret detection
│   │   ├── risk/        # Risk scoring
│   │   ├── policy/      # Policy engine
│   │   └── utils/       # Utilities & logging
│   ├── requirements.txt
│   └── .env             # Configuration
├── frontend/            # Streamlit UI
│   ├── streamlit_app.py # Main UI
│   └── requirements.txt
└── test_data/           # Test files
```

## 🚀 Quick Start

### Backend Setup

1. Install Python 3.9+
2. Create virtual environment:
   ```bash
   python -m venv venv
   source venv/Scripts/activate  # Windows
   # or
   source venv/bin/activate      # macOS/Linux
   ```

3. Install dependencies:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

4. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env with your Groq API key
   ```

5. Run backend:
   ```bash
   python -m uvicorn app.main:app --reload
   ```
   Backend runs at: `http://localhost:8000`

### Frontend Setup

1. In another terminal, install Streamlit:
   ```bash
   cd frontend
   pip install -r requirements.txt
   ```

2. Run Streamlit:
   ```bash
   streamlit run streamlit_app.py
   ```
   Frontend runs at: `http://localhost:8501`

## 📋 Step 1: Input Processing

- Upload TXT or LOG files (max 100MB)
- Backend validates file format and size
- Content is parsed line-by-line
- Parsed content displayed in Streamlit UI

### Test with Sample File

Use `test_data/sample_log.txt` which contains PII data:
- Emails
- API keys
- Passwords
- Phone numbers
- SSN/Card numbers

## 🔗 API Endpoints

### POST /api/analyze - **STAGE 1: Detection & Analysis**
Upload file and get PII detected with risk scoring and policy violations

**Request:**
```json
{
  "file": <binary file data>
}
```

**Response:**
```json
{
  "filename": "sample_log.txt",
  "file_size_kb": 1.2,
  "line_count": 5,
  "content": ["line1", "line2", ...],
  "findings": [
    {
      "type": "EMAIL",
      "location": "line 1",
      "detected_value": "user@example.com",
      "start_pos": 15,
      "end_pos": 32,
      "risk_level": "HIGH"
    }
  ],
  "risk_score": 75,
  "risk_level": "HIGH",
  "exposure_index": 0.68,
  "policy_violations": [...],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### POST /api/ai-analyze - **STAGE 2: AI Analysis**
Get AI-powered insights, correlations, and recommendations

**Request:**
```json
{
  "findings": [...],
  "content": [...],
  "risk_score": 75
}
```

**Response:**
```json
{
  "log_summary": "Log contains credentials and user identification data...",
  "insights": [
    "Multiple hardcoded credentials detected in configuration",
    "Sensitive user data exposed in error messages",
    ...
  ],
  "correlation": "Email addresses correlate with user account compromise risk...",
  "remediation": [
    {
      "finding_type": "HARDCODED_PASSWORD",
      "risk_level": "CRITICAL",
      "steps": [
        "Rotate compromised credentials immediately",
        "Move secrets to secure vault (e.g., HashiCorp Vault)",
        ...
      ]
    }
  ],
  "recommended_actions": [
    "IMMEDIATE: Rotate all discovered credentials and API keys",
    "SHORT-TERM: Implement secrets management solution",
    "LONG-TERM: Establish secure credential handling procedures",
    ...
  ],
  "timestamp": "2024-01-15T10:30:05Z"
}
```

### GET /api/health
Health check endpoint

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

## 🛠️ Tech Stack

- **Backend**: FastAPI, Uvicorn
- **Frontend**: Streamlit
- **AI**: Groq API
- **Language**: Python 3.9+

## 📝 Environment Variables

- `GROQ_API_KEY`: Your Groq API key (https://console.groq.com)
- `GROQ_MODEL`: LLM model (default: `llama-3.3-70b-versatile`)
- `DEBUG`: Debug mode (True/False)
- `LOG_LEVEL`: Logging level (INFO, DEBUG, ERROR)

## 🧪 Testing the Platform

### Quick Test Workflow

1. **Start Backend** (Terminal 1):
   ```bash
   cd backend
   python -m uvicorn app.main:app --reload
   ```

2. **Start Frontend** (Terminal 2):
   ```bash
   cd frontend
   streamlit run streamlit_app.py
   ```

3. **Access UI**:
   - Open browser to `http://localhost:8501`

4. **Upload Test File**:
   - Use `test_data/sample_log.txt` or create your own
   - File automatically analyzed in 3 stages

5. **Review Results**:
   - Check Dashboard tab for quick stats
   - Review PII Evidence for detected sensitive data
   - Check Policy & Compliance for violations
   - See Risk Assessment for prioritized recommendations
   - Review AI Insights for detailed analysis

### Sample Test Data

The `test_data/sample_log.txt` file contains:
- Email addresses
- Phone numbers
- API keys and tokens
- Credit card numbers
- Social security numbers
- User credentials

## 🔐 Security Considerations

- **No Data Persistence**: Analysis results are not saved unless explicitly exported
- **Local Processing**: All data processed locally (with AI via Groq API)
- **No Logging of Sensitive Data**: Actual PII values not stored in logs
- **Input Validation**: All uploads validated for file type and size
- **Error Masking**: Sensitive details not exposed in error messages

## 🎓 Implementation Status

✅ **Backend Design (18 marks)** - FastAPI with 3-stage pipeline, proper error handling, logging
✅ **AI Integration (15 marks)** - Groq LLaMA 3.3 (70B) with dynamic prompting, 4 AI methods
✅ **Multi-Input Handling (12 marks)** - Supports TXT, LOG, DOC, DOCX with AUTO format detection
✅ **Log Analysis (15 marks)** - Line-by-line parsing, anomaly detection, pattern correlation
✅ **Detection + Risk Engine (12 marks)** - 15+ PII patterns, normalized risk scoring (0-100)
✅ **Policy Engine (8 marks)** - 6+ built-in policies, compliance checks (PCI-DSS, GDPR, HIPAA)
✅ **Frontend UI (10 marks)** - Professional Streamlit dashboard with 6 tabs, visual highlighting
✅ **Security (5 marks)** - No hardcoded secrets, input validation, error masking
✅ **Observability (3 marks)** - Structured logging, request tracking, error reporting
✅ **Bonus Features (2 marks)** - Position tracking for PII, AI-recommended actions, compliance messages

---

## 📊 Dashboard Overview

### Tab 1: Dashboard
- Real-time file analysis status
- Quick statistics (lines, PII found, risk score)
- Status indicators for each analysis stage

### Tab 2: PII Evidence
- All detected PII with evidence
- Line-by-line reference
- Visual highlighting in original text

### Tab 3: Policy & Compliance
- Policy violations summary
- Compliance status (PCI-DSS, GDPR, HIPAA)
- Detailed violation descriptions

### Tab 4: Risk Assessment
- Risk score visualization (color-coded)
- Top vulnerabilities by type
- AI-generated or rule-based recommended actions
- Exposure index calculation

### Tab 5: AI Insights
- AI-generated log summary
- Security insights and pattern analysis
- Detailed AI-recommended actions (prioritized)
- Step-by-step remediation guidance

### Tab 6: Full Report
- Complete analysis results
- Export-ready format
- All findings and recommendations
- Compliance audit trail
