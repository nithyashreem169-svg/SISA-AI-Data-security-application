"""API Routes - Security Analysis Endpoints"""
from fastapi import APIRouter, File, UploadFile, HTTPException, Query, Body
from app.core.input_validator import InputValidator
from app.core.file_parser import FileParser
from app.core.ai_service import ai_analyzer
from app.detection.pii_detector import PIIDetector, LogAnalyzer
from app.policy.policy_engine import PolicyEngine
from app.risk.risk_engine import RiskEngine
from app.utils.logger import logger
import datetime

# Initialize analysis engines
pii_detector = PIIDetector()
log_analyzer = LogAnalyzer()
policy_engine = PolicyEngine()
risk_engine = RiskEngine()

router = APIRouter()

# =====================================================================
# ENDPOINT 1: FILE UPLOAD & VALIDATION
# =====================================================================

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload and parse file for analysis.
    Accepts: TXT, LOG, DOC, DOCX (max 100MB)
    """
    try:
        file_size = len(await file.read())
        await file.seek(0)
        
        is_valid, error_msg = InputValidator.validate_file(file.filename, file_size)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
        
        file_content = await file.read()
        logger.info(f"File received: {file.filename} ({file_size / 1024:.2f}KB)")
        
        success, lines, error_msg = FileParser.parse_file(file_content, file.filename)
        if not success:
            raise HTTPException(status_code=400, detail=error_msg)
        
        logger.info(f"File parsed: {len(lines)} lines")
        
        response = {
            "status": "success",
            "filename": file.filename,
            "file_type": file.filename.split('.')[-1].upper(),
            "file_size_kb": round(file_size / 1024, 2),
            "line_count": len(lines),
            "lines": lines
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# =====================================================================
# ENDPOINT 2: REGEX-BASED DETECTION
# =====================================================================

@router.post("/analyze")
async def analyze_file(
    request_data: dict = Body(...),
    include_policy: bool = Query(True),
    include_risk: bool = Query(True)
):
    """
    Detect sensitive patterns using regex.
    Includes policy enforcement and risk calculation.
    """
    try:
        lines = request_data.get('lines', [])
        filename = request_data.get('filename', 'input.log')
        
        if not lines:
            raise HTTPException(status_code=400, detail="No lines provided")
        
        logger.info(f"Starting pattern detection on {len(lines)} lines...")
        
        # Run regex detection
        pii_detector.reset()
        findings = pii_detector.analyze_batch(lines)
        
        findings_dicts = [
            {
                'type': f.type,
                'risk': f.risk,
                'line': f.line_number,
                'detected_value': f.detected_value,
                'confidence': f.confidence
            }
            for f in findings
        ]
        
        logger.info(f"Pattern detection complete: {len(findings_dicts)} findings")
        
        response = {
            "status": "success",
            "filename": filename,
            "lines_analyzed": len(lines),
            "total_findings": len(findings_dicts),
            "findings_by_risk": {
                'critical': len([f for f in findings_dicts if f['risk'] == 'critical']),
                'high': len([f for f in findings_dicts if f['risk'] == 'high']),
                'medium': len([f for f in findings_dicts if f['risk'] == 'medium']),
                'low': len([f for f in findings_dicts if f['risk'] == 'low'])
            },
            "findings": findings_dicts,
            "pattern_summary": pii_detector.get_summary()
        }
        
        # Optional: Apply policies
        if include_policy and findings_dicts:
            policy_results = policy_engine.apply_policies(findings_dicts)
            compliance = policy_engine.get_compliance_status(findings_dicts)
            
            response['policies'] = {
                'findings_with_actions': policy_results['findings_with_actions'],
                'actions_taken': policy_results['summary'],
                'compliance_status': compliance
            }
            logger.info("Policies applied")
        
        # Optional: Risk assessment
        if include_risk and findings_dicts:
            risk_report = risk_engine.generate_risk_report(findings_dicts, len(lines))
            response['risk_assessment'] = {
                'risk_score': risk_report['risk_score']['score'],
                'risk_level': risk_report['risk_score']['level'],
                'exposure_index': round(risk_report['exposure_index'], 2),
                'threat_level': risk_report['threat_assessment']['threat_level'],
                'top_vulnerabilities': risk_report['top_vulnerabilities'][:3],
                'recommended_actions': risk_report['recommended_actions'][:3]
            }
            logger.info(f"Risk assessment: Score {risk_report['risk_score']['score']}")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# =====================================================================
# ENDPOINT 3: AI-POWERED ANALYSIS
# =====================================================================

@router.post("/ai-analyze")
async def ai_analysis(
    request_data: dict = Body(...),
    enable_summary: bool = Query(True),
    enable_insights: bool = Query(True),
    enable_correlation: bool = Query(True),
    enable_remediation: bool = Query(True)
):
    """
    AI-powered analysis using Groq LLM.
    Requires: GROQ_API_KEY environment variable
    """
    try:
        lines = request_data.get('lines', [])
        findings = request_data.get('findings', [])
        filename = request_data.get('filename', 'input.log')
        
        if not ai_analyzer.is_enabled():
            raise HTTPException(
                status_code=503,
                detail="AI analysis not available - GROQ_API_KEY not configured"
            )
        
        logger.info(f"Starting AI analysis on {len(lines)} lines with {len(findings)} findings...")
        
        response = {
            "status": "success",
            "filename": filename,
            "ai_enabled": True,
            "analysis": {}
        }
        
        # Log summarization
        if enable_summary and lines:
            logger.info("Generating log summary...")
            summary = ai_analyzer.generate_log_summary(lines)
            if summary:
                response['analysis']['log_summary'] = summary
        
        # Security insights
        if enable_insights and findings:
            logger.info("Generating security insights...")
            insights = ai_analyzer.generate_insights_from_findings(findings)
            if insights:
                response['analysis']['security_insights'] = insights
        
        # Correlation analysis
        if enable_correlation and findings:
            logger.info("Analyzing correlations...")
            correlation = ai_analyzer.correlate_findings(findings)
            if correlation:
                response['analysis']['correlation_analysis'] = correlation
        
        # Remediation recommendations
        if enable_remediation and findings:
            logger.info("Generating remediation...")
            critical_findings = [f for f in findings if f.get('risk') == 'critical']
            
            remediations = []
            for finding in critical_findings[:3]:
                finding_type = finding.get('type', 'unknown')
                risk_level = finding.get('risk', 'unknown')
                remediation_text = ai_analyzer.generate_remediation_ai(finding_type, risk_level)
                
                if remediation_text:
                    remediations.append({
                        'finding_type': finding_type,
                        'risk_level': risk_level,
                        'steps': remediation_text
                    })
            
            if remediations:
                response['analysis']['remediation'] = remediations
        
        response['timestamp'] = datetime.datetime.now().isoformat()
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# =====================================================================
# UTILITY ENDPOINTS
# =====================================================================

@router.get("/health")
async def health_check():
    """Service health status"""
    return {
        "status": "healthy",
        "service": "SISA Security Platform",
        "version": "0.2.0",
        "ai_enabled": ai_analyzer.is_enabled()
    }


@router.get("/patterns")
async def get_patterns():
    """Get supported detection patterns"""
    from app.detection.regex_patterns import DETECTION_METHODS
    
    return {
        'total_patterns': len(DETECTION_METHODS),
        'pattern_types': list(DETECTION_METHODS.keys()),
        'description': 'Use POST /analyze endpoint to run detection'
    }


@router.get("/compliance-info")
async def get_compliance_info():
    """
    Get compliance checking methodology.
    
    Compliance is checked based on detected findings:
    - PCI-DSS: Checks for credit card data exposure
    - GDPR: Checks for personal data (SSN, email, phone)
    - HIPAA: Checks for sensitive data exposure
    
    These are not hardcoded - they are derived from:
    - Finding types detected (password, credit_card, ssn, etc.)
    - Risk levels assigned to each finding
    - Security policies applied
    """
    return {
        "compliance_standards": {
            "pci_dss": {
                "description": "Payment Card Industry Data Security Standard",
                "checked_for": "Credit card numbers detected",
                "violation": "Any credit card found in logs"
            },
            "gdpr": {
                "description": "General Data Protection Regulation",
                "checked_for": "Personal identification data (SSN, email, phone)",
                "violation": "Personal data exposed with high/critical risk"
            },
            "hipaa": {
                "description": "Health Insurance Portability and Accountability Act",
                "checked_for": "Sensitive protected health information",
                "violation": "Critical sensitive data found without proper protection"
            }
        },
        "how_compliance_works": {
            "step_1": "Run pattern detection via POST /analyze",
            "step_2": "Policy engine checks findings against compliance rules",
            "step_3": "Results indicate which standards are violated",
            "step_4": "See POST /analyze response under 'compliance_status'"
        },
        "api_note": "Compliance uses internal detection logic - no external APIs"
    }


@router.get("/risk-scoring-info")
async def get_risk_scoring():
    """Get risk scoring methodology"""
    return {
        "scoring_method": "Multi-factor weighted assessment",
        "scale": "0-100 (higher = riskier)",
        "factors": {
            "critical_findings": "25 points each",
            "high_findings": "15 points each",
            "credential_exposure": "30 points",
            "pci_violation": "25 points",
            "pii_exposure": "20 points",
            "information_leakage": "12 points",
            "pattern_concentration": "15 points",
            "volume_spike": "10 points"
        },
        "risk_levels": {
            "0-20": "minimal",
            "20-40": "low",
            "40-60": "medium",
            "60-80": "high",
            "80-100": "critical"
        }
    }
