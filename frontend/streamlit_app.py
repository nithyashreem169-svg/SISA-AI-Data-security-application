"""
SISA - AI Security Intelligence Platform
Advanced Frontend with Dashboard, PII Highlighting, and Compliance Tracking
"""

import streamlit as st
import requests
import json
from datetime import datetime
import html
import logging
import os
from io import BytesIO

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="SISA AI Security Platform",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== PROFESSIONAL STYLING ====================
st.markdown("""
<style>
    * {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    /* Main container */
    .main {
        background-color: #f8f9fa;
    }
    
    /* Header styling */
    .header-main {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 30px;
        border-radius: 10px;
        margin-bottom: 20px;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
    }
    
    .header-main h1 {
        margin: 0;
        font-size: 2.5em;
        font-weight: bold;
    }
    
    .header-main p {
        margin: 5px 0 0 0;
        font-size: 1.1em;
        opacity: 0.95;
    }
    
    /* Dashboard metrics */
    .metric-card {
        background: white;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
    }
    
    .metric-card.critical {
        border-left-color: #dc3545;
    }
    
    .metric-card.high {
        border-left-color: #fd7e14;
    }
    
    .metric-card.medium {
        border-left-color: #ffc107;
    }
    
    .metric-card.low {
        border-left-color: #28a745;
    }
    
    /* Status badges */
    .status-badge {
        display: inline-block;
        padding: 8px 15px;
        border-radius: 20px;
        font-weight: bold;
        margin: 5px 5px 5px 0;
    }
    
    .status-compliant {
        background-color: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
    }
    
    .status-non-compliant {
        background-color: #f8d7da;
        color: #721c24;
        border: 1px solid #f5c6cb;
    }
    
    /* PII Finding card */
    .pii-finding {
        background: white;
        border-radius: 8px;
        padding: 15px;
        margin: 10px 0;
        border-left: 4px solid #667eea;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    
    .pii-finding.critical {
        border-left-color: #dc3545;
        background: #ffe5e5;
    }
    
    .pii-finding.high {
        border-left-color: #fd7e14;
        background: #fff5e6;
    }
    
    .pii-finding.medium {
        border-left-color: #ffc107;
        background: #fffae6;
    }
    
    .pii-finding.low {
        border-left-color: #28a745;
        background: #f0f7f0;
    }
    
    /* Evidence line styling */
    .evidence-line {
        background-color: #f8f9fa;
        padding: 12px;
        border-radius: 5px;
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
        margin: 10px 0;
        border: 1px solid #dee2e6;
        word-break: break-word;
    }
    
    .pii-highlight {
        background-color: #ffeb3b;
        color: #000;
        font-weight: bold;
        padding: 2px 4px;
        border-radius: 3px;
    }
    
    /* Success/Error boxes */
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #c3e6cb;
        margin: 10px 0;
    }
    
    .error-box {
        background-color: #f8d7da;
        color: #721c24;
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #f5c6cb;
        margin: 10px 0;
    }
    
    .warning-box {
        background-color: #fff3cd;
        color: #856404;
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #ffeeba;
        margin: 10px 0;
    }
    
    .info-box {
        background-color: #d1ecf1;
        color: #0c5460;
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #bee5eb;
        margin: 10px 0;
    }
    
    /* Sidebar styling */
    .sidebar-section {
        margin: 20px 0;
        padding: 15px;
        background: white;
        border-radius: 8px;
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 5px 5px 0 0;
        font-weight: 500;
    }
</style>
""", unsafe_allow_html=True)

# ==================== SIDEBAR CONFIGURATION ====================
with st.sidebar:
    st.markdown("### Configuration")
    default_backend_url = os.getenv("BACKEND_URL", "http://localhost:8000/api")
    backend_url = st.text_input(
        "Backend URL",
        value=default_backend_url,
        help="FastAPI backend endpoint"
    )
    
    st.divider()
    
    st.markdown("### Analysis Options")
    enable_pii = st.checkbox("PII Detection", value=True)
    enable_policy = st.checkbox("Policy Check", value=True)
    enable_risk = st.checkbox("Risk Assessment", value=True)
    enable_ai = st.checkbox("AI Analysis", value=True, help="Use AI for insights, correlation, and remediation")
    
    st.divider()
    
    st.markdown("### Test Files")
    test_file_option = st.radio(
        "Select mode:",
        ["Upload Custom File", "Use Test Data"],
        help="Choose between uploading your own file or using predefined test data"
    )
    
    test_file_selection = None
    if test_file_option == "Use Test Data":
        test_file_selection = st.selectbox(
            "Choose test file:",
            [
                "Sample Log TXT",
                "Server Events (.log)",
                "Audit Log (.doc)",
                "Compliance Report (.docx)"
            ],
            help="Sample test files with unbalanced safe/unsafe elements for analysis testing"
        )
    
    st.divider()
    
    st.markdown("### About")
    st.info(
        "**SISA Platform**\n\n"
        "Security analysis tool for:\n"
        "• Automatic PII detection\n"
        "• Security policy enforcement\n"
        "• Risk scoring & assessment\n"
        "• Compliance checking\n"
        "\n**Supported:** TXT, LOG, DOC, DOCX"
    )

# ==================== MAIN HEADER ====================
st.markdown("""
<div class="header-main">
    <h1>SISA AI Security Platform</h1>
    <p>Advanced Security Analysis & Threat Detection Dashboard</p>
</div>
""", unsafe_allow_html=True)

# ==================== FILE UPLOAD SECTION ====================
st.markdown("## Upload & Analyze")

col1, col2 = st.columns([3, 1])

uploaded_file = None

# Load test file if selected
if test_file_option == "Use Test Data":
    st.info(f"Using test file: {test_file_selection}")
    test_file_path = None
    test_file_name = None
    
    # Resolve paths relative to project root (one level up from frontend/)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    if test_file_selection == "Sample Log TXT":
        test_file_path = os.path.join(project_root, "test_data", "sample_log.txt")
        test_file_name = "sample_log.txt"
    elif test_file_selection == "Server Events (.log)":
        test_file_path = os.path.join(project_root, "test_data", "server_events.log")
        test_file_name = "server_events.log"
    elif test_file_selection == "Audit Log (.doc)":
        test_file_path = os.path.join(project_root, "test_data", "audit_log.doc")
        test_file_name = "audit_log.doc"
    elif test_file_selection == "Compliance Report (.docx)":
        test_file_path = os.path.join(project_root, "test_data", "compliance_report.docx")
        test_file_name = "compliance_report.docx"
    
    if test_file_path and os.path.exists(test_file_path):
        with open(test_file_path, 'rb') as f:
            file_content = f.read()
        
        # Create a file-like object
        from io import BytesIO
        uploaded_file = BytesIO(file_content)
        uploaded_file.name = test_file_name
        uploaded_file.size = len(file_content)
        uploaded_file.type = "application/octet-stream" if test_file_name.endswith('.docx') else "text/plain"
        
        with col1:
            st.success(f"Loaded: {test_file_name}")
        with col2:
            file_size_mb = len(file_content) / (1024 * 1024)
            st.metric("File Size", f"{file_size_mb:.2f} MB")
        
        st.info("Test file loaded. Click 'Start Analysis' below to scan for security threats.")
    else:
        st.error(f"Test file not found at: {test_file_path}")
else:
    with col1:
        uploaded_file = st.file_uploader(
            "Choose a security log file",
            type=["txt", "log", "doc", "docx"],
            help="Upload TXT, LOG, DOC, or DOCX files for analysis"
        )
    
    with col2:
        if uploaded_file:
            file_size_mb = uploaded_file.size / (1024 * 1024)
            st.metric("File Size", f"{file_size_mb:.2f} MB")


# ==================== ANALYSIS FLOW ====================
if uploaded_file:
    if st.button("Start Analysis", use_container_width=True, type="primary"):
        analysis_placeholder = st.empty()
        
        try:
            # STAGE 1: Upload
            with analysis_placeholder.container():
                st.info("Stage 1/2: Uploading and parsing file...")
            
            files = {"file": (uploaded_file.name, uploaded_file, uploaded_file.type)}
            upload_response = requests.post(
                f"{backend_url}/upload",
                files=files,
                timeout=60
            )
            
            if upload_response.status_code != 200:
                error_data = upload_response.json()
                st.markdown(f"""<div class='error-box'>
                    <strong>Upload Error:</strong> {error_data.get('detail', 'Unknown error')}
                </div>""", unsafe_allow_html=True)
                st.stop()
            
            upload_data = upload_response.json()
            
            # STAGE 2: Analyze
            with analysis_placeholder.container():
                st.info("Stage 2/2: Analyzing for security threats...")
            
            analyze_payload = {
                "lines": upload_data.get("lines", []),
                "filename": upload_data.get("filename", "")
            }
            
            analyze_params = {
                "include_policy": enable_policy,
                "include_risk": enable_risk
            }
            
            analyze_response = requests.post(
                f"{backend_url}/analyze",
                json=analyze_payload,
                params=analyze_params,
                timeout=60
            )
            
            if analyze_response.status_code != 200:
                error_data = analyze_response.json()
                st.markdown(f"""<div class='error-box'>
                    <strong>Analysis Error:</strong> {error_data.get('detail', 'Unknown error')}
                </div>""", unsafe_allow_html=True)
                st.stop()
            
            analysis_placeholder.empty()
            
            result_data = analyze_response.json()
            
            # If PII detection is disabled, clear findings
            if not enable_pii:
                result_data['findings'] = []
                result_data['total_findings'] = 0
                result_data['findings_by_risk'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            findings = result_data.get('findings', [])
            total_findings = result_data.get('total_findings', 0)
            findings_by_risk = result_data.get('findings_by_risk', {})
            
            # STAGE 3: AI Analysis (optional)
            ai_analysis = None
            if enable_ai and findings:
                with analysis_placeholder.container():
                    st.info("Stage 3/3: Running AI analysis...")
                
                try:
                    risk_score = 0
                    if 'risk_assessment' in result_data:
                        risk_score = result_data['risk_assessment'].get('risk_score', 0)
                    
                    ai_payload = {
                        "lines": result_data.get("content", []),
                        "findings": findings,
                        "filename": upload_data.get("filename", ""),
                        "risk_score": risk_score
                    }
                    
                    ai_response = requests.post(
                        f"{backend_url}/ai-analyze",
                        json=ai_payload,
                        timeout=60
                    )
                    
                    if ai_response.status_code == 200:
                        ai_analysis = ai_response.json()
                    else:
                        st.warning("AI analysis failed, but continuing with other results...")
                except Exception as e:
                    st.warning(f"AI analysis skipped: {str(e)}")
                
                analysis_placeholder.empty()
            
            # ==================== DASHBOARD (KPI Section) ====================
            st.markdown("## Security Analysis Dashboard")
            
            # Key metrics row
            kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5 = st.columns(5)
            
            with kpi_col1:
                st.metric(
                    "Total Findings",
                    total_findings,
                    delta="issues detected" if total_findings > 0 else "clean"
                )
            
            with kpi_col2:
                critical_count = findings_by_risk.get('critical', 0)
                st.metric("Critical", critical_count)
            
            with kpi_col3:
                high_count = findings_by_risk.get('high', 0)
                st.metric("High", high_count)
            
            with kpi_col4:
                medium_count = findings_by_risk.get('medium', 0)
                st.metric("Medium", medium_count)
            
            with kpi_col5:
                low_count = findings_by_risk.get('low', 0)
                st.metric("Low", low_count)
            
            st.divider()
            
            # ==================== MAIN CONTENT TABS ====================
            tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
                "Dashboard",
                "PII Evidence",
                "Policy & Compliance",
                "Risk Assessment",
                "AI Insights",
                "Full Report"
            ])
            
            # ==================== TAB 1: DASHBOARD ====================
            with tab1:
                st.markdown("### Executive Summary")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"""
                    **File Information:**
                    - Filename: {upload_data.get('filename', 'N/A')}
                    - Type: {upload_data.get('file_type', 'N/A')}
                    - Size: {upload_data.get('file_size_kb', 0):.2f} KB
                    - Lines: {result_data.get('lines_analyzed', 0)}
                    """)
                
                with col2:
                    if 'risk_assessment' in result_data:
                        risk_data = result_data['risk_assessment']
                        st.markdown(f"""
                        **Risk Assessment:**
                        - Risk Score: **{risk_data.get('risk_score', 0)}/100**
                        - Level: **{risk_data.get('risk_level', 'N/A').upper()}**
                        - Exposure: {risk_data.get('exposure_index', 0) * 100:.1f}%
                        """)
                
                st.divider()
                
                # Pattern summary
                st.markdown("### Detection Patterns Found")
                if 'pattern_summary' in result_data:
                    pattern_data = result_data['pattern_summary']
                    
                    col1, col2, col3 = st.columns(3)
                    pattern_list = list(pattern_data.items())
                    
                    for idx, (pattern, count) in enumerate(pattern_list):
                        if idx % 3 == 0:
                            col = col1
                        elif idx % 3 == 1:
                            col = col2
                        else:
                            col = col3
                        
                        with col:
                            st.markdown(f"""
                            <div class='metric-card'>
                                <strong>{pattern}</strong><br>
                                <span style='font-size: 1.8em; color: #667eea;'>{count}</span> detected
                            </div>
                            """, unsafe_allow_html=True)
                
                # Suspicious patterns from LogAnalyzer
                suspicious = result_data.get('suspicious_patterns', [])
                if suspicious:
                    st.divider()
                    st.markdown("### Suspicious Patterns Detected")
                    for sp in suspicious:
                        sp_type = sp.get('type', 'unknown')
                        sp_severity = sp.get('severity', 'medium')
                        sp_desc = sp.get('description', '')
                        severity_color = {'low': '#28a745', 'medium': '#ffc107', 'high': '#fd7e14', 'critical': '#dc3545'}.get(sp_severity, '#ffc107')
                        st.markdown(f"""
                        <div class='metric-card' style='border-left-color: {severity_color};'>
                            <strong>{sp_type.replace('_', ' ').upper()}</strong>
                            <span style='float: right; color: {severity_color}; font-weight: bold;'>{sp_severity.upper()}</span>
                            <br><span style='color: #555;'>{sp_desc}</span>
                        </div>
                        """, unsafe_allow_html=True)
                
                # Log-level insights from LogAnalyzer
                log_insights = result_data.get('log_insights', [])
                if log_insights:
                    st.divider()
                    st.markdown("### Log Analysis Insights")
                    for insight in log_insights:
                        st.markdown(f"• {insight}")
            
            # ==================== TAB 2: PII EVIDENCE (NEW) ====================
            with tab2:
                st.markdown("### Detected Sensitive Data")
                
                if findings:
                    # Filter by risk level
                    risk_filter = st.selectbox(
                        "Filter by risk level",
                        ["All", "Critical", "High", "Medium", "Low"],
                        key="risk_filter"
                    )
                    
                    # Display findings with evidence lines
                    for idx, finding in enumerate(findings):
                        finding_type = finding.get('type', 'Unknown')
                        finding_risk = finding.get('risk', 'low')
                        line_number = finding.get('line', 'N/A')
                        detected_value = finding.get('detected_value', '***REDACTED***')
                        confidence = finding.get('confidence', 0)
                        
                        # Filter check
                        if risk_filter != "All" and finding_risk.lower() != risk_filter.lower():
                            continue
                        
                        # PII Finding Card
                        st.markdown(f"""
                        <div class='pii-finding {finding_risk}'>
                            <strong>Detection #{idx + 1}: {finding_type.upper()}</strong>
                            <span style='float: right; font-size: 0.9em;'>Line {line_number}</span>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Details
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.write(f"**Type:** {finding_type}")
                        with col2:
                            st.write(f"**Risk:** {finding_risk.upper()}")
                        with col3:
                            st.write(f"**Confidence:** {confidence}%")
                        
                        # Evidence line from original content
                        if line_number != 'N/A' and isinstance(line_number, int) and line_number <= len(upload_data.get('lines', [])):
                            evidence_line = upload_data.get('lines', [])[line_number - 1]
                            
                            # Build highlighted evidence safely
                            try:
                                matched_text = detected_value
                                
                                # Find the match position and build escaped HTML
                                match_idx = evidence_line.find(matched_text)
                                if match_idx >= 0:
                                    before = html.escape(evidence_line[:match_idx])
                                    match_html = f'<mark style="background-color: #ffeb3b; font-weight: bold; padding: 2px 4px; border-radius: 3px;">{html.escape(matched_text)}</mark>'
                                    after = html.escape(evidence_line[match_idx + len(matched_text):])
                                    highlighted_evidence = before + match_html + after
                                else:
                                    highlighted_evidence = html.escape(evidence_line)
                            except Exception as e:
                                highlighted_evidence = html.escape(evidence_line)
                            
                            safe_line = html.escape(evidence_line)
                            
                            st.markdown(f"""
                            <div class="evidence-line">
                                <strong>Evidence Line {line_number}:</strong><br>
                                <code>{safe_line}</code><br><br>
                                <strong style="color: #fd7e14;">Highlighted Match:</strong><br>
                                <div>{highlighted_evidence}</div>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        st.divider()
                else:
                    st.markdown("""<div class='success-box'>
                        <strong>No sensitive data detected!</strong><br>
                        The file appears to be clean of PII and sensitive information.
                    </div>""", unsafe_allow_html=True)
            
            # ==================== TAB 3: POLICY & COMPLIANCE ====================
            with tab3:
                st.markdown("### Policy Enforcement & Compliance")
                
                if 'policies' in result_data:
                    policies_data = result_data['policies']
                    compliance = policies_data.get('compliance_status', {})
                    
                    # Compliance badges
                    st.markdown("#### Compliance Status")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        pci_compliant = compliance.get('pci_dss_compliant', False)
                        status_class = 'status-compliant' if pci_compliant else 'status-non-compliant'
                        status_text = 'COMPLIANT' if pci_compliant else 'NON-COMPLIANT'
                        st.markdown(f"""
                        <div style='text-align: center;'>
                            <h4>PCI-DSS</h4>
                            <span class='{status_class}' style='display: inline-block; padding: 10px 20px; font-size: 1.1em;'>
                                {status_text}
                            </span>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col2:
                        gdpr_compliant = compliance.get('gdpr_compliant', False)
                        status_class = 'status-compliant' if gdpr_compliant else 'status-non-compliant'
                        status_text = 'COMPLIANT' if gdpr_compliant else 'NON-COMPLIANT'
                        st.markdown(f"""
                        <div style='text-align: center;'>
                            <h4>GDPR</h4>
                            <span class='{status_class}' style='display: inline-block; padding: 10px 20px; font-size: 1.1em;'>
                                {status_text}
                            </span>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col3:
                        hipaa_compliant = compliance.get('hipaa_compliant', False)
                        status_class = 'status-compliant' if hipaa_compliant else 'status-non-compliant'
                        status_text = 'COMPLIANT' if hipaa_compliant else 'NON-COMPLIANT'
                        st.markdown(f"""
                        <div style='text-align: center;'>
                            <h4>HIPAA</h4>
                            <span class='{status_class}' style='display: inline-block; padding: 10px 20px; font-size: 1.1em;'>
                                {status_text}
                            </span>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    st.divider()
                    
                    # Compliance Messages
                    st.markdown("#### Compliance Assessment")
                    
                    if pci_compliant:
                        st.success("✓ PCI-DSS: No payment card data detected in findings")
                    else:
                        st.error("✗ PCI-DSS: Credit card or sensitive payment data detected - requires remediation")
                    
                    if gdpr_compliant:
                        st.success("✓ GDPR: Personal data handling appears compliant")
                    else:
                        st.error("✗ GDPR: Personal data (email, SSN, phone) detected - ensure consent & processing agreements")
                    
                    if hipaa_compliant:
                        st.success("✓ HIPAA: No health information detected")
                    else:
                        st.error("✗ HIPAA: Sensitive information detected - ensure encryption & access controls")
                    
                    st.divider()
                    
                    # Violations
                    if compliance.get('violations'):
                        st.markdown("#### Compliance Violations Found")
                        for violation in compliance['violations']:
                            st.markdown(f"""<div class='error-box'>
                                <strong>Violation:</strong> {violation}
                            </div>""", unsafe_allow_html=True)
                    else:
                        st.info("No compliance violations detected")
                    
                    st.divider()
                    
                    # Actions taken
                    if policies_data.get('actions_taken'):
                        st.markdown("#### Policy Actions Applied")
                        actions_summary = policies_data['actions_taken']
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Redacted", actions_summary.get('redacted_count', 0))
                        with col2:
                            st.metric("Masked", actions_summary.get('masked_count', 0))
                        with col3:
                            st.metric("Warned", actions_summary.get('warned_count', 0))
                else:
                    st.info("Policy check not enabled")
            
            # ==================== TAB 4: RISK ASSESSMENT ====================
            with tab4:
                st.markdown("### Risk Assessment Report")
                
                if 'risk_assessment' in result_data:
                    risk_data = result_data['risk_assessment']
                    
                    # Risk score display
                    risk_score = risk_data.get('risk_score', 0)
                    risk_level = risk_data.get('risk_level', 'unknown').upper()
                    
                    # Color code by risk
                    if risk_score >= 80:
                        color = '#dc3545'  # Red
                    elif risk_score >= 60:
                        color = '#fd7e14'  # Orange
                    elif risk_score >= 40:
                        color = '#ffc107'  # Yellow
                    else:
                        color = '#28a745'  # Green
                    
                    st.markdown(f"""
                    <div style='text-align: center; padding: 30px; background: linear-gradient(135deg, {color}20 0%, {color}10 100%); border-radius: 10px;'>
                        <h2 style='color: {color}; margin: 0;'>{risk_score}/100</h2>
                        <p style='font-size: 1.3em; color: {color}; margin: 10px 0 0 0;'>{risk_level} RISK</p>
                        <p style='margin: 5px 0 0 0; color: #666;'>Exposure Index: {risk_data.get('exposure_index', 0) * 100:.1f}%</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.divider()
                    
                    # Top vulnerabilities
                    if risk_data.get('top_vulnerabilities'):
                        st.markdown("#### Top Vulnerabilities")
                        
                        for vuln in risk_data['top_vulnerabilities']:
                            if isinstance(vuln, dict):
                                vuln_type = vuln.get('type', 'Unknown')
                                vuln_count = vuln.get('count', 0)
                                vuln_severity = vuln.get('severity', 'low')
                                
                                st.markdown(f"""
                                <div class='metric-card {vuln_severity}'>
                                    <strong>{vuln_type.upper()}</strong><br>
                                    Found: <span style='color: #667eea; font-size: 1.2em;'>{vuln_count}</span> times<br>
                                    Severity: <strong>{vuln_severity.upper()}</strong>
                                </div>
                                """, unsafe_allow_html=True)
                    
                    st.divider()
                    
                    # Recommendations
                    # Recommended Actions
                    st.markdown("#### Recommended Actions")
                    
                    if ai_analysis and ai_analysis.get('recommended_actions'):
                        # Show AI-generated recommendations if available
                        st.markdown("*AI-Generated recommendations based on analysis:*")
                        recommended_actions = ai_analysis['recommended_actions']
                        if isinstance(recommended_actions, str):
                            recommended_actions = recommended_actions.split('\n')
                        
                        for idx, action in enumerate(filter(None, recommended_actions), 1):
                            try:
                                action_text = str(action).strip() if hasattr(action, 'strip') else str(action)
                                if action_text:
                                    st.markdown(f"**{idx}.** {action_text}")
                            except Exception as e:
                                logger.error(f"Error displaying action: {e}")
                    elif risk_data.get('recommended_actions'):
                        # Fall back to backend recommendations if available
                        for idx, action in enumerate(risk_data['recommended_actions'][:5], 1):
                            st.markdown(f"**{idx}.** {action}")
                    else:
                        # Show rule-based recommendations based on risk level
                        recommendations = {
                            'CRITICAL': [
                                'Immediately isolate affected systems from network',
                                'Enable real-time monitoring and alerting',
                                'Conduct emergency incident response',
                                'Notify security team and stakeholders',
                                'Review access logs for unauthorized access'
                            ],
                            'HIGH': [
                                'Implement additional monitoring and logging',
                                'Review and patch affected systems',
                                'Conduct security assessment of related systems',
                                'Enhance access controls and authentication',
                                'Schedule urgent security team meeting'
                            ],
                            'MEDIUM': [
                                'Schedule security remediation planning',
                                'Review system configurations and policies',
                                'Implement recommended security updates',
                                'Enhance monitoring capabilities',
                                'Update security procedures and documentation'
                            ],
                            'LOW': [
                                'Review security best practices',
                                'Plan for routine security updates',
                                'Enhance awareness and training',
                                'Document and track issues',
                                'Prioritize with other improvements'
                            ]
                        }
                        
                        risk_actions = recommendations.get(risk_level, recommendations['MEDIUM'])
                        for idx, action in enumerate(risk_actions[:5], 1):
                            st.markdown(f"**{idx}.** {action}")
                    
                    if ai_analysis and ai_analysis.get('recommended_actions'):
                        st.info("For more detailed AI-powered insights and remediation steps, see the 'AI Insights' tab.")
                else:
                    st.info("Risk assessment not enabled")
            
            # ==================== TAB 5: AI INSIGHTS ====================
            with tab5:
                st.markdown("### AI-Powered Security Insights")
                
                if not ai_analysis:
                    st.info("AI analysis not enabled or no findings detected. Enable AI Analysis in the sidebar to get insights.")
                else:
                    try:
                        # ===== LOG SUMMARY (BEAUTIFIED) =====
                        st.markdown("#### Log Summary")
                        if ai_analysis.get('log_summary'):
                            summary_text = str(ai_analysis['log_summary']).strip()
                            if summary_text:
                                # Create a nicely formatted summary box
                                st.markdown(f"""
                                <div style='background: linear-gradient(135deg, #667eea20 0%, #764ba220 100%); padding: 15px; border-radius: 8px; border-left: 4px solid #667eea;'>
                                    <p style='margin: 0; line-height: 1.6; color: #333;'>{html.escape(summary_text)}</p>
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                st.info("No log summary generated")
                        else:
                            st.info("No log summary available")
                        
                        st.divider()
                        
                        # ===== PATTERN CORRELATION =====
                        st.markdown("#### Pattern Correlation Analysis")
                        if ai_analysis.get('correlation'):
                            correlation_text = str(ai_analysis['correlation']).strip()
                            if correlation_text:
                                st.markdown(f"""
                                <div style='background: #10b98120; padding: 15px; border-radius: 8px; border-left: 4px solid #10b981;'>
                                    <p style='margin: 0; line-height: 1.6; color: #333;'>{correlation_text}</p>
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                st.info("No pattern correlations detected")
                        else:
                            st.info("No pattern correlation data available")
                        
                        st.divider()
                        
                        # ===== RECOMMENDED ACTIONS =====
                        st.markdown("#### Recommended Actions (AI-Generated)")
                        if ai_analysis.get('recommended_actions'):
                            recommended_actions = ai_analysis['recommended_actions']
                            if isinstance(recommended_actions, str):
                                recommended_actions = recommended_actions.split('\n')
                            
                            action_items = [item for item in recommended_actions if item and str(item).strip()]
                            if action_items:
                                for idx, action in enumerate(action_items, 1):
                                    try:
                                        action_text = str(action).strip()
                                        if action_text:
                                            st.markdown(f"**{idx}.** {action_text}")
                                    except Exception as e:
                                        logger.error(f"Error displaying action: {e}")
                            else:
                                st.info("No recommended actions available")
                        else:
                            st.info("No recommended actions available")
                        
                        st.divider()
                        
                        # ===== REMEDIATION STEPS =====
                        st.markdown("#### Remediation Steps (For Critical Issues)")
                        if ai_analysis.get('remediation'):
                            remediation_list = ai_analysis['remediation']
                            
                            if isinstance(remediation_list, list):
                                remediation_items = [r for r in remediation_list if r]
                                if remediation_items:
                                    for remediation_item in remediation_items:
                                        try:
                                            if isinstance(remediation_item, dict):
                                                finding_type = remediation_item.get('finding_type', 'Unknown')
                                                risk_level = remediation_item.get('risk_level', 'unknown').upper()
                                                steps = remediation_item.get('steps', '')
                                                
                                                # Color code by risk level
                                                risk_color = {
                                                    'CRITICAL': '#dc3545',
                                                    'HIGH': '#fd7e14',
                                                    'MEDIUM': '#ffc107',
                                                    'LOW': '#28a745'
                                                }.get(risk_level, '#6c757d')
                                                
                                                st.markdown(f"""
                                                <div style='background: {risk_color}20; padding: 12px; border-radius: 6px; border-left: 4px solid {risk_color}; margin-bottom: 10px;'>
                                                    <strong style='color: {risk_color};'>Issue: {finding_type.upper()}</strong> <span style='color: #666;'>({risk_level})</span>
                                                </div>
                                                """, unsafe_allow_html=True)
                                                
                                                if isinstance(steps, list):
                                                    for step_idx, step in enumerate(steps, 1):
                                                        st.markdown(f"• **Step {step_idx}:** {str(step).strip()}")
                                                elif isinstance(steps, str) and steps:
                                                    st.markdown(f"**Steps:** {steps}")
                                                else:
                                                    st.markdown("No remediation steps provided")
                                                
                                                st.divider()
                                        except Exception as e:
                                            logger.error(f"Error displaying remediation: {e}")
                                else:
                                    st.info("No remediation steps available")
                            else:
                                st.info("No remediation data available")
                        else:
                            st.info("No remediation steps available")
                    
                    except Exception as e:
                        logger.error(f"Error in AI Insights tab: {e}")
                        st.error(f"Error displaying AI insights: {str(e)}")
            
            # ==================== TAB 6: FULL REPORT ====================
            with tab6:
                st.markdown("### Full Analysis Report")
                
                if st.checkbox("Show Raw JSON Response"):
                    st.json(result_data)
                # Download report (fix: use only st.download_button)
                report_json = json.dumps(result_data, indent=2)
                st.download_button(
                    label="Download Report as JSON",
                    data=report_json,
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        except requests.exceptions.ConnectionError:
            st.markdown(f"""<div class='error-box'>
                <strong>Connection Error:</strong> Cannot connect to backend at {backend_url}<br><br>
                Make sure FastAPI server is running:<br>
                <code>cd backend && python -m uvicorn app.main:app --reload</code>
            </div>""", unsafe_allow_html=True)
        
        except Exception as e:
            st.markdown(f"""<div class='error-box'>
                <strong>Error:</strong> {str(e)}
            </div>""", unsafe_allow_html=True)

else:
    st.markdown("""
    <div class='info-box' style='text-align: center; padding: 40px;'>
        <h3>Upload a file to get started</h3>
        <p>Supported formats: TXT, LOG, DOC, DOCX</p>
        <p>Drag and drop or use the file uploader above</p>
    </div>
    """, unsafe_allow_html=True)
