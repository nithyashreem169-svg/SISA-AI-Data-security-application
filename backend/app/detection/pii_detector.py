"""
PII Detection Engine - Main orchestrator for detecting sensitive data
Combines regex patterns + AI insights
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from app.detection.regex_patterns import PatternDetector, DETECTION_METHODS, SensitivityLevel
from app.utils.logger import logger


@dataclass
class Finding:
    """Represents a detected sensitive data finding"""
    type: str
    risk: str
    line_number: int
    line_content: str
    start_pos: int
    end_pos: int
    detected_value: str = "***"  # Masked by default
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class PIIDetector:
    """Detects Personally Identifiable Information and sensitive data"""
    
    def __init__(self):
        """Initialize the detector"""
        self.findings: List[Finding] = []
        self.pattern_counts: Dict[str, int] = {}
    
    def analyze_line(self, line: str, line_number: int) -> List[Finding]:
        """
        Analyze a single line for sensitive data.
        Includes deduplication: overlapping matches on the same span
        keep only the highest-severity finding.
        
        Args:
            line: The line content to analyze
            line_number: Line number (1-indexed)
            
        Returns:
            List of findings in this line
        """
        raw_findings = []
        
        # Severity ordering for dedup (higher index = more severe)
        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        
        # Run all detection methods
        for pattern_type, (detector_method, risk_level) in DETECTION_METHODS.items():
            try:
                matches = detector_method(line)
                
                for match_value, start_pos, end_pos in matches:
                    finding = Finding(
                        type=pattern_type,
                        risk=risk_level.value,
                        line_number=line_number,
                        line_content=line,
                        start_pos=start_pos,
                        end_pos=end_pos,
                        detected_value=match_value,
                        confidence=1.0
                    )
                    raw_findings.append(finding)
                    
            except Exception as e:
                logger.error(f"Error detecting {pattern_type}: {str(e)}")
                continue
        
        # Deduplicate: if two findings overlap on the same text span,
        # keep only the one with the higher severity
        line_findings = []
        seen_spans = {}  # key: (start_pos, end_pos) -> best finding
        
        for finding in raw_findings:
            span_key = (finding.start_pos, finding.end_pos)
            existing = seen_spans.get(span_key)
            
            if existing is None:
                seen_spans[span_key] = finding
            else:
                # Keep the higher-severity finding
                if severity_order.get(finding.risk, 0) > severity_order.get(existing.risk, 0):
                    seen_spans[span_key] = finding
        
        for finding in seen_spans.values():
            line_findings.append(finding)
            # Track pattern counts
            self.pattern_counts[finding.type] = self.pattern_counts.get(finding.type, 0) + 1
            logger.info(f"Line {line_number}: Found {finding.type} ({finding.risk})")
        
        return line_findings
    
    def analyze_batch(self, lines: List[str]) -> List[Finding]:
        """
        Analyze multiple lines
        
        Args:
            lines: List of line content to analyze
            
        Returns:
            List of all findings
        """
        all_findings = []
        
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            
            line_findings = self.analyze_line(line, line_number)
            all_findings.extend(line_findings)
        
        self.findings = all_findings
        logger.info(f"Analysis complete: {len(all_findings)} findings across {len(lines)} lines")
        
        return all_findings
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of findings"""
        if not self.findings:
            return {
                'total_findings': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'risk_score': 0,
                'findings_by_type': {}
            }
        
        summary = {
            'total_findings': len(self.findings),
            'critical_count': len([f for f in self.findings if f.risk == 'critical']),
            'high_count': len([f for f in self.findings if f.risk == 'high']),
            'medium_count': len([f for f in self.findings if f.risk == 'medium']),
            'low_count': len([f for f in self.findings if f.risk == 'low']),
            'findings_by_type': self.pattern_counts,
            'risk_score': self._calculate_risk_score(),
            'most_common_types': sorted(
                self.pattern_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:3]
        }
        
        return summary
    
    def _calculate_risk_score(self) -> int:
        """
        Calculate overall risk score (0-100)
        Based on severity and count of findings
        """
        if not self.findings:
            return 0
        
        score = 0
        
        # Weight by risk level
        score += len([f for f in self.findings if f.risk == 'critical']) * 10
        score += len([f for f in self.findings if f.risk == 'high']) * 5
        score += len([f for f in self.findings if f.risk == 'medium']) * 2
        score += len([f for f in self.findings if f.risk == 'low']) * 1
        
        # Cap at 100
        return min(score, 100)
    
    def get_risk_level(self) -> str:
        """Determine overall risk level"""
        score = self._calculate_risk_score()
        
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'minimal'
    
    def get_critical_findings(self) -> List[Finding]:
        """Get only critical risk findings"""
        return [f for f in self.findings if f.risk == 'critical']
    
    def get_findings_by_type(self, pattern_type: str) -> List[Finding]:
        """Get findings of a specific type"""
        return [f for f in self.findings if f.type == pattern_type]
    
    def get_findings_by_line(self, line_number: int) -> List[Finding]:
        """Get findings on a specific line"""
        return [f for f in self.findings if f.line_number == line_number]
    
    def format_for_response(self, include_content: bool = False) -> Dict[str, Any]:
        """
        Format findings for API response
        
        Args:
            include_content: Whether to include full line content
            
        Returns:
            Formatted response dictionary
        """
        risk_score = self._calculate_risk_score()
        
        findings_list = []
        for finding in self.findings:
            finding_dict = {
                'type': finding.type,
                'risk': finding.risk,
                'line': finding.line_number,
                'position': {
                    'start': finding.start_pos,
                    'end': finding.end_pos
                },
                'confidence': finding.confidence
            }
            
            if include_content:
                finding_dict['line_content'] = finding.line_content
            
            findings_list.append(finding_dict)
        
        return {
            'risk_score': risk_score,
            'risk_level': self.get_risk_level(),
            'total_findings': len(self.findings),
            'critical_findings': len([f for f in self.findings if f.risk == 'critical']),
            'findings': findings_list,
            'summary_stats': self.get_summary()
        }
    
    def reset(self):
        """Reset detector state"""
        self.findings = []
        self.pattern_counts = {}


class LogAnalyzer:
    """Specialized analyzer for log files"""
    
    def __init__(self):
        """Initialize log analyzer"""
        self.detector = PIIDetector()
        self.log_entries = []
        self.suspicious_patterns = []
    
    def parse_log_lines(self, lines: List[str]) -> List[Dict[str, Any]]:
        """
        Parse and structure log lines
        Attempts to extract timestamp, level, and message
        """
        parsed_entries = []
        
        for line_num, line in enumerate(lines, 1):
            # Simple log line parsing (timestamp level message)
            entry = {
                'line_number': line_num,
                'raw_line': line,
                'timestamp': None,
                'level': None,
                'message': None
            }
            
            # Try to extract log level
            for level in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                if level in line.upper():
                    entry['level'] = level
                    break
            
            parsed_entries.append(entry)
        
        self.log_entries = parsed_entries
        return parsed_entries
    
    def analyze_logs(self, lines: List[str]) -> Dict[str, Any]:
        """
        Comprehensive log analysis
        
        Args:
            lines: List of log lines to analyze
            
        Returns:
            Analysis results with findings and insights
        """
        # Parse log structure
        self.parse_log_lines(lines)
        
        # Run PII detection
        findings = self.detector.analyze_batch(lines)
        
        # Analyze log patterns
        self._detect_suspicious_patterns(lines)
        
        # Generate insights
        insights = self._generate_insights()
        
        return {
            'parsed_entries': self.log_entries,
            'findings': [f.to_dict() for f in findings],
            'risk_analysis': self.detector.format_for_response(include_content=True),
            'suspicious_patterns': self.suspicious_patterns,
            'insights': insights
        }
    
    def _detect_suspicious_patterns(self, lines: List[str]):
        """Detect suspicious log patterns"""
        suspicious = []
        
        # Count error lines
        error_lines = [i+1 for i, line in enumerate(lines) if 'ERROR' in line.upper()]
        if len(error_lines) > len(lines) * 0.2:  # >20% errors
            suspicious.append({
                'type': 'high_error_rate',
                'severity': 'medium',
                'description': f'High error rate detected: {len(error_lines)} errors in {len(lines)} lines'
            })
        
        # Count failed/denied patterns
        failed_count = sum(1 for line in lines if 'failed' in line.lower() or 'denied' in line.lower())
        if failed_count > 5:
            suspicious.append({
                'type': 'repeated_failures',
                'severity': 'medium',
                'description': f'Possible brute-force attempt: {failed_count} failed attempts detected'
            })
        
        # Detect stack traces
        trace_lines = [i+1 for i, line in enumerate(lines) if 'traceback' in line.lower() or 'at ' in line.lower()]
        if trace_lines:
            suspicious.append({
                'type': 'stack_trace_leak',
                'severity': 'medium',
                'description': f'Stack traces found on lines: {trace_lines[:5]}'
            })
        
        # Detect debug mode
        debug_lines = [i+1 for i, line in enumerate(lines) if 'debug' in line.lower() and '=' in line]
        if debug_lines:
            suspicious.append({
                'type': 'debug_mode_enabled',
                'severity': 'low',
                'description': 'Debug mode or verbose logging detected'
            })
        
        self.suspicious_patterns = suspicious
    
    def _generate_insights(self) -> List[str]:
        """Generate human-readable insights from analysis"""
        insights = []
        
        # Critical findings insights
        critical = self.detector.get_critical_findings()
        if critical:
            insight_types = list(set([f.type for f in critical]))
            insights.append(f"CRITICAL: Found {len(critical)} critical issues ({', '.join(insight_types)})")
        
        # High risk insights
        high_risk = [f for f in self.detector.findings if f.risk == 'high']
        if high_risk:
            insights.append(f"HIGH RISK: {len(high_risk)} high-risk findings detected")
        
        # Pattern-specific insights
        if any(f.type == 'password' for f in self.detector.findings):
            insights.append("Credentials exposed: Passwords/credentials found in logs")
        
        if any(f.type in ['api_key', 'aws_key', 'generic_token'] for f in self.detector.findings):
            insights.append("API Keys/Tokens exposed in logs - potential security breach")
        
        if any(f.type == 'stack_trace' for f in self.detector.findings):
            insights.append("Stack traces found: Internal system details may be leaked")
        
        if any(f.type == 'ssn' for f in self.detector.findings):
            insights.append("Personal identification numbers (SSN) exposed")
        
        if any(f.type == 'credit_card' for f in self.detector.findings):
            insights.append("Payment card information (PCI) exposed - COMPLIANCE RISK")
        
        # Suspicious patterns
        if self.suspicious_patterns:
            insights.append(f"{len(self.suspicious_patterns)} suspicious patterns detected in logs")
        
        if not insights:
            insights.append("No critical security issues detected")
        
        return insights
    
    def reset(self):
        """Reset analyzer state"""
        self.detector.reset()
        self.log_entries = []
        self.suspicious_patterns = []
