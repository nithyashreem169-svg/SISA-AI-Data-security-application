"""
Risk Engine - Risk assessment, scoring, and threat analysis
"""
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime
from app.utils.logger import logger


class RiskScore:
    """Represents calculated risk score and factors"""
    
    def __init__(self, score: int, level: str, factors: Dict[str, float], details: str = ""):
        """
        Initialize risk score
        
        Args:
            score: Numerical risk score (0-100)
            level: Risk level string (minimal, low, medium, high, critical)
            factors: Dictionary of contributing factors and their weights
            details: Detailed explanation of score
        """
        self.score = max(0, min(score, 100))  # Clamp 0-100
        self.level = level
        self.factors = factors
        self.details = details
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'score': self.score,
            'level': self.level,
            'factors': self.factors,
            'details': self.details,
            'timestamp': self.timestamp
        }


class RiskEngine:
    """Comprehensive risk assessment engine"""
    
    # Risk factor weights
    FACTOR_WEIGHTS = {
        'critical_findings': 25,      # Weight of critical severity findings
        'high_findings': 15,          # Weight of high severity findings
        'medium_findings': 8,         # Weight of medium severity findings
        'credential_exposure': 30,    # Credentials exposed
        'pci_violation': 25,          # Payment card info exposed
        'pii_exposure': 20,           # Personal info exposed
        'error_leaks': 12,            # Stack traces/debug info
        'pattern_concentration': 15,  # Multiple sensitive types
        'volume_spike': 10,           # Unusual volume of findings
    }
    
    # Risk thresholds for levels
    RISK_THRESHOLDS = {
        'minimal': (0, 20),
        'low': (20, 40),
        'medium': (40, 60),
        'high': (60, 80),
        'critical': (80, 100)
    }
    
    def __init__(self):
        """Initialize risk engine"""
        self.risk_history = []
        self.baseline_metrics = self._initialize_baseline()
    
    def _initialize_baseline(self) -> Dict[str, Any]:
        """Initialize baseline metrics for anomaly detection"""
        return {
            'avg_findings_per_line': 0.0,
            'expected_finding_types': {},
            'avg_risk_score': 0.0,
            'baseline_set': False
        }
    
    def calculate_risk_score(
        self,
        findings: List[Dict[str, Any]],
        num_lines: int,
        suspicious_patterns: Optional[List[Dict[str, Any]]] = None
    ) -> RiskScore:
        """
        Calculate comprehensive risk score
        
        Args:
            findings: List of detected findings
            num_lines: Total number of lines analyzed
            suspicious_patterns: List of suspicious patterns found
            
        Returns:
            RiskScore object with breakdown
        """
        factors = {}
        base_score = 0
        
        if not findings:
            return RiskScore(0, 'minimal', factors, "No security issues detected")
        
        # Count findings by severity
        critical_count = len([f for f in findings if f.get('risk') == 'critical'])
        high_count = len([f for f in findings if f.get('risk') == 'high'])
        medium_count = len([f for f in findings if f.get('risk') == 'medium'])
        low_count = len([f for f in findings if f.get('risk') == 'low'])
        
        total_findings = len(findings)
        
        # Normalized scoring: 0-100 scale based on finding composition
        # Aligned with hackathon requirements: risk_score 10-12 for mixed findings
        
        # Factor 1: Critical findings (most important)
        if critical_count > 0:
            factor_score = min(critical_count * 20, 40)
            factors['critical_severity'] = factor_score
            base_score += factor_score
        
        # Factor 2: High findings
        if high_count > 0:
            factor_score = min(high_count * 10, 25)
            factors['high_severity'] = factor_score
            base_score += factor_score
        
        # Factor 3: Medium findings
        if medium_count > 0:
            factor_score = min(medium_count * 5, 15)
            factors['medium_severity'] = factor_score
            base_score += factor_score
        
        # Factor 4: Low findings
        if low_count > 0:
            factor_score = min(low_count * 2, 10)
            factors['low_severity'] = factor_score
            base_score += factor_score
        
        # Factor 5: Credential exposure (additive boost)
        credential_types = ['password', 'api_key', 'aws_key', 'generic_token', 'private_key']
        credential_findings = [f for f in findings if f.get('type') in credential_types]
        if credential_findings:
            # Boost if credentials found, but cap total
            factors['credential_exposure_boost'] = 5
            base_score += 5
        
        # Factor 6: PCI-DSS violation (credit cards)
        pci_findings = [f for f in findings if f.get('type') == 'credit_card']
        if pci_findings:
            factors['pci_violation_boost'] = 5
            base_score += 5
        
        # Factor 7: Volume relative to lines
        findings_per_line = total_findings / max(num_lines, 1)
        if findings_per_line > 0.5:  # >50% of lines have issues
            factors['volume_spike'] = 5
            base_score += 5
        elif findings_per_line > 0.2:  # >20% of lines have issues
            factors['volume_spike'] = 3
            base_score += 3
        
        # Normalize and determine level
        risk_score = min(int(base_score), 100)
        risk_level = self._score_to_level(risk_score)
        
        details = self._generate_risk_details(
            risk_score, 
            critical_count, 
            high_count, 
            total_findings
        )
        
        risk_obj = RiskScore(risk_score, risk_level, factors, details)
        self.risk_history.append(risk_obj)
        
        return risk_obj
    
    def _score_to_level(self, score: int) -> str:
        """Convert numerical score to risk level"""
        for level, (min_score, max_score) in self.RISK_THRESHOLDS.items():
            if min_score <= score < max_score:
                return level
        return 'critical'
    
    def _generate_risk_details(self, score: int, critical: int, high: int, total: int) -> str:
        """Generate human-readable risk explanation"""
        if score >= 80:
            return f"CRITICAL RISK: {critical} critical and {high} high severity issues found in {total} total findings"
        elif score >= 60:
            return f"HIGH RISK: {high} high severity findings detected ({total} total)"
        elif score >= 40:
            return f"MEDIUM RISK: Multiple security issues detected ({total} findings)"
        elif score >= 20:
            return f"LOW RISK: {total} minor security findings"
        else:
            return "MINIMAL RISK: No significant security issues"
    
    def assess_threat_level(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Comprehensive threat assessment
        
        Args:
            findings: List of findings
            
        Returns:
            Threat assessment report
        """
        assessment = {
            'threat_level': 'unknown',
            'attack_vectors': [],
            'potential_impact': [],
            'response_urgency': 'normal',
            'estimated_risk': 0
        }
        
        if not findings:
            return assessment
        
        # Threat vector analysis
        credential_types = ['password', 'api_key', 'aws_key', 'private_key']
        if any(f.get('type') in credential_types for f in findings):
            assessment['attack_vectors'].append('Stolen credentials for unauthorized access')
            assessment['response_urgency'] = 'urgent'
        
        if any(f.get('type') == 'credit_card' for f in findings):
            assessment['attack_vectors'].append('Financial fraud and PCI compliance violation')
            assessment['response_urgency'] = 'immediate'
            assessment['potential_impact'].append('Direct financial loss and regulatory penalties')
        
        if any(f.get('type') in ['ssn', 'email', 'phone'] for f in findings):
            assessment['attack_vectors'].append('Identity theft and targeted phishing')
            assessment['potential_impact'].append('Personal data breach and regulatory fines')
        
        if any(f.get('type') in ['stack_trace', 'file_path'] for f in findings):
            assessment['attack_vectors'].append('Reconnaissance and system mapping')
            assessment['potential_impact'].append('Targeted attacks on known vulnerabilities')
        
        # Determine threat level
        critical_count = len([f for f in findings if f.get('risk') == 'critical'])
        
        if critical_count >= 5:
            assessment['threat_level'] = 'critical'
        elif critical_count >= 3:
            assessment['threat_level'] = 'high'
        elif critical_count >= 1:
            assessment['threat_level'] = 'medium'
        else:
            assessment['threat_level'] = 'low'
        
        return assessment
    
    def calculate_exposure_index(self, findings: List[Dict[str, Any]]) -> float:
        """
        Calculate data exposure index (0.0-1.0)
        Indicates how exposed sensitive data is
        
        Args:
            findings: List of findings
            
        Returns:
            Exposure index score
        """
        if not findings:
            return 0.0
        
        exposure_score = 0.0
        max_score = 0.0
        
        # Data type exposures with their impact weights
        exposure_weights = {
            'password': 1.0,           # Most critical
            'private_key': 1.0,
            'aws_key': 1.0,
            'api_key': 0.8,
            'generic_token': 0.8,
            'credit_card': 1.0,
            'ssn': 0.9,
            'db_connection': 0.8,
            'email': 0.3,
            'phone': 0.3,
            'ip_address': 0.4,
            'file_path': 0.5,
            'stack_trace': 0.5,
        }
        
        for finding in findings:
            finding_type = finding.get('type')
            weight = exposure_weights.get(finding_type, 0.5)
            
            # Weight by severity
            if finding.get('risk') == 'critical':
                exposure_score += weight * 1.0
            elif finding.get('risk') == 'high':
                exposure_score += weight * 0.7
            elif finding.get('risk') == 'medium':
                exposure_score += weight * 0.4
            else:
                exposure_score += weight * 0.2
            
            max_score += 1.0
        
        # Normalize to 0.0-1.0
        if max_score == 0:
            return 0.0
        
        return min(exposure_score / max_score, 1.0)
    
    def generate_risk_report(self, findings: List[Dict[str, Any]], num_lines: int) -> Dict[str, Any]:
        """
        Generate comprehensive risk report
        
        Args:
            findings: List of findings
            num_lines: Total lines analyzed
            
        Returns:
            Complete risk assessment report
        """
        risk_score = self.calculate_risk_score(findings, num_lines)
        threat_assessment = self.assess_threat_level(findings)
        exposure_index = self.calculate_exposure_index(findings)
        
        # CVSS-like scoring
        cvss_score = (risk_score.score + (exposure_index * 100)) / 2
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'risk_score': risk_score.to_dict(),
            'risk_distribution': self._get_risk_distribution(findings),
            'threat_assessment': threat_assessment,
            'exposure_index': exposure_index,
            'cvss_score': round(cvss_score, 1),
            'total_findings': len(findings),
            'findings_summary': {
                'critical': len([f for f in findings if f.get('risk') == 'critical']),
                'high': len([f for f in findings if f.get('risk') == 'high']),
                'medium': len([f for f in findings if f.get('risk') == 'medium']),
                'low': len([f for f in findings if f.get('risk') == 'low'])
            },
            'top_vulnerabilities': self._get_top_vulnerabilities(findings),
            'recommended_actions': self._generate_recommendations(risk_score)
        }
        
        return report
    
    def _get_risk_distribution(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of findings by type"""
        distribution = defaultdict(int)
        for finding in findings:
            finding_type = finding.get('type', 'unknown')
            distribution[finding_type] += 1
        return dict(distribution)
    
    def _get_top_vulnerabilities(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get top vulnerabilities by frequency and severity"""
        vulnerabilities = defaultdict(lambda: {'count': 0, 'max_risk': 'low'})
        
        risk_order = ['low', 'medium', 'high', 'critical']
        
        for finding in findings:
            vuln_type = finding.get('type')
            count = vulnerabilities[vuln_type]['count']
            current_risk = vulnerabilities[vuln_type]['max_risk']
            new_risk = finding.get('risk', 'low')
            
            vulnerabilities[vuln_type]['count'] = count + 1
            
            if risk_order.index(new_risk) > risk_order.index(current_risk):
                vulnerabilities[vuln_type]['max_risk'] = new_risk
        
        # Sort by count and severity
        sorted_vulns = sorted(
            vulnerabilities.items(),
            key=lambda x: (risk_order.index(x[1]['max_risk']), x[1]['count']),
            reverse=True
        )
        
        return [
            {
                'type': vuln_type,
                'count': data['count'],
                'severity': data['max_risk']
            }
            for vuln_type, data in sorted_vulns[:5]
        ]
    
    def _generate_recommendations(self, risk_score: RiskScore) -> List[str]:
        """Generate action recommendations based on risk"""
        recommendations = []
        
        if risk_score.score >= 80:
            recommendations.append("🚨 IMMEDIATE ACTION REQUIRED: Critical security issues detected")
            recommendations.append("Isolate affected systems and disable compromised credentials immediately")
            recommendations.append("Engage security incident response team")
            recommendations.append("Begin forensic investigation")
        elif risk_score.score >= 60:
            recommendations.append("HIGH PRIORITY: Significant security issues found")
            recommendations.append("Create incident ticket with urgency")
            recommendations.append("Review and patch affected systems within 24 hours")
        elif risk_score.score >= 40:
            recommendations.append("MEDIUM PRIORITY: Review and remediate within 1 week")
            recommendations.append("Implement logging and monitoring for similar issues")
        else:
            recommendations.append("👁️ Monitor for similar patterns in future scans")
        
        recommendations.append("Implement automated log sanitization to prevent data exposure")
        recommendations.append("Deploy data loss prevention (DLP) tools")
        
        return recommendations
