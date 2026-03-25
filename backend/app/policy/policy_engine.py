"""
Policy Engine - Applies security policies and compliance rules
"""
from typing import List, Dict, Any, Optional
from enum import Enum
from app.utils.logger import logger


class PolicyAction(Enum):
    """Actions that can be taken on findings"""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    MASK = "mask"
    REDACT = "redact"


class ComplianceStandard(Enum):
    """Supported compliance standards"""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    CUSTOM = "custom"


class SecurityPolicy:
    """Represents a security policy rule"""
    
    def __init__(
        self,
        name: str,
        description: str,
        finding_types: List[str],
        action: PolicyAction,
        severity_threshold: str = "low"
    ):
        """
        Initialize a security policy
        
        Args:
            name: Policy name
            description: Policy description
            finding_types: List of finding types this policy applies to
            action: Action to take when policy is triggered
            severity_threshold: Minimum severity to trigger (low, medium, high, critical)
        """
        self.name = name
        self.description = description
        self.finding_types = finding_types
        self.action = action
        self.severity_threshold = severity_threshold
        self.enabled = True
    
    def applies_to(self, finding_type: str, risk_level: str) -> bool:
        """Check if policy applies to a finding"""
        if not self.enabled:
            return False
        
        if finding_type not in self.finding_types:
            return False
        
        severity_order = ['low', 'medium', 'high', 'critical']
        return severity_order.index(risk_level) >= severity_order.index(self.severity_threshold)


class PolicyEngine:
    """Manages and applies security policies"""
    
    def __init__(self):
        """Initialize policy engine with default policies"""
        self.policies: List[SecurityPolicy] = []
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Create default security policies"""
        
        # CRITICAL CREDENTIALS POLICY
        self.add_policy(SecurityPolicy(
            name="Block Critical Credentials",
            description="Immediately block and redact passwords and private keys",
            finding_types=['password', 'private_key', 'aws_key', 'db_connection', 'credential'],
            action=PolicyAction.REDACT,
            severity_threshold='critical'
        ))
        
        # API KEYS POLICY
        self.add_policy(SecurityPolicy(
            name="Flag API Keys",
            description="Warn and mask exposed API keys and tokens",
            finding_types=['api_key', 'generic_token'],
            action=PolicyAction.MASK,
            severity_threshold='high'
        ))
        
        # PCI COMPLIANCE POLICY
        self.add_policy(SecurityPolicy(
            name="PCI-DSS Credit Card Protection",
            description="Protect payment card information - COMPLIANCE REQUIREMENT",
            finding_types=['credit_card'],
            action=PolicyAction.REDACT,
            severity_threshold='low'
        ))
        
        # GDPR PII POLICY
        self.add_policy(SecurityPolicy(
            name="GDPR PII Protection",
            description="Protect personally identifiable information",
            finding_types=['ssn', 'email', 'phone'],
            action=PolicyAction.MASK,
            severity_threshold='low'
        ))
        
        # DEBUG/ERROR LEAK POLICY
        self.add_policy(SecurityPolicy(
            name="Prevent Information Leakage",
            description="Flag and warn about stack traces and debug info",
            finding_types=['stack_trace', 'error_leak', 'file_path'],
            action=PolicyAction.WARN,
            severity_threshold='medium'
        ))
        
        # IP ADDRESS POLICY
        self.add_policy(SecurityPolicy(
            name="Monitor IP Addresses",
            description="Track exposed IP addresses for anomalies",
            finding_types=['ip_address'],
            action=PolicyAction.WARN,
            severity_threshold='medium'
        ))
    
    def add_policy(self, policy: SecurityPolicy):
        """Add a custom policy"""
        self.policies.append(policy)
        logger.info(f"Policy added: {policy.name}")
    
    def remove_policy(self, policy_name: str):
        """Remove a policy by name"""
        self.policies = [p for p in self.policies if p.name != policy_name]
    
    def list_policies(self) -> List[Dict[str, Any]]:
        """List all active policies"""
        return [
            {
                'name': p.name,
                'description': p.description,
                'action': p.action.value,
                'enabled': p.enabled,
                'applies_to': p.finding_types
            }
            for p in self.policies
        ]
    
    def enable_policy(self, policy_name: str):
        """Enable a specific policy"""
        for policy in self.policies:
            if policy.name == policy_name:
                policy.enabled = True
                logger.info(f"Policy enabled: {policy_name}")
    
    def disable_policy(self, policy_name: str):
        """Disable a specific policy"""
        for policy in self.policies:
            if policy.name == policy_name:
                policy.enabled = False
                logger.info(f"Policy disabled: {policy_name}")
    
    def apply_policies(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Apply all policies to findings
        
        Args:
            findings: List of detected findings
            
        Returns:
            Policy enforcement results
        """
        actions_taken = []
        processed_findings = []
        
        for finding in findings:
            finding_type = finding.get('type')
            risk_level = finding.get('risk')
            
            # Check which policies apply
            applicable_policies = [
                p for p in self.policies
                if p.applies_to(finding_type, risk_level)
            ]
            
            # Determine strongest action required
            strongest_action = PolicyAction.ALLOW
            action_priority = {
                PolicyAction.ALLOW: 0,
                PolicyAction.WARN: 1,
                PolicyAction.MASK: 2,
                PolicyAction.REDACT: 3,
                PolicyAction.BLOCK: 4
            }
            
            for policy in applicable_policies:
                if action_priority[policy.action] > action_priority[strongest_action]:
                    strongest_action = policy.action
            
            # Apply action
            processed_finding = finding.copy()
            processed_finding['policy_action'] = strongest_action.value
            processed_finding['applied_policies'] = [p.name for p in applicable_policies]
            
            # Record action
            if strongest_action != PolicyAction.ALLOW:
                actions_taken.append({
                    'finding': finding,
                    'action': strongest_action.value,
                    'policies': [p.name for p in applicable_policies]
                })
            
            processed_findings.append(processed_finding)
        
        return {
            'total_findings': len(findings),
            'findings_with_actions': len(actions_taken),
            'actions_taken': actions_taken,
            'processed_findings': processed_findings,
            'summary': self._generate_policy_summary(actions_taken)
        }
    
    def _generate_policy_summary(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of policy enforcement"""
        summary = {
            'redacted_count': 0,
            'masked_count': 0,
            'warned_count': 0,
            'blocked_count': 0,
            'by_finding_type': {}
        }
        
        for action in actions:
            action_type = action['action']
            finding_type = action['finding'].get('type')
            
            if action_type == 'redact':
                summary['redacted_count'] += 1
            elif action_type == 'mask':
                summary['masked_count'] += 1
            elif action_type == 'warn':
                summary['warned_count'] += 1
            elif action_type == 'block':
                summary['blocked_count'] += 1
            
            if finding_type not in summary['by_finding_type']:
                summary['by_finding_type'][finding_type] = 0
            summary['by_finding_type'][finding_type] += 1
        
        summary['total_actions'] = len(actions)
        return summary
    
    def get_compliance_status(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Check compliance status based on findings
        
        Args:
            findings: List of findings to check
            
        Returns:
            Compliance status report
        """
        status = {
            'pci_dss_compliant': True,
            'gdpr_compliant': True,
            'hipaa_compliant': True,
            'issues': []
        }
        
        # Check PCI-DSS: No credit card data should be exposed
        if any(f.get('type') == 'credit_card' for f in findings):
            status['pci_dss_compliant'] = False
            status['issues'].append('PCI-DSS: Credit card data exposed')
        
        # Check GDPR: Personal data should be protected
        pii_types = ['ssn', 'email', 'phone', 'password']
        exposed_pii = [f for f in findings if f.get('type') in pii_types and f.get('risk') in ['high', 'critical']]
        if exposed_pii:
            status['gdpr_compliant'] = False
            status['issues'].append(f'GDPR: {len(exposed_pii)} personal data items exposed')
        
        # Check HIPAA: No PHI (Protected Health Information)
        # In this context, we treat sensitive data similarly
        if any(f.get('risk') == 'critical' for f in findings):
            status['hipaa_compliant'] = False
            status['issues'].append('HIPAA: Critical sensitive data exposed')
        
        status['overall_compliant'] = (
            status['pci_dss_compliant'] and 
            status['gdpr_compliant'] and 
            status['hipaa_compliant']
        )
        
        return status
    
    def create_remediation_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate remediation recommendations
        
        Args:
            findings: List of findings requiring remediation
            
        Returns:
            Remediation recommendations
        """
        recommendations = {
            'immediate_actions': [],
            'short_term_actions': [],
            'long_term_actions': [],
            'compliance_checks': []
        }
        
        critical_findings = [f for f in findings if f.get('risk') == 'critical']
        high_findings = [f for f in findings if f.get('risk') == 'high']
        
        # Immediate actions
        if critical_findings:
            crit_types = list(set([f.get('type') for f in critical_findings]))
            recommendations['immediate_actions'].append(
                f"URGENT: Rotate/revoke exposed credentials ({', '.join(crit_types)})"
            )
            recommendations['immediate_actions'].append(
                " Review and audit affected systems for unauthorized access"
            )
        
        if any(f.get('type') == 'credit_card' for f in findings):
            recommendations['immediate_actions'].append(
                " COMPLIANCE: Notify PCI auditors and review cardholder data"
            )
        
        # Short-term actions
        if high_findings:
            recommendations['short_term_actions'].append(
                f"Implement log sanitization to prevent sensitive data in logs"
            )
            recommendations['short_term_actions'].append(
                f"Add masking at ingestion point for {len(set([f.get('type') for f in high_findings]))} data types"
            )
        
        if any(f.get('type') in ['stack_trace', 'error_leak'] for f in findings):
            recommendations['short_term_actions'].append(
                "Disable verbose/debug logging in production"
            )
        
        # Long-term actions
        recommendations['long_term_actions'].append(
            "Implement data loss prevention (DLP) policies"
        )
        recommendations['long_term_actions'].append(
            "Deploy automated log monitoring and alerting"
        )
        recommendations['long_term_actions'].append(
            "Conduct security awareness training on sensitive data handling"
        )
        recommendations['long_term_actions'].append(
            "Regular security audits and penetration testing"
        )
        
        # Compliance checks
        if not self.get_compliance_status(findings)['overall_compliant']:
            recommendations['compliance_checks'].append(
                "Schedule compliance review with security/privacy team"
            )
            recommendations['compliance_checks'].append(
                "Document findings and remediation efforts for audit trail"
            )
        
        return recommendations
