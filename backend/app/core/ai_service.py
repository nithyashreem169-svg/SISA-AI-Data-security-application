"""
AI Service Module - OpenAI SDK with Groq OpenAI-Compatible API
Provides AI-powered insights, summarization, and recommendations
"""
from typing import List, Dict, Any, Optional
from app.config import config
from app.utils.logger import logger

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class AIAnalyzer:
    """AI-powered analysis using OpenAI SDK with Groq backend"""
    
    def __init__(self):
        """Initialize OpenAI client with Groq endpoint"""
        self.available = OPENAI_AVAILABLE and bool(config.GROQ_API_KEY)
        self.model = config.GROQ_MODEL
        
        if self.available:
            try:
                self.client = OpenAI(
                    api_key=config.GROQ_API_KEY,
                    base_url="https://api.groq.com/openai/v1"
                )
                logger.info(f"OpenAI SDK with Groq initialized successfully (Model: {self.model})")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI+Groq: {e}")
                self.available = False
        else:
            logger.warning("OpenAI/Groq not available - AI features disabled")
    
    def generate_log_summary(self, lines: List[str], max_lines: int = 100) -> Optional[str]:
        """
        Generate AI-powered log summary
        
        Args:
            lines: Log lines to summarize
            max_lines: Max lines to send to AI (for token limits)
            
        Returns:
            AI-generated summary or None if unavailable
        """
        if not self.available:
            return None
        
        try:
            # Take a representative sample
            sample_lines = lines[:max_lines]
            log_content = "\n".join(sample_lines)
            
            message = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": f"""Analyze these log entries and provide a brief 2-3 sentence summary highlighting:
1. Main events/activities
2. Any errors or anomalies
3. Security concerns if any

Log entries:
{log_content}

Keep summary concise and focused on security implications."""
                    }
                ],
                max_tokens=300,
                temperature=0.7
            )
            
            summary = message.choices[0].message.content.strip()
            logger.info("AI log summary generated")
            return summary
            
        except Exception as e:
            logger.error(f"AI summarization failed: {e}")
            return None
    
    def generate_insights_from_findings(self, findings: List[Dict[str, Any]]) -> Optional[List[str]]:
        """
        Generate AI insights from detected findings
        
        Args:
            findings: List of detected security findings
            
        Returns:
            AI-generated actionable insights
        """
        if not self.available or not findings:
            return None
        
        try:
            # Prepare findings summary
            findings_text = "\n".join([
                f"- {f.get('type', 'unknown')}: {f.get('risk', 'unknown')} risk on line {f.get('line', '?')}"
                for f in findings[:20]  # Limit to top 20 findings
            ])
            
            prompt = f"""You are a security expert. Analyze these detected security findings and provide 3-4 specific, actionable insights:

Detected findings:
{findings_text}

For each insight, provide:
1. What the issue is
2. Why it's critical
3. How to fix it

Format as bullet points with risk indicators [CRITICAL], [HIGH], [MEDIUM]"""
            
            message = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=400,
                temperature=0.7
            )
            
            insights_text = message.choices[0].message.content.strip()
            insights = [line.strip() for line in insights_text.split('\n') if line.strip()]
            logger.info(f"AI insights generated ({len(insights)} points)")
            return insights
            
        except Exception as e:
            logger.error(f"AI insights generation failed: {e}")
            return None
    
    def correlate_findings(self, findings: List[Dict[str, Any]]) -> Optional[str]:
        """
        AI-powered correlation analysis across findings
        Identifies patterns and related issues
        
        Args:
            findings: List of security findings
            
        Returns:
            Correlation analysis or None
        """
        if not self.available or not findings:
            return None
        
        try:
            # Group findings by type
            finding_types = {}
            for f in findings:
                ftype = f.get('type', 'unknown')
                finding_types[ftype] = finding_types.get(ftype, 0) + 1
            
            findings_by_type = "\n".join([
                f"- {ftype}: {count} occurrences"
                for ftype, count in sorted(finding_types.items(), key=lambda x: x[1], reverse=True)
            ])
            
            prompt = f"""As a security analyst, identify correlations and patterns in these findings:

Finding distribution:
{findings_by_type}

Total findings: {len(findings)}

Provide insights on:
1. What patterns indicate about the system
2. Potential root causes
3. Related vulnerabilities that might exist
4. Recommended investigation priorities

Be concise and focus on actionable patterns."""
            
            message = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=350,
                temperature=0.7
            )
            
            correlation = message.choices[0].message.content.strip()
            logger.info("AI correlation analysis completed")
            return correlation
            
        except Exception as e:
            logger.error(f"AI correlation failed: {e}")
            return None
    
    def generate_remediation_ai(self, finding_type: str, risk_level: str, context: str = "") -> Optional[str]:
        """
        Generate AI-powered remediation steps
        
        Args:
            finding_type: Type of finding (e.g., 'password', 'api_key')
            risk_level: Risk level (critical, high, medium, low)
            context: Additional context about the finding
            
        Returns:
            Remediation steps or None
        """
        if not self.available:
            return None
        
        try:
            prompt = f"""Provide step-by-step remediation for this security issue:

Issue type: {finding_type}
Risk level: {risk_level}
Context: {context if context else 'No additional context'}

Format as numbered steps with:
1. Immediate actions (do first)
2. Short-term fixes (within 24 hours)
3. Long-term prevention

Keep it practical and specific to {finding_type}."""
            
            message = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=250,
                temperature=0.7
            )
            
            remediation = message.choices[0].message.content.strip()
            logger.info(f"AI remediation generated for {finding_type}")
            return remediation
            
        except Exception as e:
            logger.error(f"AI remediation generation failed: {e}")
            return None
    
    def generate_recommended_actions(self, findings: List[Dict[str, Any]], risk_score: int) -> Optional[List[str]]:
        """
        Generate AI-recommended actions based on findings and risk score
        
        Args:
            findings: List of detected security findings
            risk_score: Overall risk score
            
        Returns:
            List of AI-recommended actions
        """
        if not self.available or not findings:
            return None
        
        try:
            critical_findings = [f for f in findings if f.get('risk') == 'critical']
            high_findings = [f for f in findings if f.get('risk') == 'high']
            
            findings_summary = f"""
Critical Issues: {len(critical_findings)}
High Issues: {len(high_findings)}
Total Issues: {len(findings)}
Risk Score: {risk_score}/100
"""
            
            prompt = f"""Based on this security analysis, provide 4-5 prioritized recommended actions:

{findings_summary}

Provide specific, actionable recommendations in order of priority.
Start each with:
1. IMMEDIATE - for critical issues
2. SHORT-TERM - for issues within 24 hours
3. LONG-TERM - for strategic improvements"""
            
            message = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=300,
                temperature=0.7
            )
            
            actions_text = message.choices[0].message.content.strip()
            actions = [line.strip() for line in actions_text.split('\n') if line.strip() and line.strip()[0].isdigit()]
            logger.info(f"AI recommended actions generated ({len(actions)} actions)")
            return actions if actions else None
            
        except Exception as e:
            logger.error(f"AI recommended actions generation failed: {e}")
            return None
    
    def is_enabled(self) -> bool:
        """Check if AI features are enabled"""
        return self.available


# Singleton instance
ai_analyzer = AIAnalyzer()
