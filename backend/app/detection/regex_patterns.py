"""
Regex Patterns Module - Comprehensive PII and Sensitive Data Detection
"""
import re
from enum import Enum
from typing import List, Tuple

class SensitivityLevel(Enum):
    """Risk levels for detected patterns"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RegexPatterns:
    """Collection of regex patterns for detecting sensitive data"""
    
    # ============ EMAIL PATTERNS ============
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    
    # ============ PHONE PATTERNS ============
    # US/International phone numbers
    PHONE_PATTERN = re.compile(
        r'(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b'
    )
    
    # ============ SOCIAL SECURITY NUMBER ============
    SSN_PATTERN = re.compile(
        r'\b(?!000|666|9\d{2})\d{3}-?\d{2}-?\d{4}\b'
    )
    
    # ============ CREDIT CARD PATTERNS ============
    # Visa, Mastercard, American Express, Discover
    CREDIT_CARD_PATTERN = re.compile(
        r'\b(?:\d{4}[-\s]?){3}\d{4}\b'  # Generic: XXXX-XXXX-XXXX-XXXX or XXXX XXXX XXXX XXXX
    )
    
    # ============ API KEYS & TOKENS ============
    # Common API key formats
    API_KEY_PATTERN = re.compile(
        r'(?:api[_-]?key|apikey|api_secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9\-_.]{20,})["\']?',
        re.IGNORECASE
    )
    
    # AWS Keys
    AWS_KEY_PATTERN = re.compile(
        r'AKIA[0-9A-Z]{16}'
    )
    
    # Generic token patterns (sk-*, pat-*, ghp-*, etc.)
    GENERIC_TOKEN_PATTERN = re.compile(
        r'\b(?:sk|pat|ghp|ghu|ghs|ghr|pk|rk)[-_][a-zA-Z0-9_-]{20,}\b',
        re.IGNORECASE
    )
    
    # ============ DATABASE CONNECTION STRINGS ============
    DB_CONNECTION_PATTERN = re.compile(
        r'(?:mongodb|mysql|postgresql|oracle|mssql)://[^\s]+',
        re.IGNORECASE
    )
    
    CONNECTION_STRING_PATTERN = re.compile(
        r'(?:password|passwd|pwd|secret)\s*[:=]\s*["\']?([^\s"\';,}]+)["\']?',
        re.IGNORECASE
    )
    
    # ============ PASSWORD PATTERNS ============
    # Common password assignments in code/logs (with or without quotes)
    # Allows 0-2 intervening words between keyword and assignment (e.g. "password found:")
    PASSWORD_PATTERN = re.compile(
        r'(?:password|passwd|pwd|pass|secret|credentials?)(?:\s+\w+){0,2}\s*[:=]\s*["\']?([^\s"\';,}\]]{4,})["\']?',
        re.IGNORECASE
    )
    
    # ============ PRIVATE KEYS ============
    PRIVATE_KEY_PATTERN = re.compile(
        r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY.*?-----END (?:RSA |DSA |EC )?PRIVATE KEY-----',
        re.DOTALL | re.IGNORECASE
    )
    
    # ============ CERTIFICATE PATTERNS ============
    CERTIFICATE_PATTERN = re.compile(
        r'-----BEGIN CERTIFICATE.*?-----END CERTIFICATE-----',
        re.DOTALL | re.IGNORECASE
    )
    
    # ============ STACK TRACES ============
    # Java/Python/C# stack traces (precise: requires package-style paths)
    STACK_TRACE_PATTERN = re.compile(
        r'(?:Traceback|Exception|at\s+[\w]+(?:\.[\w]+){2,}|File\s+"[^"]+",\s+line\s+\d+)',
        re.IGNORECASE
    )
    
    # ============ ERROR MESSAGES ============
    # Only match lines that actually contain error/exception keywords with details
    ERROR_LEAK_PATTERN = re.compile(
        r'(?:exception|traceback|stack\s*trace|NullPointer|Segfault|SIGSEGV|panic:|fatal\s+error)\s*[:\-].*?(?:\n|$)',
        re.IGNORECASE
    )
    
    # ============ HARDCODED CREDENTIALS ============
    # Requires assignment operator (= or :) and a non-trivial value
    HARDCODED_CRED_PATTERN = re.compile(
        r'(?:username|user_?name|uid|login_?id)\s*[:=]\s*["\']?([a-zA-Z0-9_.@-]{3,})["\']?',
        re.IGNORECASE
    )
    
    # ============ IP ADDRESSES ============
    IP_ADDRESS_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    # ============ FILE PATHS & SENSITIVE LOCATIONS ============
    FILE_PATH_PATTERN = re.compile(
        r'(?:/home/\w+|C:\\Users\\|/root|/etc/passwd|/var/log)'
    )


class PatternDetector:
    """Detect sensitive patterns in text"""
    
    @staticmethod
    def find_emails(text: str) -> List[Tuple[str, int, int]]:
        """Find email addresses. Returns: [(email, start, end), ...]"""
        return [(m.group(0), m.start(), m.end()) for m in RegexPatterns.EMAIL_PATTERN.finditer(text)]
    
    @staticmethod
    def find_phone_numbers(text: str) -> List[Tuple[str, int, int]]:
        """Find phone numbers"""
        return [(m.group(0), m.start(), m.end()) for m in RegexPatterns.PHONE_PATTERN.finditer(text)]
    
    @staticmethod
    def find_ssn(text: str) -> List[Tuple[str, int, int]]:
        """Find Social Security Numbers"""
        return [(m.group(0), m.start(), m.end()) for m in RegexPatterns.SSN_PATTERN.finditer(text)]
    
    @staticmethod
    def find_credit_cards(text: str) -> List[Tuple[str, int, int]]:
        """Find credit card numbers"""
        return [(m.group(0), m.start(), m.end()) for m in RegexPatterns.CREDIT_CARD_PATTERN.finditer(text)]
    
    @staticmethod
    def find_api_keys(text: str) -> List[Tuple[str, int, int]]:
        """Find API keys"""
        results = []
        for m in RegexPatterns.API_KEY_PATTERN.finditer(text):
            results.append((m.group(1), m.start(), m.end()))
        return results
    
    @staticmethod
    def find_aws_keys(text: str) -> List[Tuple[str, int, int]]:
        """Find AWS access keys"""
        return [(m.group(0), m.start(), m.end()) for m in RegexPatterns.AWS_KEY_PATTERN.finditer(text)]
    
    @staticmethod
    def find_generic_tokens(text: str) -> List[Tuple[str, int, int]]:
        """Find generic tokens (GitHub, OpenAI, etc.)"""
        return [(m.group(0), m.start(), m.end()) for m in RegexPatterns.GENERIC_TOKEN_PATTERN.finditer(text)]
    
    @staticmethod
    def find_passwords(text: str) -> List[Tuple[str, int, int]]:
        """Find password assignments"""
        results = []
        for m in RegexPatterns.PASSWORD_PATTERN.finditer(text):
            value = m.group(1)
            # Skip trivially short or placeholder values
            if value and len(value) >= 4 and value.lower() not in ('null', 'none', 'true', 'false', 'test'):
                results.append((value, m.start(), m.end()))
        return results
    
    @staticmethod
    def find_private_keys(text: str) -> List[Tuple[str, int, int]]:
        """Find PEM private keys"""
        return [(m.group(0)[:50] + "...", m.start(), m.end()) for m in RegexPatterns.PRIVATE_KEY_PATTERN.finditer(text)]
    
    @staticmethod
    def find_db_connections(text: str) -> List[Tuple[str, int, int]]:
        """Find database connection strings (excluding pure password assignments)"""
        results = []
        for m in RegexPatterns.DB_CONNECTION_PATTERN.finditer(text):
            results.append((m.group(0), m.start(), m.end()))
        # Only add CONNECTION_STRING_PATTERN matches that look like DB strings
        # (contain host, port, or protocol indicators — not just passwords)
        for m in RegexPatterns.CONNECTION_STRING_PATTERN.finditer(text):
            full_match = m.group(0)
            # Skip if this is just a password/secret assignment (already caught by PASSWORD_PATTERN)
            keyword = full_match.split('=')[0].split(':')[0].strip().lower() if '=' in full_match or ':' in full_match else ''
            if keyword in ('password', 'passwd', 'pwd', 'pass', 'secret'):
                continue  # Skip — caught by PASSWORD_PATTERN
            results.append((m.group(1), m.start(), m.end()))
        return results
    
    @staticmethod
    def find_stack_traces(text: str) -> List[Tuple[str, int, int]]:
        """Find stack traces"""
        return [(m.group(0)[:100], m.start(), m.end()) for m in RegexPatterns.STACK_TRACE_PATTERN.finditer(text)]
    
    @staticmethod
    def find_error_leaks(text: str) -> List[Tuple[str, int, int]]:
        """Find error messages that leak information"""
        return [(m.group(0)[:100], m.start(), m.end()) for m in RegexPatterns.ERROR_LEAK_PATTERN.finditer(text)]
    
    @staticmethod
    def find_hardcoded_credentials(text: str) -> List[Tuple[str, int, int]]:
        """Find hardcoded username/login patterns"""
        results = []
        for m in RegexPatterns.HARDCODED_CRED_PATTERN.finditer(text):
            results.append((m.group(1), m.start(), m.end()))
        return results
    
    @staticmethod
    def find_ip_addresses(text: str) -> List[Tuple[str, int, int]]:
        """Find IP addresses"""
        return [(m.group(0), m.start(), m.end()) for m in RegexPatterns.IP_ADDRESS_PATTERN.finditer(text)]
    
    @staticmethod
    def find_file_paths(text: str) -> List[Tuple[str, int, int]]:
        """Find sensitive file paths"""
        return [(m.group(0), m.start(), m.end()) for m in RegexPatterns.FILE_PATH_PATTERN.finditer(text)]


class PatternRiskMapper:
    """Map detected patterns to risk levels"""
    
    RISK_MAP = {
        'password': SensitivityLevel.CRITICAL,
        'api_key': SensitivityLevel.HIGH,
        'aws_key': SensitivityLevel.CRITICAL,
        'generic_token': SensitivityLevel.HIGH,
        'private_key': SensitivityLevel.CRITICAL,
        'db_connection': SensitivityLevel.HIGH,
        'credential': SensitivityLevel.CRITICAL,
        'hardcoded_credential': SensitivityLevel.CRITICAL,
        'credit_card': SensitivityLevel.CRITICAL,
        'ssn': SensitivityLevel.CRITICAL,
        'email': SensitivityLevel.LOW,
        'phone': SensitivityLevel.LOW,
        'ip_address': SensitivityLevel.MEDIUM,
        'stack_trace': SensitivityLevel.MEDIUM,
        'error_leak': SensitivityLevel.MEDIUM,
        'file_path': SensitivityLevel.MEDIUM,
    }
    
    @staticmethod
    def get_risk_level(pattern_type: str) -> SensitivityLevel:
        """Get risk level for a pattern type"""
        return PatternRiskMapper.RISK_MAP.get(pattern_type, SensitivityLevel.LOW)


# Mapping of detection methods to pattern types
DETECTION_METHODS = {
    'email': (PatternDetector.find_emails, SensitivityLevel.LOW),
    'phone': (PatternDetector.find_phone_numbers, SensitivityLevel.LOW),
    'ssn': (PatternDetector.find_ssn, SensitivityLevel.CRITICAL),
    'credit_card': (PatternDetector.find_credit_cards, SensitivityLevel.CRITICAL),
    'api_key': (PatternDetector.find_api_keys, SensitivityLevel.HIGH),
    'aws_key': (PatternDetector.find_aws_keys, SensitivityLevel.CRITICAL),
    'generic_token': (PatternDetector.find_generic_tokens, SensitivityLevel.HIGH),
    'password': (PatternDetector.find_passwords, SensitivityLevel.CRITICAL),
    'private_key': (PatternDetector.find_private_keys, SensitivityLevel.CRITICAL),
    'db_connection': (PatternDetector.find_db_connections, SensitivityLevel.HIGH),
    'stack_trace': (PatternDetector.find_stack_traces, SensitivityLevel.MEDIUM),
    'error_leak': (PatternDetector.find_error_leaks, SensitivityLevel.MEDIUM),
    'hardcoded_credential': (PatternDetector.find_hardcoded_credentials, SensitivityLevel.CRITICAL),
    'ip_address': (PatternDetector.find_ip_addresses, SensitivityLevel.MEDIUM),
    'file_path': (PatternDetector.find_file_paths, SensitivityLevel.MEDIUM),
}
