"""
Security and Compliance Module
Implements security features and compliance requirements
"""

import hashlib
import hmac
import secrets
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import jwt
import logging
from dataclasses import dataclass
from enum import Enum


class ComplianceLevel(Enum):
    """Compliance level definitions"""
    BASIC = 1
    STANDARD = 2
    STRICT = 3
    MAXIMUM = 4


@dataclass
class AuditLog:
    """Audit log entry"""
    timestamp: datetime
    user_id: str
    action: str
    resource: str
    details: Dict
    ip_address: str
    success: bool


class SecurityManager:
    """Manages security features for the threat detection system"""
    
    def __init__(self, config: Dict):
        """Initialize security manager"""
        self.config = config
        self.logger = logging.getLogger('SecurityManager')
        
        # Initialize encryption
        self.encryption_key = self._generate_or_load_key()
        self.cipher = Fernet(self.encryption_key)
        
        # JWT configuration
        self.jwt_secret = config.get('security', {}).get('jwt_secret', self._generate_jwt_secret())
        self.jwt_algorithm = 'HS256'
        self.token_expiry = config.get('security', {}).get('token_expiry', 3600)
        
        # Audit logging
        self.audit_enabled = config.get('compliance', {}).get('audit_logging', True)
        self.audit_logs = []
    
    def _generate_or_load_key(self) -> bytes:
        """Generate or load encryption key"""
        # In production, load from secure key management system
        return Fernet.generate_key()
    
    def _generate_jwt_secret(self) -> str:
        """Generate JWT secret"""
        return secrets.token_urlsafe(32)
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return encrypted.decode()
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        try:
            decrypted = self.cipher.decrypt(encrypted_data.encode())
            return decrypted.decode()
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        
        return key.hex(), salt.hex()
    
    def verify_password(self, password: str, hashed: str, salt: str) -> bool:
        """Verify password against hash"""
        try:
            computed_hash, _ = self.hash_password(password, bytes.fromhex(salt))
            return hmac.compare_digest(computed_hash, hashed)
        except:
            return False
    
    def generate_token(self, user_id: str, permissions: List[str]) -> str:
        """Generate JWT token"""
        payload = {
            'user_id': user_id,
            'permissions': permissions,
            'exp': datetime.utcnow() + timedelta(seconds=self.token_expiry),
            'iat': datetime.utcnow()
        }
        
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            self.logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            self.logger.warning("Invalid token")
            return None
    
    def log_audit_event(self, user_id: str, action: str, resource: str,
                       details: Dict, ip_address: str, success: bool):
        """Log audit event"""
        if not self.audit_enabled:
            return
        
        audit_log = AuditLog(
            timestamp=datetime.now(),
            user_id=user_id,
            action=action,
            resource=resource,
            details=details,
            ip_address=ip_address,
            success=success
        )
        
        self.audit_logs.append(audit_log)
        
        # Also log to file
        self.logger.info(
            f"AUDIT: User={user_id}, Action={action}, Resource={resource}, "
            f"Success={success}, IP={ip_address}"
        )
    
    def sanitize_input(self, input_data: str) -> str:
        """Sanitize user input to prevent injection attacks"""
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\n', '\r', '\t']
        sanitized = input_data
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Limit length
        max_length = 10000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    def check_rate_limit(self, user_id: str, action: str) -> bool:
        """Check if user has exceeded rate limit"""
        # Simplified rate limiting - in production use Redis
        # Returns True if within limit, False if exceeded
        return True
    
    def anonymize_data(self, data: Dict) -> Dict:
        """Anonymize personal data for compliance"""
        anonymized = data.copy()
        
        # Fields to anonymize
        pii_fields = ['email', 'phone', 'ip_address', 'name', 'address']
        
        for field in pii_fields:
            if field in anonymized:
                if field == 'email':
                    # Partial anonymization of email
                    parts = anonymized[field].split('@')
                    if len(parts) == 2:
                        anonymized[field] = f"{parts[0][:2]}***@{parts[1]}"
                elif field == 'ip_address':
                    # Anonymize last octet
                    parts = anonymized[field].split('.')
                    if len(parts) == 4:
                        anonymized[field] = f"{'.'.join(parts[:3])}.xxx"
                else:
                    # Hash other fields
                    anonymized[field] = hashlib.sha256(
                        anonymized[field].encode()
                    ).hexdigest()[:8]
        
        return anonymized


class ComplianceManager:
    """Manages compliance requirements"""
    
    def __init__(self, config: Dict):
        """Initialize compliance manager"""
        self.config = config
        self.logger = logging.getLogger('ComplianceManager')
        
        self.gdpr_compliant = config.get('compliance', {}).get('gdpr_compliant', True)
        self.data_retention_days = config.get('compliance', {}).get('data_retention_days', 90)
        self.legal_jurisdiction = config.get('compliance', {}).get('legal_jurisdiction', 'US')
    
    def check_data_retention(self, data_timestamp: datetime) -> bool:
        """Check if data should be retained based on retention policy"""
        retention_period = timedelta(days=self.data_retention_days)
        return datetime.now() - data_timestamp <= retention_period
    
    def get_required_consent(self) -> List[str]:
        """Get required consent items based on jurisdiction"""
        consent_items = ['data_processing', 'threat_analysis']
        
        if self.gdpr_compliant:
            consent_items.extend([
                'personal_data_storage',
                'automated_decision_making',
                'data_sharing_law_enforcement'
            ])
        
        if self.legal_jurisdiction == 'US':
            consent_items.append('law_enforcement_cooperation')
        elif self.legal_jurisdiction == 'EU':
            consent_items.append('cross_border_data_transfer')
        
        return consent_items
    
    def validate_data_request(self, request_type: str, user_id: str) -> bool:
        """Validate data access/deletion requests for compliance"""
        valid_requests = ['access', 'deletion', 'portability', 'rectification']
        
        if request_type not in valid_requests:
            return False
        
        # Check if user has right to request
        # In production, would verify user identity
        return True
    
    def generate_compliance_report(self) -> Dict:
        """Generate compliance report"""
        return {
            'timestamp': datetime.now().isoformat(),
            'gdpr_compliant': self.gdpr_compliant,
            'data_retention_days': self.data_retention_days,
            'legal_jurisdiction': self.legal_jurisdiction,
            'encryption_enabled': True,
            'audit_logging_enabled': True,
            'anonymization_enabled': True,
            'consent_management': True,
            'data_breach_protocol': True
        }
    
    def handle_data_breach(self, breach_details: Dict):
        """Handle data breach according to compliance requirements"""
        self.logger.critical(f"DATA BREACH DETECTED: {breach_details}")
        
        # Required actions based on compliance
        if self.gdpr_compliant:
            # GDPR requires notification within 72 hours
            self._notify_authorities(breach_details)
            self._notify_affected_users(breach_details)
        
        # Log breach
        self._log_breach(breach_details)
        
        # Initiate containment
        self._initiate_breach_containment(breach_details)
    
    def _notify_authorities(self, breach_details: Dict):
        """Notify relevant authorities of data breach"""
        # In production, would send actual notifications
        self.logger.info("Notifying authorities of data breach")
    
    def _notify_affected_users(self, breach_details: Dict):
        """Notify affected users of data breach"""
        # In production, would send actual notifications
        self.logger.info("Notifying affected users of data breach")
    
    def _log_breach(self, breach_details: Dict):
        """Log data breach details"""
        breach_log = {
            'timestamp': datetime.now().isoformat(),
            'details': breach_details,
            'actions_taken': ['authorities_notified', 'users_notified', 'containment_initiated']
        }
        # In production, would store in secure breach log
        self.logger.info(f"Breach logged: {breach_log}")
    
    def _initiate_breach_containment(self, breach_details: Dict):
        """Initiate breach containment procedures"""
        # In production, would trigger actual containment
        self.logger.info("Initiating breach containment procedures")


class AccessControl:
    """Manages access control and permissions"""
    
    def __init__(self):
        """Initialize access control"""
        self.roles = {
            'admin': ['all'],
            'investigator': ['read', 'analyze', 'report'],
            'analyst': ['read', 'analyze'],
            'viewer': ['read']
        }
        
        self.resources = {
            'threats': ['read', 'write', 'delete'],
            'profiles': ['read', 'write', 'delete'],
            'devices': ['read', 'write'],
            'reports': ['read', 'write'],
            'settings': ['read', 'write']
        }
    
    def check_permission(self, user_role: str, resource: str, action: str) -> bool:
        """Check if user has permission for action on resource"""
        if user_role not in self.roles:
            return False
        
        user_permissions = self.roles[user_role]
        
        if 'all' in user_permissions:
            return True
        
        if resource not in self.resources:
            return False
        
        if action not in self.resources[resource]:
            return False
        
        return action in user_permissions
    
    def get_user_permissions(self, user_role: str) -> List[str]:
        """Get list of permissions for user role"""
        return self.roles.get(user_role, [])
    
    def add_role(self, role_name: str, permissions: List[str]):
        """Add new role with permissions"""
        self.roles[role_name] = permissions
    
    def update_role_permissions(self, role_name: str, permissions: List[str]):
        """Update permissions for existing role"""
        if role_name in self.roles:
            self.roles[role_name] = permissions