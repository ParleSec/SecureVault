"""
Security monitoring and threat detection
"""

import os
import time
import json
import logging
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from datetime import datetime, timedelta
from pathlib import Path
from threading import Thread, Lock
import platform
from collections import deque

logger = logging.getLogger(__name__)

class SecurityEvent:
    """
    Represents a security-related event
    """
    def __init__(self, 
                event_type: str,
                severity: str,
                source: str,
                details: Dict[str, Any],
                timestamp: Optional[datetime] = None):
        self.event_type = event_type
        self.severity = severity  # 'low', 'medium', 'high', 'critical'
        self.source = source
        self.details = details
        self.timestamp = timestamp or datetime.utcnow()
        self.event_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate a unique ID for this event"""
        data = f"{self.timestamp.isoformat()}:{self.event_type}:{self.source}:{json.dumps(self.details)}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'severity': self.severity,
            'source': self.source,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        """Create from dictionary"""
        event = cls(
            event_type=data['event_type'],
            severity=data['severity'],
            source=data['source'],
            details=data['details'],
            timestamp=datetime.fromisoformat(data['timestamp'])
        )
        event.event_id = data['event_id']
        return event

class SecurityMonitor:
    """
    Monitors and logs security events with threat detection
    """
    def __init__(self,
                log_dir: Optional[str] = './logs/security',
                event_retention_days: int = 90,
                alert_handlers: Optional[List[Callable[[SecurityEvent], None]]] = None):
        self.log_dir = Path(log_dir) if log_dir else None
        self.event_retention_days = event_retention_days
        self.alert_handlers = alert_handlers or []
        
        # In-memory event storage
        self.recent_events: deque = deque(maxlen=1000)
        self.event_lock = Lock()
        
        # Threat detection
        self.threat_detectors = []
        self._initialize_threat_detectors()
        
        # Ensure log directory exists
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def _initialize_threat_detectors(self):
        """Initialize built-in threat detectors"""
        # Authentication failure detector
        self.threat_detectors.append(
            AuthFailureDetector(threshold=5, window_minutes=15)
        )
        
        # File tampering detector
        self.threat_detectors.append(
            FileTamperingDetector()
        )
        
        # Permission change detector
        self.threat_detectors.append(
            PermissionChangeDetector()
        )
        
        # Rate limiting detector
        self.threat_detectors.append(
            RateLimitDetector(threshold=20, window_minutes=5)
        )
    
    def add_event(self, event: SecurityEvent) -> str:
        """
        Add a security event and trigger threat detection
        Returns the event ID
        """
        with self.event_lock:
            # Add to in-memory storage
            self.recent_events.append(event)
            
            # Log the event
            if self.log_dir:
                self._log_event_to_file(event)
            
            # Run threat detection
            self._check_for_threats(event)
            
            # Process alerts for high severity events
            if event.severity in ('high', 'critical'):
                self._trigger_alerts(event)
        
        return event.event_id
    
    def _log_event_to_file(self, event: SecurityEvent):
        """Log event to secure file"""
        try:
            # Create daily log file
            date_str = event.timestamp.strftime('%Y-%m-%d')
            log_file = self.log_dir / f"security-{date_str}.log"
            
            # Append event as JSON
            with open(log_file, 'a') as f:
                f.write(json.dumps(event.to_dict()) + '\n')
            
            # Set secure permissions on Unix systems
            if platform.system() != 'Windows':
                import stat
                os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
                
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    def _check_for_threats(self, event: SecurityEvent):
        """Run threat detection on event"""
        for detector in self.threat_detectors:
            try:
                threat = detector.check_event(event, self.recent_events)
                if threat:
                    # Create threat event
                    threat_event = SecurityEvent(
                        event_type=f"THREAT:{detector.name}",
                        severity=threat.severity,
                        source='security_monitor',
                        details={
                            'threat_type': threat.threat_type,
                            'description': threat.description,
                            'related_events': [e.event_id for e in threat.related_events],
                            'confidence': threat.confidence,
                            'mitigations': threat.mitigations
                        }
                    )
                    
                    # Add threat event and trigger alerts
                    self.recent_events.append(threat_event)
                    if self.log_dir:
                        self._log_event_to_file(threat_event)
                    
                    # Always trigger alerts for threats
                    self._trigger_alerts(threat_event)
                    
            except Exception as e:
                logger.error(f"Threat detector {detector.name} failed: {e}")
    
    def _trigger_alerts(self, event: SecurityEvent):
        """Trigger alert handlers for an event"""
        for handler in self.alert_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")
    
    def get_recent_events(self, 
                         event_types: Optional[List[str]] = None,
                         severity: Optional[List[str]] = None,
                         source: Optional[List[str]] = None,
                         min_timestamp: Optional[datetime] = None,
                         max_timestamp: Optional[datetime] = None) -> List[SecurityEvent]:
        """
        Get filtered recent events
        """
        with self.event_lock:
            events = list(self.recent_events)
        
        # Apply filters
        filtered = events
        
        if event_types:
            filtered = [e for e in filtered if e.event_type in event_types]
        
        if severity:
            filtered = [e for e in filtered if e.severity in severity]
        
        if source:
            filtered = [e for e in filtered if e.source in source]
        
        if min_timestamp:
            filtered = [e for e in filtered if e.timestamp >= min_timestamp]
        
        if max_timestamp:
            filtered = [e for e in filtered if e.timestamp <= max_timestamp]
        
        return filtered
    
    def cleanup_old_events(self):
        """Clean up events older than retention period"""
        if not self.log_dir:
            return
            
        try:
            retention_limit = datetime.utcnow() - timedelta(days=self.event_retention_days)
            
            # Find old log files
            for log_file in self.log_dir.glob('security-*.log'):
                try:
                    # Extract date from filename
                    date_str = log_file.stem.split('-')[1]
                    log_date = datetime.strptime(date_str, '%Y-%m-%d')
                    
                    # Delete if older than retention period
                    if log_date.replace(tzinfo=None) < retention_limit:
                        os.remove(log_file)
                except (ValueError, IndexError):
                    # Skip files with invalid format
                    continue
                    
        except Exception as e:
            logger.error(f"Failed to clean up old events: {e}")
    
    def start_background_tasks(self):
        """Start background monitoring tasks"""
        def run_cleanup():
            while True:
                try:
                    # Run daily cleanup
                    self.cleanup_old_events()
                    
                    # Sleep for a day
                    time.sleep(86400)  # 24 hours
                except Exception as e:
                    logger.error(f"Background task error: {e}")
                    time.sleep(3600)  # Retry after an hour on error
        
        # Start cleanup thread
        cleanup_thread = Thread(target=run_cleanup, daemon=True)
        cleanup_thread.start()

class ThreatInfo:
    """
    Information about a detected threat
    """
    def __init__(self,
                threat_type: str,
                severity: str,
                description: str,
                related_events: List[SecurityEvent],
                confidence: float,
                mitigations: List[str]):
        self.threat_type = threat_type
        self.severity = severity
        self.description = description
        self.related_events = related_events
        self.confidence = confidence  # 0.0 to 1.0
        self.mitigations = mitigations

class ThreatDetector:
    """
    Base class for threat detectors
    """
    def __init__(self, name: str):
        self.name = name
    
    def check_event(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> Optional[ThreatInfo]:
        """
        Check if the event indicates a threat
        Returns ThreatInfo if a threat is detected, None otherwise
        """
        raise NotImplementedError("Subclasses must implement check_event()")

class AuthFailureDetector(ThreatDetector):
    """
    Detects authentication brute force attempts
    """
    def __init__(self, threshold: int = 5, window_minutes: int = 15):
        super().__init__("AuthFailureDetector")
        self.threshold = threshold
        self.window_minutes = window_minutes
    
    def check_event(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> Optional[ThreatInfo]:
        # Only check auth failure events
        if event.event_type != 'auth_failure':
            return None
        
        # Get timestamp window
        window_start = event.timestamp - timedelta(minutes=self.window_minutes)
        
        # Count auth failures in window
        source_ip = event.details.get('source_ip', 'unknown')
        username = event.details.get('username', 'unknown')
        
        # Find related failures
        related_failures = [
            e for e in recent_events
            if e.event_type == 'auth_failure' and
               e.timestamp >= window_start and
               (e.details.get('source_ip') == source_ip or
                e.details.get('username') == username)
        ]
        
        # If threshold reached, report threat
        if len(related_failures) >= self.threshold:
            return ThreatInfo(
                threat_type="brute_force_attempt",
                severity="high",
                description=f"Multiple authentication failures detected from {source_ip} for user {username}",
                related_events=related_failures,
                confidence=min(0.5 + (len(related_failures) / self.threshold * 0.5), 0.95),
                mitigations=[
                    f"Temporarily block IP address {source_ip}",
                    f"Lock account {username}",
                    "Enable additional authentication factors"
                ]
            )
        
        return None

class FileTamperingDetector(ThreatDetector):
    """
    Detects file tampering attempts
    """
    def __init__(self):
        super().__init__("FileTamperingDetector")
    
    def check_event(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> Optional[ThreatInfo]:
        # Check for signature verification failures
        if event.event_type == 'signature_verification_failed':
            return ThreatInfo(
                threat_type="file_tampering",
                severity="critical", 
                description="File signature verification failed, possible tampering detected",
                related_events=[event],
                confidence=0.9,
                mitigations=[
                    "Restore file from backup",
                    "Investigate unauthorized access",
                    "Verify file integrity across vault"
                ]
            )
        
        # Check for unusual file modifications
        if event.event_type == 'file_modified':
            # Look for previous access denied events
            window_start = event.timestamp - timedelta(minutes=30)
            file_path = event.details.get('file_path', '')
            
            # Find related suspicious events
            suspicious_events = [
                e for e in recent_events
                if e.timestamp >= window_start and
                   (e.event_type in ('access_denied', 'permission_changed') and
                    e.details.get('file_path', '') == file_path)
            ]
            
            if suspicious_events:
                return ThreatInfo(
                    threat_type="suspicious_file_modification",
                    severity="high",
                    description=f"Suspicious modification pattern detected for {file_path}",
                    related_events=suspicious_events + [event],
                    confidence=0.7,
                    mitigations=[
                        "Review file modifications",
                        "Check file permissions",
                        "Verify user authorization"
                    ]
                )
        
        return None

class PermissionChangeDetector(ThreatDetector):
    """
    Detects suspicious permission changes
    """
    def __init__(self):
        super().__init__("PermissionChangeDetector")
    
    def check_event(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> Optional[ThreatInfo]:
        if event.event_type != 'permission_changed':
            return None
        
        # Check for insecure permissions
        if event.details.get('new_permissions', '').endswith('777') or \
           event.details.get('new_permissions', '') == 'everyone_full_control':
            return ThreatInfo(
                threat_type="insecure_permissions",
                severity="high",
                description="Highly insecure permissions detected",
                related_events=[event],
                confidence=0.85,
                mitigations=[
                    "Restore secure permissions immediately",
                    "Audit other permission changes",
                    "Review access control policies"
                ]
            )
        
        # Look for multiple permission changes
        window_start = event.timestamp - timedelta(hours=1)
        
        # Count recent permission changes
        permission_changes = [
            e for e in recent_events
            if e.event_type == 'permission_changed' and
               e.timestamp >= window_start
        ]
        
        if len(permission_changes) > 3:
            return ThreatInfo(
                threat_type="mass_permission_changes",
                severity="medium",
                description="Multiple permission changes in short time period",
                related_events=permission_changes,
                confidence=0.6,
                mitigations=[
                    "Review recent permission changes",
                    "Verify changes were authorized",
                    "Consider restoring previous permissions"
                ]
            )
        
        return None

class RateLimitDetector(ThreatDetector):
    """
    Detects rate limit violations indicating DoS attempts
    """
    def __init__(self, threshold: int = 20, window_minutes: int = 5):
        super().__init__("RateLimitDetector")
        self.threshold = threshold
        self.window_minutes = window_minutes
    
    def check_event(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> Optional[ThreatInfo]:
        if event.event_type != 'rate_limit_exceeded':
            return None
        
        # Get timestamp window
        window_start = event.timestamp - timedelta(minutes=self.window_minutes)
        
        # Count rate limit events for this source
        source_ip = event.details.get('source_ip', 'unknown')
        user_id = event.details.get('user_id', 'unknown')
        
        related_events = [
            e for e in recent_events
            if e.event_type == 'rate_limit_exceeded' and
               e.timestamp >= window_start and
               (e.details.get('source_ip') == source_ip or
                e.details.get('user_id') == user_id)
        ]
        if len(related_events) >= self.threshold:
            return ThreatInfo(
                threat_type="denial_of_service_attempt",
                severity="high",
                description=f"Multiple rate limit violations detected from {source_ip} / user {user_id}",
                related_events=related_events,
                confidence=min(0.6 + (len(related_events) / self.threshold * 0.3), 0.9),
                mitigations=[
                    f"Block IP address {source_ip}",
                    f"Temporarily suspend account {user_id}",
                    "Increase rate limiting restrictions",
                    "Enable CAPTCHA for this source"
                ]
            )
        
        return None

class SecurityMonitoringSystem:
    """
    Complete security monitoring system with notifications and integrations
    """
    def __init__(self, 
                log_dir: str = './logs/security',
                monitoring_config: Optional[Dict[str, Any]] = None):
        self.config = monitoring_config or {}
        self.monitor = SecurityMonitor(
            log_dir=log_dir,
            event_retention_days=self.config.get('event_retention_days', 90),
            alert_handlers=[self._handle_alert]
        )
        
        # Initialize notification systems
        self.notification_handlers = {}
        self._setup_notification_handlers()
        
        # Start background tasks
        self.monitor.start_background_tasks()
        
        # Setup metrics collection
        self.metrics = {
            'events_total': 0,
            'events_by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'events_by_type': {},
            'threats_detected': 0,
            'alerts_triggered': 0
        }
        self.metrics_lock = Lock()
    
    def _setup_notification_handlers(self):
        """Setup notification systems based on configuration"""
        # Setup email notifications if configured
        if 'email' in self.config:
            self.notification_handlers['email'] = self._create_email_handler()
        
        # Setup log file notifications
        self.notification_handlers['log'] = self._create_log_handler()
        
        # Setup console notifications
        self.notification_handlers['console'] = self._create_console_handler()
    
    def _create_email_handler(self):
        """Create email notification handler"""
        email_config = self.config.get('email', {})
        
        def send_email_alert(event: SecurityEvent):
            try:
                import smtplib
                from email.mime.text import MIMEText
                
                # Only send emails for high and critical events
                if event.severity not in ('high', 'critical'):
                    return
                
                server = email_config.get('smtp_server')
                port = email_config.get('smtp_port', 587)
                username = email_config.get('username')
                password = email_config.get('password')
                recipients = email_config.get('recipients', [])
                
                if not server or not recipients:
                    logger.error("Email configuration incomplete")
                    return
                
                # Create message
                msg = MIMEText(
                    f"Security Alert: {event.event_type}\n"
                    f"Severity: {event.severity}\n"
                    f"Time: {event.timestamp.isoformat()}\n"
                    f"Details: {json.dumps(event.details, indent=2)}"
                )
                
                msg['Subject'] = f"[SECURITY ALERT] {event.severity.upper()}: {event.event_type}"
                msg['From'] = email_config.get('from_address', username)
                msg['To'] = ', '.join(recipients)
                
                # Send email
                with smtplib.SMTP(server, port) as smtp:
                    if username and password:
                        smtp.starttls()
                        smtp.login(username, password)
                    smtp.send_message(msg)
                
                logger.info(f"Security alert email sent for event {event.event_id}")
                
            except Exception as e:
                logger.error(f"Failed to send email alert: {e}")
        
        return send_email_alert
    
    def _create_log_handler(self):
        """Create log file notification handler"""
        def log_alert(event: SecurityEvent):
            try:
                log_message = (
                    f"SECURITY ALERT [{event.severity.upper()}]: {event.event_type} "
                    f"({event.timestamp.isoformat()}) - {json.dumps(event.details)}"
                )
                
                if event.severity == 'critical':
                    logger.critical(log_message)
                elif event.severity == 'high':
                    logger.error(log_message)
                elif event.severity == 'medium':
                    logger.warning(log_message)
                else:
                    logger.info(log_message)
                    
            except Exception as e:
                logger.error(f"Failed to log alert: {e}")
        
        return log_alert
    
    def _create_console_handler(self):
        """Create console notification handler"""
        def console_alert(event: SecurityEvent):
            try:
                if event.severity in ('high', 'critical'):
                    # Print to stderr for high severity
                    print(
                        f"\n{'!' * 80}\n"
                        f"SECURITY ALERT [{event.severity.upper()}]: {event.event_type}\n"
                        f"Time: {event.timestamp.isoformat()}\n"
                        f"Details: {json.dumps(event.details, indent=2)}\n"
                        f"{'!' * 80}\n",
                        file=sys.stderr
                    )
            except Exception as e:
                logger.error(f"Failed to send console alert: {e}")
        
        return console_alert
    
    def _handle_alert(self, event: SecurityEvent):
        """
        Process security alerts through all notification channels
        """
        with self.metrics_lock:
            self.metrics['alerts_triggered'] += 1
        
        # Send notifications through all handlers
        for handler_name, handler in self.notification_handlers.items():
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Alert handler '{handler_name}' failed: {e}")
    
    def log_security_event(self, event_type: str, severity: str, 
                         source: str, details: Dict[str, Any]) -> str:
        """
        Log a security event and trigger appropriate responses
        Returns the event ID
        """
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            source=source,
            details=details
        )
        
        # Update metrics
        with self.metrics_lock:
            self.metrics['events_total'] += 1
            self.metrics['events_by_severity'][severity] += 1
            
            if event_type not in self.metrics['events_by_type']:
                self.metrics['events_by_type'][event_type] = 0
            self.metrics['events_by_type'][event_type] += 1
        
        # Add to monitor
        event_id = self.monitor.add_event(event)
        return event_id
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get current security metrics"""
        with self.metrics_lock:
            return dict(self.metrics)
    
    def get_recent_threats(self, hours: int = 24) -> List[ThreatInfo]:
        """Get recent threats detected in the specified time window"""
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get threat events
        threat_events = self.monitor.get_recent_events(
            event_types=[t for t in self.monitor.recent_events if t.startswith('THREAT:')],
            min_timestamp=start_time
        )
        
        # Extract threat info
        threats = []
        for event in threat_events:
            if 'threat_type' in event.details:
                threat = ThreatInfo(
                    threat_type=event.details['threat_type'],
                    severity=event.severity,
                    description=event.details.get('description', ''),
                    related_events=[],  # Can't fully reconstruct
                    confidence=event.details.get('confidence', 0.0),
                    mitigations=event.details.get('mitigations', [])
                )
                threats.append(threat)
        
        return threats
    
    def search_security_events(self,
                             start_time: Optional[datetime] = None,
                             end_time: Optional[datetime] = None,
                             severity: Optional[List[str]] = None,
                             event_types: Optional[List[str]] = None,
                             source: Optional[str] = None,
                             limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search security events with filters
        """
        filters = {}
        if start_time:
            filters['min_timestamp'] = start_time
        if end_time:
            filters['max_timestamp'] = end_time
        if severity:
            filters['severity'] = severity
        if event_types:
            filters['event_types'] = event_types
        if source:
            filters['source'] = [source]
        
        # Get matching events
        events = self.monitor.get_recent_events(**filters)
        
        # Sort by timestamp (newest first) and limit
        events.sort(key=lambda e: e.timestamp, reverse=True)
        events = events[:limit]
        
        # Convert to dicts
        return [event.to_dict() for event in events]

# Create a global security monitoring system
security_system = SecurityMonitoringSystem()
        
