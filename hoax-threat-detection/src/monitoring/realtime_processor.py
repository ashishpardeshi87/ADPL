"""
Real-time Processing Module
Coordinates real-time threat detection across multiple channels
"""

import asyncio
import json
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from collections import deque
import logging
from dataclasses import dataclass, asdict
from enum import Enum
import redis
from concurrent.futures import ThreadPoolExecutor
import websockets

# Import core modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import ThreatDetector, MetadataExtractor, DeviceFingerprinter, BehavioralProfiler
from core.threat_detector import ThreatLevel

class AlertPriority(Enum):
    """Alert priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

@dataclass
class ThreatAlert:
    """Threat alert data structure"""
    alert_id: str
    timestamp: datetime
    source: str
    threat_level: ThreatLevel
    priority: AlertPriority
    confidence: float
    message: str
    metadata: Dict
    fingerprint: Optional[str]
    profile_id: Optional[str]
    action_required: bool
    auto_response: Optional[str]

class RealtimeProcessor:
    """
    Central real-time processing engine for threat detection
    """
    
    def __init__(self, config: Dict):
        """Initialize the real-time processor"""
        self.config = config
        self.logger = self._setup_logging()
        
        # Initialize core components
        self.threat_detector = ThreatDetector()
        self.metadata_extractor = MetadataExtractor()
        self.device_fingerprinter = DeviceFingerprinter()
        self.behavioral_profiler = BehavioralProfiler()
        
        # Initialize storage
        self.redis_client = self._setup_redis()
        
        # Processing queues
        self.incoming_queue = asyncio.Queue()
        self.processing_queue = asyncio.Queue()
        self.alert_queue = asyncio.Queue()
        
        # Active monitoring sessions
        self.active_monitors = {}
        
        # Alert history (circular buffer)
        self.alert_history = deque(maxlen=1000)
        
        # Websocket connections for real-time updates
        self.websocket_clients = set()
        
        # Thread pool for CPU-intensive tasks
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Statistics
        self.stats = {
            'messages_processed': 0,
            'threats_detected': 0,
            'alerts_generated': 0,
            'false_positives': 0,
            'processing_time_avg': 0
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('RealtimeProcessor')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _setup_redis(self) -> Optional[redis.Redis]:
        """Setup Redis connection for caching and pub/sub"""
        try:
            client = redis.Redis(
                host=self.config.get('cache', {}).get('host', 'localhost'),
                port=self.config.get('cache', {}).get('port', 6379),
                db=self.config.get('cache', {}).get('db', 0),
                decode_responses=True
            )
            client.ping()
            return client
        except Exception as e:
            self.logger.warning(f"Redis not available: {e}")
            return None
    
    async def start(self):
        """Start the real-time processor"""
        self.logger.info("Starting Real-time Processor...")
        
        # Start processing tasks
        tasks = [
            asyncio.create_task(self.process_incoming()),
            asyncio.create_task(self.analyze_threats()),
            asyncio.create_task(self.handle_alerts()),
            asyncio.create_task(self.websocket_server()),
            asyncio.create_task(self.statistics_reporter())
        ]
        
        # Start monitoring channels
        await self.start_monitors()
        
        # Wait for all tasks
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            self.logger.info("Shutting down Real-time Processor...")
            await self.shutdown()
    
    async def start_monitors(self):
        """Start all configured monitoring channels"""
        monitors_config = self.config.get('monitoring', {})
        
        # Start email monitor
        if monitors_config.get('email', {}).get('enabled'):
            from .email_monitor import EmailMonitor
            email_monitor = EmailMonitor(monitors_config['email'], self.incoming_queue)
            self.active_monitors['email'] = email_monitor
            asyncio.create_task(email_monitor.start())
        
        # Start social media monitors
        if monitors_config.get('social_media', {}).get('twitter', {}).get('enabled'):
            from .social_media_monitor import TwitterMonitor
            twitter_monitor = TwitterMonitor(
                monitors_config['social_media']['twitter'],
                self.incoming_queue
            )
            self.active_monitors['twitter'] = twitter_monitor
            asyncio.create_task(twitter_monitor.start())
        
        if monitors_config.get('social_media', {}).get('telegram', {}).get('enabled'):
            from .social_media_monitor import TelegramMonitor
            telegram_monitor = TelegramMonitor(
                monitors_config['social_media']['telegram'],
                self.incoming_queue
            )
            self.active_monitors['telegram'] = telegram_monitor
            asyncio.create_task(telegram_monitor.start())
    
    async def process_incoming(self):
        """Process incoming messages from all sources"""
        while True:
            try:
                # Get message from queue
                message = await self.incoming_queue.get()
                
                # Add processing timestamp
                message['processing_started'] = datetime.now().isoformat()
                
                # Extract metadata
                metadata = await self._extract_metadata(message)
                message['metadata'] = metadata
                
                # Generate device fingerprint
                if message.get('device_data'):
                    fingerprint = await self._generate_fingerprint(message['device_data'])
                    message['fingerprint'] = fingerprint
                
                # Add to processing queue
                await self.processing_queue.put(message)
                
                # Update statistics
                self.stats['messages_processed'] += 1
                
            except Exception as e:
                self.logger.error(f"Error processing incoming message: {e}")
                await asyncio.sleep(0.1)
    
    async def analyze_threats(self):
        """Analyze messages for threats"""
        while True:
            try:
                # Get message from processing queue
                message = await self.processing_queue.get()
                
                # Perform threat detection
                threat_analysis = await self._detect_threat(message)
                
                # Perform behavioral analysis
                behavioral_analysis = await self._analyze_behavior(message)
                
                # Combine analyses
                combined_analysis = self._combine_analyses(
                    threat_analysis,
                    behavioral_analysis,
                    message
                )
                
                # Generate alert if needed
                if self._should_generate_alert(combined_analysis):
                    alert = self._create_alert(combined_analysis)
                    await self.alert_queue.put(alert)
                    
                    # Update statistics
                    self.stats['threats_detected'] += 1
                
                # Store in database
                await self._store_analysis(combined_analysis)
                
                # Broadcast to websocket clients
                await self._broadcast_update(combined_analysis)
                
            except Exception as e:
                self.logger.error(f"Error analyzing threat: {e}")
                await asyncio.sleep(0.1)
    
    async def handle_alerts(self):
        """Handle generated alerts"""
        while True:
            try:
                # Get alert from queue
                alert = await self.alert_queue.get()
                
                # Log alert
                self.logger.warning(f"THREAT ALERT: {alert.message}")
                
                # Store alert
                self.alert_history.append(alert)
                if self.redis_client:
                    self._store_alert_redis(alert)
                
                # Send notifications
                await self._send_notifications(alert)
                
                # Take automatic actions if configured
                if alert.auto_response:
                    await self._execute_auto_response(alert)
                
                # Update statistics
                self.stats['alerts_generated'] += 1
                
            except Exception as e:
                self.logger.error(f"Error handling alert: {e}")
                await asyncio.sleep(0.1)
    
    async def _extract_metadata(self, message: Dict) -> Dict:
        """Extract metadata from message"""
        loop = asyncio.get_event_loop()
        
        source_type = message.get('source_type', '')
        
        if source_type == 'email':
            metadata = await loop.run_in_executor(
                self.executor,
                self.metadata_extractor.extract_from_email,
                message.get('raw_content', b''),
                message.get('headers', {})
            )
        elif source_type == 'social_media':
            metadata = await loop.run_in_executor(
                self.executor,
                self.metadata_extractor.extract_from_social_media,
                message.get('post_data', {}),
                message.get('platform', '')
            )
        elif source_type == 'web_request':
            metadata = await loop.run_in_executor(
                self.executor,
                self.metadata_extractor.extract_from_web_request,
                message.get('headers', {}),
                message.get('body', '')
            )
        else:
            metadata = {}
        
        return metadata
    
    async def _generate_fingerprint(self, device_data: Dict) -> Dict:
        """Generate device fingerprint"""
        loop = asyncio.get_event_loop()
        
        fingerprint = await loop.run_in_executor(
            self.executor,
            self.device_fingerprinter.generate_fingerprint,
            device_data
        )
        
        return fingerprint
    
    async def _detect_threat(self, message: Dict) -> Dict:
        """Detect threats in message"""
        loop = asyncio.get_event_loop()
        
        text = message.get('text', '') or message.get('content', '')
        metadata = message.get('metadata', {})
        
        threat_analysis = await loop.run_in_executor(
            self.executor,
            self.threat_detector.detect_threat,
            text,
            metadata
        )
        
        return asdict(threat_analysis)
    
    async def _analyze_behavior(self, message: Dict) -> Dict:
        """Analyze behavioral patterns"""
        loop = asyncio.get_event_loop()
        
        # Get historical messages for the same source
        source_id = self._get_source_identifier(message)
        historical_messages = await self._get_historical_messages(source_id)
        
        if len(historical_messages) >= 2:
            profile = await loop.run_in_executor(
                self.executor,
                self.behavioral_profiler.create_profile,
                historical_messages + [message]
            )
            
            # Check for linked profiles
            similar_profiles = await self._find_similar_profiles(profile)
            
            return {
                'profile': profile,
                'linked_profiles': similar_profiles
            }
        
        return {}
    
    def _combine_analyses(self, threat_analysis: Dict, 
                         behavioral_analysis: Dict, message: Dict) -> Dict:
        """Combine threat and behavioral analyses"""
        combined = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'threat_analysis': threat_analysis,
            'behavioral_analysis': behavioral_analysis,
            'risk_score': 0.0,
            'confidence': 0.0
        }
        
        # Calculate combined risk score
        threat_level = threat_analysis.get('threat_level', 0)
        if isinstance(threat_level, ThreatLevel):
            threat_score = threat_level.value / 4.0
        else:
            threat_score = threat_level / 4.0
        
        behavioral_risk = 0.0
        if behavioral_analysis.get('profile'):
            profile = behavioral_analysis['profile']
            risk_indicators = profile.get('risk_indicators', [])
            behavioral_risk = min(1.0, len(risk_indicators) * 0.25)
        
        # Weight threat detection more heavily
        combined['risk_score'] = threat_score * 0.7 + behavioral_risk * 0.3
        
        # Calculate confidence
        threat_confidence = threat_analysis.get('confidence', 0.0)
        profile_confidence = behavioral_analysis.get('profile', {}).get('profile_confidence', 0.0)
        
        if profile_confidence > 0:
            combined['confidence'] = (threat_confidence + profile_confidence) / 2
        else:
            combined['confidence'] = threat_confidence
        
        return combined
    
    def _should_generate_alert(self, analysis: Dict) -> bool:
        """Determine if an alert should be generated"""
        risk_score = analysis.get('risk_score', 0.0)
        confidence = analysis.get('confidence', 0.0)
        
        # Generate alert if risk is high enough and confidence is reasonable
        if risk_score >= 0.6 and confidence >= 0.5:
            return True
        
        # Also alert on critical threats regardless of confidence
        threat_level = analysis.get('threat_analysis', {}).get('threat_level')
        if threat_level == ThreatLevel.CRITICAL or threat_level == 4:
            return True
        
        return False
    
    def _create_alert(self, analysis: Dict) -> ThreatAlert:
        """Create a threat alert from analysis"""
        import uuid
        
        threat_analysis = analysis.get('threat_analysis', {})
        message = analysis.get('message', {})
        
        # Determine priority
        risk_score = analysis.get('risk_score', 0.0)
        if risk_score >= 0.9:
            priority = AlertPriority.EMERGENCY
        elif risk_score >= 0.75:
            priority = AlertPriority.CRITICAL
        elif risk_score >= 0.6:
            priority = AlertPriority.HIGH
        elif risk_score >= 0.4:
            priority = AlertPriority.MEDIUM
        else:
            priority = AlertPriority.LOW
        
        # Create alert message
        alert_message = self._format_alert_message(analysis)
        
        # Determine if action is required
        action_required = priority.value >= AlertPriority.HIGH.value
        
        # Determine auto-response
        auto_response = None
        if priority == AlertPriority.EMERGENCY:
            auto_response = "notify_emergency_response"
        elif priority == AlertPriority.CRITICAL:
            auto_response = "notify_law_enforcement"
        
        return ThreatAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            source=message.get('source_type', 'unknown'),
            threat_level=threat_analysis.get('threat_level', ThreatLevel.NONE),
            priority=priority,
            confidence=analysis.get('confidence', 0.0),
            message=alert_message,
            metadata=message.get('metadata', {}),
            fingerprint=message.get('fingerprint', {}).get('device_id'),
            profile_id=analysis.get('behavioral_analysis', {}).get('profile', {}).get('profile_id'),
            action_required=action_required,
            auto_response=auto_response
        )
    
    def _format_alert_message(self, analysis: Dict) -> str:
        """Format alert message for human readability"""
        threat = analysis.get('threat_analysis', {})
        message = analysis.get('message', {})
        
        alert_parts = []
        alert_parts.append(f"Threat Level: {threat.get('threat_level', 'UNKNOWN')}")
        alert_parts.append(f"Source: {message.get('source_type', 'unknown')}")
        
        if threat.get('detected_keywords'):
            keywords = ', '.join(threat['detected_keywords'][:5])
            alert_parts.append(f"Keywords: {keywords}")
        
        if threat.get('matched_patterns'):
            patterns = ', '.join(threat['matched_patterns'][:3])
            alert_parts.append(f"Patterns: {patterns}")
        
        explanation = threat.get('explanation', '')
        if explanation:
            alert_parts.append(f"Analysis: {explanation}")
        
        return " | ".join(alert_parts)
    
    async def _store_analysis(self, analysis: Dict):
        """Store analysis results"""
        if self.redis_client:
            try:
                # Store in Redis with expiration
                key = f"analysis:{datetime.now().strftime('%Y%m%d')}:{analysis.get('message', {}).get('id', 'unknown')}"
                self.redis_client.setex(
                    key,
                    timedelta(days=30),
                    json.dumps(analysis, default=str)
                )
            except Exception as e:
                self.logger.error(f"Failed to store analysis: {e}")
    
    def _store_alert_redis(self, alert: ThreatAlert):
        """Store alert in Redis"""
        try:
            key = f"alert:{alert.alert_id}"
            value = json.dumps(asdict(alert), default=str)
            self.redis_client.setex(key, timedelta(days=90), value)
            
            # Add to daily alert list
            list_key = f"alerts:{datetime.now().strftime('%Y%m%d')}"
            self.redis_client.lpush(list_key, alert.alert_id)
            self.redis_client.expire(list_key, timedelta(days=90))
        except Exception as e:
            self.logger.error(f"Failed to store alert in Redis: {e}")
    
    async def _send_notifications(self, alert: ThreatAlert):
        """Send alert notifications"""
        # Send to websocket clients
        await self._broadcast_alert(alert)
        
        # Send email notifications for high priority alerts
        if alert.priority.value >= AlertPriority.HIGH.value:
            await self._send_email_notification(alert)
        
        # Send SMS for emergency alerts
        if alert.priority == AlertPriority.EMERGENCY:
            await self._send_sms_notification(alert)
    
    async def _broadcast_update(self, analysis: Dict):
        """Broadcast analysis update to websocket clients"""
        if self.websocket_clients:
            message = json.dumps({
                'type': 'analysis_update',
                'data': analysis
            }, default=str)
            
            # Send to all connected clients
            disconnected = set()
            for client in self.websocket_clients:
                try:
                    await client.send(message)
                except:
                    disconnected.add(client)
            
            # Remove disconnected clients
            self.websocket_clients -= disconnected
    
    async def _broadcast_alert(self, alert: ThreatAlert):
        """Broadcast alert to websocket clients"""
        if self.websocket_clients:
            message = json.dumps({
                'type': 'threat_alert',
                'data': asdict(alert)
            }, default=str)
            
            # Send to all connected clients
            disconnected = set()
            for client in self.websocket_clients:
                try:
                    await client.send(message)
                except:
                    disconnected.add(client)
            
            # Remove disconnected clients
            self.websocket_clients -= disconnected
    
    async def websocket_server(self):
        """WebSocket server for real-time updates"""
        try:
            async def handle_client(websocket, path):
                """Handle WebSocket client connection"""
                self.websocket_clients.add(websocket)
                self.logger.info(f"WebSocket client connected: {websocket.remote_address}")
                
                try:
                    # Send initial status
                    await websocket.send(json.dumps({
                        'type': 'connection',
                        'status': 'connected',
                        'stats': self.stats
                    }))
                    
                    # Keep connection alive
                    async for message in websocket:
                        # Handle client messages if needed
                        pass
                        
                except websockets.exceptions.ConnectionClosed:
                    pass
                finally:
                    self.websocket_clients.remove(websocket)
                    self.logger.info(f"WebSocket client disconnected: {websocket.remote_address}")
            
            # Start WebSocket server
            server = await websockets.serve(
                handle_client,
                self.config.get('websocket', {}).get('host', '0.0.0.0'),
                self.config.get('websocket', {}).get('port', 8765)
            )
            
            self.logger.info("WebSocket server started on port 8765")
            await asyncio.Future()  # Run forever
            
        except Exception as e:
            self.logger.error(f"WebSocket server error: {e}")
    
    async def statistics_reporter(self):
        """Periodically report statistics"""
        while True:
            await asyncio.sleep(60)  # Report every minute
            
            self.logger.info(f"Statistics: {self.stats}")
            
            # Broadcast stats to websocket clients
            if self.websocket_clients:
                message = json.dumps({
                    'type': 'statistics',
                    'data': self.stats
                })
                
                disconnected = set()
                for client in self.websocket_clients:
                    try:
                        await client.send(message)
                    except:
                        disconnected.add(client)
                
                self.websocket_clients -= disconnected
    
    def _get_source_identifier(self, message: Dict) -> str:
        """Get unique identifier for message source"""
        # Try different identifiers in order of preference
        identifiers = [
            message.get('metadata', {}).get('sender_ip'),
            message.get('metadata', {}).get('from'),
            message.get('metadata', {}).get('user_id'),
            message.get('fingerprint', {}).get('device_id'),
            message.get('source_id')
        ]
        
        for identifier in identifiers:
            if identifier:
                return str(identifier)
        
        return 'unknown'
    
    async def _get_historical_messages(self, source_id: str, limit: int = 10) -> List[Dict]:
        """Get historical messages from the same source"""
        if not self.redis_client:
            return []
        
        try:
            # Get recent messages from Redis
            pattern = f"analysis:*:{source_id}*"
            keys = self.redis_client.keys(pattern)[:limit]
            
            messages = []
            for key in keys:
                data = self.redis_client.get(key)
                if data:
                    messages.append(json.loads(data))
            
            return messages
        except Exception as e:
            self.logger.error(f"Failed to get historical messages: {e}")
            return []
    
    async def _find_similar_profiles(self, profile: Dict, threshold: float = 0.8) -> List[str]:
        """Find similar behavioral profiles"""
        if not self.redis_client:
            return []
        
        try:
            # Get all profiles from Redis
            pattern = "profile:*"
            keys = self.redis_client.keys(pattern)[:100]  # Limit for performance
            
            similar = []
            for key in keys:
                stored_profile = self.redis_client.get(key)
                if stored_profile:
                    stored_profile = json.loads(stored_profile)
                    similarity = self.behavioral_profiler.compare_profiles(profile, stored_profile)
                    if similarity >= threshold:
                        similar.append(stored_profile.get('profile_id'))
            
            return similar
        except Exception as e:
            self.logger.error(f"Failed to find similar profiles: {e}")
            return []
    
    async def _execute_auto_response(self, alert: ThreatAlert):
        """Execute automatic response for alert"""
        response = alert.auto_response
        
        if response == "notify_emergency_response":
            self.logger.critical(f"EMERGENCY RESPONSE TRIGGERED: {alert.message}")
            # In production, would interface with emergency systems
        elif response == "notify_law_enforcement":
            self.logger.critical(f"LAW ENFORCEMENT NOTIFICATION: {alert.message}")
            # In production, would interface with law enforcement systems
        else:
            self.logger.info(f"Auto-response: {response}")
    
    async def _send_email_notification(self, alert: ThreatAlert):
        """Send email notification for alert"""
        # In production, would send actual email
        self.logger.info(f"Email notification would be sent for alert: {alert.alert_id}")
    
    async def _send_sms_notification(self, alert: ThreatAlert):
        """Send SMS notification for emergency alert"""
        # In production, would send actual SMS
        self.logger.critical(f"SMS notification would be sent for emergency: {alert.alert_id}")
    
    async def shutdown(self):
        """Shutdown the processor gracefully"""
        self.logger.info("Shutting down Real-time Processor...")
        
        # Stop all monitors
        for monitor in self.active_monitors.values():
            if hasattr(monitor, 'stop'):
                await monitor.stop()
        
        # Close Redis connection
        if self.redis_client:
            self.redis_client.close()
        
        # Close websocket connections
        for client in self.websocket_clients:
            await client.close()
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        self.logger.info("Real-time Processor shutdown complete")