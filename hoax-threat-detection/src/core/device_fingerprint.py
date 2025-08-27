"""
Device Fingerprinting Module
Implements device tracking and fingerprinting techniques
"""

import hashlib
import json
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict
import re

class DeviceFingerprinter:
    """
    Device fingerprinting system to track devices across sessions
    even when users attempt to remain anonymous
    """
    
    def __init__(self):
        """Initialize the device fingerprinter"""
        # In-memory storage for demo (should use database in production)
        self.fingerprint_database = {}
        self.device_profiles = defaultdict(list)
        self.suspicious_patterns = self._load_suspicious_patterns()
    
    def _load_suspicious_patterns(self) -> Dict:
        """Load patterns that indicate suspicious device behavior"""
        return {
            'user_agent_spoofing': [
                r'curl|wget|python-requests|scrapy',
                r'bot|crawler|spider',
                r'headless|phantom'
            ],
            'privacy_tools': [
                r'tor browser|torbrowser',
                r'vpn|proxy',
                r'privacy badger|ublock'
            ],
            'inconsistent_attributes': {
                'timezone_mismatch': True,
                'language_mismatch': True,
                'resolution_mismatch': True
            }
        }
    
    def generate_fingerprint(self, device_data: Dict) -> Dict:
        """
        Generate a unique device fingerprint from various attributes
        
        Args:
            device_data: Dictionary containing device attributes
            
        Returns:
            Dictionary with fingerprint and analysis results
        """
        # Extract core attributes
        attributes = self._extract_core_attributes(device_data)
        
        # Generate multiple fingerprint types
        fingerprints = {
            'canvas_fingerprint': self._generate_canvas_fingerprint(device_data),
            'webgl_fingerprint': self._generate_webgl_fingerprint(device_data),
            'audio_fingerprint': self._generate_audio_fingerprint(device_data),
            'browser_fingerprint': self._generate_browser_fingerprint(attributes),
            'network_fingerprint': self._generate_network_fingerprint(device_data),
            'behavioral_fingerprint': self._generate_behavioral_fingerprint(device_data)
        }
        
        # Create composite fingerprint
        composite_fp = self._create_composite_fingerprint(fingerprints)
        
        # Check for known devices
        known_device = self._check_known_device(composite_fp)
        
        # Detect anomalies
        anomalies = self._detect_anomalies(device_data, attributes)
        
        # Calculate confidence score
        confidence = self._calculate_confidence(fingerprints, anomalies)
        
        # Store fingerprint
        self._store_fingerprint(composite_fp, device_data)
        
        return {
            'device_id': composite_fp,
            'fingerprints': fingerprints,
            'attributes': attributes,
            'known_device': known_device,
            'anomalies': anomalies,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'risk_score': self._calculate_risk_score(anomalies, known_device)
        }
    
    def _extract_core_attributes(self, device_data: Dict) -> Dict:
        """Extract core device attributes for fingerprinting"""
        attributes = {}
        
        # Browser attributes
        attributes['user_agent'] = device_data.get('user_agent', '')
        attributes['platform'] = device_data.get('platform', '')
        attributes['language'] = device_data.get('language', '')
        attributes['languages'] = device_data.get('languages', [])
        attributes['timezone'] = device_data.get('timezone', '')
        attributes['timezone_offset'] = device_data.get('timezone_offset', 0)
        
        # Screen attributes
        attributes['screen_resolution'] = device_data.get('screen_resolution', '')
        attributes['screen_depth'] = device_data.get('screen_depth', '')
        attributes['color_depth'] = device_data.get('color_depth', '')
        attributes['pixel_ratio'] = device_data.get('pixel_ratio', 1)
        
        # Hardware attributes
        attributes['hardware_concurrency'] = device_data.get('hardware_concurrency', 0)
        attributes['device_memory'] = device_data.get('device_memory', 0)
        attributes['max_touch_points'] = device_data.get('max_touch_points', 0)
        
        # Browser features
        attributes['cookies_enabled'] = device_data.get('cookies_enabled', False)
        attributes['local_storage'] = device_data.get('local_storage', False)
        attributes['session_storage'] = device_data.get('session_storage', False)
        attributes['indexed_db'] = device_data.get('indexed_db', False)
        attributes['webgl_vendor'] = device_data.get('webgl_vendor', '')
        attributes['webgl_renderer'] = device_data.get('webgl_renderer', '')
        
        # Plugins and fonts
        attributes['plugins'] = device_data.get('plugins', [])
        attributes['fonts'] = device_data.get('fonts', [])
        attributes['mime_types'] = device_data.get('mime_types', [])
        
        # Network attributes
        attributes['do_not_track'] = device_data.get('do_not_track', '')
        attributes['ad_blocker'] = device_data.get('ad_blocker', False)
        
        return attributes
    
    def _generate_canvas_fingerprint(self, device_data: Dict) -> str:
        """Generate fingerprint from canvas rendering"""
        canvas_data = device_data.get('canvas_data', '')
        if not canvas_data:
            # Simulate canvas fingerprint generation
            canvas_text = f"{device_data.get('user_agent', '')}_{device_data.get('screen_resolution', '')}"
            return hashlib.md5(canvas_text.encode()).hexdigest()[:16]
        return hashlib.md5(canvas_data.encode()).hexdigest()[:16]
    
    def _generate_webgl_fingerprint(self, device_data: Dict) -> str:
        """Generate fingerprint from WebGL attributes"""
        webgl_data = {
            'vendor': device_data.get('webgl_vendor', ''),
            'renderer': device_data.get('webgl_renderer', ''),
            'version': device_data.get('webgl_version', ''),
            'shading_language': device_data.get('webgl_shading_language', ''),
            'extensions': device_data.get('webgl_extensions', [])
        }
        webgl_str = json.dumps(webgl_data, sort_keys=True)
        return hashlib.md5(webgl_str.encode()).hexdigest()[:16]
    
    def _generate_audio_fingerprint(self, device_data: Dict) -> str:
        """Generate fingerprint from audio context"""
        audio_data = device_data.get('audio_context', {})
        if not audio_data:
            # Simulate audio fingerprint
            audio_str = f"audio_{device_data.get('platform', 'unknown')}"
            return hashlib.md5(audio_str.encode()).hexdigest()[:16]
        audio_str = json.dumps(audio_data, sort_keys=True)
        return hashlib.md5(audio_str.encode()).hexdigest()[:16]
    
    def _generate_browser_fingerprint(self, attributes: Dict) -> str:
        """Generate fingerprint from browser attributes"""
        browser_features = {
            'user_agent': attributes.get('user_agent', ''),
            'language': attributes.get('language', ''),
            'platform': attributes.get('platform', ''),
            'cookies': attributes.get('cookies_enabled', False),
            'do_not_track': attributes.get('do_not_track', ''),
            'plugins': len(attributes.get('plugins', [])),
            'mime_types': len(attributes.get('mime_types', []))
        }
        browser_str = json.dumps(browser_features, sort_keys=True)
        return hashlib.sha256(browser_str.encode()).hexdigest()[:16]
    
    def _generate_network_fingerprint(self, device_data: Dict) -> str:
        """Generate fingerprint from network attributes"""
        network_data = {
            'ip': device_data.get('ip_address', ''),
            'accept_language': device_data.get('accept_language', ''),
            'accept_encoding': device_data.get('accept_encoding', ''),
            'connection': device_data.get('connection', ''),
            'proxy_headers': device_data.get('proxy_headers', [])
        }
        network_str = json.dumps(network_data, sort_keys=True)
        return hashlib.md5(network_str.encode()).hexdigest()[:16]
    
    def _generate_behavioral_fingerprint(self, device_data: Dict) -> str:
        """Generate fingerprint from behavioral patterns"""
        behavioral_data = device_data.get('behavioral', {})
        if not behavioral_data:
            # Default behavioral fingerprint
            return "0" * 16
        
        # Extract behavioral features
        features = {
            'mouse_movements': behavioral_data.get('mouse_movements', []),
            'keystroke_dynamics': behavioral_data.get('keystroke_dynamics', {}),
            'scroll_behavior': behavioral_data.get('scroll_behavior', {}),
            'click_patterns': behavioral_data.get('click_patterns', []),
            'touch_patterns': behavioral_data.get('touch_patterns', [])
        }
        
        # Create fingerprint from behavioral patterns
        behavioral_str = json.dumps(features, sort_keys=True)
        return hashlib.sha256(behavioral_str.encode()).hexdigest()[:16]
    
    def _create_composite_fingerprint(self, fingerprints: Dict) -> str:
        """Create a composite fingerprint from multiple fingerprint types"""
        # Weight different fingerprint types
        weights = {
            'canvas_fingerprint': 0.25,
            'webgl_fingerprint': 0.20,
            'browser_fingerprint': 0.25,
            'network_fingerprint': 0.15,
            'audio_fingerprint': 0.10,
            'behavioral_fingerprint': 0.05
        }
        
        # Combine fingerprints with weights
        composite_parts = []
        for fp_type, fp_value in fingerprints.items():
            weight = weights.get(fp_type, 0.1)
            weighted_value = hashlib.md5(f"{fp_value}_{weight}".encode()).hexdigest()
            composite_parts.append(weighted_value[:int(16 * weight)])
        
        composite = ''.join(composite_parts)
        return hashlib.sha256(composite.encode()).hexdigest()
    
    def _check_known_device(self, fingerprint: str) -> Optional[Dict]:
        """Check if fingerprint matches a known device"""
        if fingerprint in self.fingerprint_database:
            device_info = self.fingerprint_database[fingerprint]
            return {
                'device_id': fingerprint,
                'first_seen': device_info['first_seen'],
                'last_seen': device_info['last_seen'],
                'total_events': device_info['total_events'],
                'threat_history': device_info.get('threat_history', [])
            }
        return None
    
    def _detect_anomalies(self, device_data: Dict, attributes: Dict) -> List[Dict]:
        """Detect anomalies in device fingerprint"""
        anomalies = []
        
        # Check for user agent spoofing
        ua = attributes.get('user_agent', '').lower()
        for pattern in self.suspicious_patterns['user_agent_spoofing']:
            if re.search(pattern, ua):
                anomalies.append({
                    'type': 'user_agent_spoofing',
                    'description': f'Suspicious user agent pattern: {pattern}',
                    'severity': 'medium'
                })
        
        # Check for privacy tools
        for pattern in self.suspicious_patterns['privacy_tools']:
            if re.search(pattern, ua):
                anomalies.append({
                    'type': 'privacy_tool',
                    'description': f'Privacy tool detected: {pattern}',
                    'severity': 'low'
                })
        
        # Check for inconsistent attributes
        if self._check_timezone_mismatch(device_data):
            anomalies.append({
                'type': 'timezone_mismatch',
                'description': 'Timezone doesn\'t match IP location',
                'severity': 'medium'
            })
        
        # Check for headless browser
        if self._is_headless_browser(attributes):
            anomalies.append({
                'type': 'headless_browser',
                'description': 'Headless browser detected',
                'severity': 'high'
            })
        
        # Check for missing expected features
        if not attributes.get('plugins') and 'chrome' in ua:
            anomalies.append({
                'type': 'missing_plugins',
                'description': 'Chrome browser with no plugins (unusual)',
                'severity': 'low'
            })
        
        # Check for WebGL anomalies
        if self._check_webgl_anomalies(attributes):
            anomalies.append({
                'type': 'webgl_anomaly',
                'description': 'WebGL renderer/vendor mismatch',
                'severity': 'medium'
            })
        
        # Check for canvas poisoning
        if self._detect_canvas_poisoning(device_data):
            anomalies.append({
                'type': 'canvas_poisoning',
                'description': 'Canvas fingerprint randomization detected',
                'severity': 'high'
            })
        
        return anomalies
    
    def _check_timezone_mismatch(self, device_data: Dict) -> bool:
        """Check if timezone matches IP geolocation"""
        ip_location = device_data.get('ip_location', {})
        browser_timezone = device_data.get('timezone', '')
        
        if ip_location and browser_timezone:
            expected_timezone = ip_location.get('timezone', '')
            if expected_timezone and expected_timezone != browser_timezone:
                return True
        return False
    
    def _is_headless_browser(self, attributes: Dict) -> bool:
        """Detect headless browser characteristics"""
        indicators = [
            not attributes.get('plugins'),
            attributes.get('webgl_vendor') == 'Brian Paul',
            attributes.get('webgl_renderer') == 'Mesa OffScreen',
            'HeadlessChrome' in attributes.get('user_agent', ''),
            attributes.get('hardware_concurrency', 0) == 0
        ]
        return sum(indicators) >= 2
    
    def _check_webgl_anomalies(self, attributes: Dict) -> bool:
        """Check for WebGL anomalies"""
        vendor = attributes.get('webgl_vendor', '').lower()
        renderer = attributes.get('webgl_renderer', '').lower()
        
        # Check for mismatched vendor/renderer
        known_pairs = [
            ('intel', 'intel'),
            ('nvidia', 'nvidia'),
            ('amd', 'amd'),
            ('apple', 'apple'),
            ('google', 'angle')
        ]
        
        if vendor and renderer:
            matched = any(v in vendor and r in renderer for v, r in known_pairs)
            return not matched
        
        return False
    
    def _detect_canvas_poisoning(self, device_data: Dict) -> bool:
        """Detect canvas fingerprint poisoning/randomization"""
        canvas_history = device_data.get('canvas_history', [])
        if len(canvas_history) > 1:
            # Check if canvas fingerprint changes frequently
            unique_fingerprints = set(canvas_history)
            if len(unique_fingerprints) > len(canvas_history) * 0.5:
                return True
        return False
    
    def _calculate_confidence(self, fingerprints: Dict, anomalies: List) -> float:
        """Calculate confidence score for device fingerprint"""
        confidence = 1.0
        
        # Reduce confidence for each anomaly
        for anomaly in anomalies:
            if anomaly['severity'] == 'high':
                confidence -= 0.3
            elif anomaly['severity'] == 'medium':
                confidence -= 0.15
            else:
                confidence -= 0.05
        
        # Reduce confidence for missing fingerprint components
        for fp_type, fp_value in fingerprints.items():
            if not fp_value or fp_value == "0" * 16:
                confidence -= 0.1
        
        return max(0.0, min(1.0, confidence))
    
    def _calculate_risk_score(self, anomalies: List, known_device: Optional[Dict]) -> float:
        """Calculate risk score for the device"""
        risk = 0.0
        
        # Add risk for anomalies
        for anomaly in anomalies:
            if anomaly['severity'] == 'high':
                risk += 0.4
            elif anomaly['severity'] == 'medium':
                risk += 0.2
            else:
                risk += 0.1
        
        # Check device history if known
        if known_device:
            threat_history = known_device.get('threat_history', [])
            if threat_history:
                # Increase risk based on threat history
                recent_threats = [t for t in threat_history 
                                if datetime.fromisoformat(t['timestamp']) > 
                                datetime.now() - timedelta(days=30)]
                risk += len(recent_threats) * 0.2
        else:
            # New device - slight risk increase
            risk += 0.1
        
        return min(1.0, risk)
    
    def _store_fingerprint(self, fingerprint: str, device_data: Dict):
        """Store device fingerprint in database"""
        if fingerprint not in self.fingerprint_database:
            self.fingerprint_database[fingerprint] = {
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'total_events': 1,
                'device_data': device_data,
                'threat_history': []
            }
        else:
            self.fingerprint_database[fingerprint]['last_seen'] = datetime.now().isoformat()
            self.fingerprint_database[fingerprint]['total_events'] += 1
    
    def link_devices(self, fingerprints: List[str]) -> List[Set[str]]:
        """
        Link multiple device fingerprints that likely belong to the same user
        
        Args:
            fingerprints: List of device fingerprints to analyze
            
        Returns:
            List of sets containing linked fingerprints
        """
        linked_groups = []
        processed = set()
        
        for fp1 in fingerprints:
            if fp1 in processed:
                continue
            
            group = {fp1}
            processed.add(fp1)
            
            for fp2 in fingerprints:
                if fp2 in processed:
                    continue
                
                if self._calculate_similarity(fp1, fp2) > 0.7:
                    group.add(fp2)
                    processed.add(fp2)
            
            if len(group) > 1:
                linked_groups.append(group)
        
        return linked_groups
    
    def _calculate_similarity(self, fp1: str, fp2: str) -> float:
        """Calculate similarity between two fingerprints"""
        if fp1 not in self.fingerprint_database or fp2 not in self.fingerprint_database:
            return 0.0
        
        data1 = self.fingerprint_database[fp1]['device_data']
        data2 = self.fingerprint_database[fp2]['device_data']
        
        # Compare various attributes
        similarity_scores = []
        
        # User agent similarity
        if data1.get('user_agent') == data2.get('user_agent'):
            similarity_scores.append(1.0)
        else:
            similarity_scores.append(0.0)
        
        # Screen resolution
        if data1.get('screen_resolution') == data2.get('screen_resolution'):
            similarity_scores.append(1.0)
        else:
            similarity_scores.append(0.0)
        
        # Timezone
        if data1.get('timezone') == data2.get('timezone'):
            similarity_scores.append(0.8)
        else:
            similarity_scores.append(0.0)
        
        # Language
        if data1.get('language') == data2.get('language'):
            similarity_scores.append(0.7)
        else:
            similarity_scores.append(0.0)
        
        # Calculate average similarity
        return sum(similarity_scores) / len(similarity_scores) if similarity_scores else 0.0
    
    def track_device_threat(self, fingerprint: str, threat_info: Dict):
        """Track threat activity for a device"""
        if fingerprint in self.fingerprint_database:
            threat_record = {
                'timestamp': datetime.now().isoformat(),
                'threat_level': threat_info.get('threat_level'),
                'threat_type': threat_info.get('threat_type'),
                'message': threat_info.get('message')
            }
            self.fingerprint_database[fingerprint]['threat_history'].append(threat_record)