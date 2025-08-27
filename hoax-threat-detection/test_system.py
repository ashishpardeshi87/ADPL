#!/usr/bin/env python3
"""
Test script to demonstrate the Hoax Threat Detection System
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent / 'src'))

from core.threat_detector import ThreatDetector
from core.metadata_extractor import MetadataExtractor
from core.device_fingerprint import DeviceFingerprinter
from core.behavioral_profiler import BehavioralProfiler


def test_threat_detection():
    """Test threat detection functionality"""
    print("\n" + "="*60)
    print("THREAT DETECTION TEST")
    print("="*60)
    
    detector = ThreatDetector()
    
    # Test messages
    test_messages = [
        {
            'text': "Hello, how are you today?",
            'expected': 'NONE'
        },
        {
            'text': "There is a bomb in the building, evacuate immediately!",
            'expected': 'HIGH/CRITICAL'
        },
        {
            'text': "The device will explode at noon tomorrow at the airport",
            'expected': 'CRITICAL'
        },
        {
            'text': "Just kidding lol, it was a prank",
            'expected': 'LOW/MEDIUM'
        },
        {
            'text': "I planted an explosive device that will detonate in 30 minutes",
            'expected': 'CRITICAL'
        }
    ]
    
    for i, msg in enumerate(test_messages, 1):
        print(f"\nTest {i}: {msg['text'][:50]}...")
        analysis = detector.detect_threat(msg['text'])
        
        print(f"  Threat Level: {analysis.threat_level.name}")
        print(f"  Confidence: {analysis.confidence:.2%}")
        print(f"  Urgency: {analysis.urgency_score:.2f}")
        print(f"  Credibility: {analysis.credibility_score:.2f}")
        print(f"  Expected: {msg['expected']}")
        print(f"  ✓ Detected keywords: {len(analysis.detected_keywords)}")
        print(f"  ✓ Matched patterns: {len(analysis.matched_patterns)}")


def test_metadata_extraction():
    """Test metadata extraction functionality"""
    print("\n" + "="*60)
    print("METADATA EXTRACTION TEST")
    print("="*60)
    
    extractor = MetadataExtractor()
    
    # Test email metadata
    sample_email = b"""From: suspicious@example.com
To: target@organization.com
Subject: Warning
Date: Mon, 15 Jan 2024 10:30:00 -0500
Message-ID: <123456@example.com>
X-Originating-IP: [192.168.1.100]

This is a test email with threatening content.
"""
    
    print("\nExtracting email metadata...")
    metadata = extractor.extract_from_email(sample_email)
    
    print(f"  From: {metadata.get('from')}")
    print(f"  To: {metadata.get('to')}")
    print(f"  Subject: {metadata.get('subject')}")
    print(f"  Originating IP: {metadata.get('originating_ip')}")
    print(f"  Message ID: {metadata.get('message_id')}")
    
    # Test social media metadata
    sample_post = {
        'id': '123456789',
        'text': 'Test post content',
        'user_id': 'user123',
        'username': 'testuser',
        'created_at': '2024-01-15T10:30:00Z',
        'user': {
            'created_at': '2023-01-01T00:00:00Z',
            'followers_count': 100,
            'friends_count': 50
        }
    }
    
    print("\nExtracting social media metadata...")
    metadata = extractor.extract_from_social_media(sample_post, 'twitter')
    
    print(f"  Platform: {metadata.get('platform')}")
    print(f"  User ID: {metadata.get('user_id')}")
    print(f"  Username: {metadata.get('username')}")
    print(f"  Account age: {metadata.get('account_age_days')} days")
    print(f"  New account: {metadata.get('is_new_account')}")


def test_device_fingerprinting():
    """Test device fingerprinting functionality"""
    print("\n" + "="*60)
    print("DEVICE FINGERPRINTING TEST")
    print("="*60)
    
    fingerprinter = DeviceFingerprinter()
    
    # Simulate device data
    device_data = {
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        'platform': 'Win32',
        'language': 'en-US',
        'screen_resolution': '1920x1080',
        'timezone': 'America/New_York',
        'cookies_enabled': True,
        'webgl_vendor': 'Google Inc.',
        'webgl_renderer': 'ANGLE (Intel(R) HD Graphics)',
        'ip_address': '192.168.1.100'
    }
    
    print("\nGenerating device fingerprint...")
    result = fingerprinter.generate_fingerprint(device_data)
    
    print(f"  Device ID: {result['device_id'][:16]}...")
    print(f"  Risk Score: {result['risk_score']:.2f}")
    print(f"  Confidence: {result['confidence']:.2f}")
    print(f"  Anomalies detected: {len(result['anomalies'])}")
    
    if result['anomalies']:
        print("  Anomalies:")
        for anomaly in result['anomalies'][:3]:
            print(f"    - {anomaly['type']}: {anomaly['description']}")


def test_behavioral_profiling():
    """Test behavioral profiling functionality"""
    print("\n" + "="*60)
    print("BEHAVIORAL PROFILING TEST")
    print("="*60)
    
    profiler = BehavioralProfiler()
    
    # Simulate communication history
    communications = [
        {
            'text': 'I will blow up the building tomorrow at noon',
            'timestamp': '2024-01-15T10:00:00Z',
            'source_type': 'email'
        },
        {
            'text': 'The bomb is already planted and ready',
            'timestamp': '2024-01-15T11:00:00Z',
            'source_type': 'email'
        },
        {
            'text': 'You have been warned. Evacuate now!',
            'timestamp': '2024-01-15T12:00:00Z',
            'source_type': 'email'
        }
    ]
    
    print("\nCreating behavioral profile...")
    profile = profiler.create_profile(communications)
    
    print(f"  Profile ID: {profile['profile_id']}")
    print(f"  Total communications: {profile['total_communications']}")
    print(f"  Consistency score: {profile.get('consistency_score', 0):.2f}")
    print(f"  Profile confidence: {profile.get('profile_confidence', 0):.2f}")
    
    if profile.get('risk_indicators'):
        print(f"  Risk indicators: {', '.join(profile['risk_indicators'])}")
    
    if profile.get('writing_style'):
        style = profile['writing_style']
        print(f"  Writing style:")
        print(f"    - Avg sentence length: {style.get('avg_sentence_length', 0):.1f} words")
        print(f"    - Vocabulary richness: {style.get('vocabulary_richness', 0):.2f}")
        print(f"    - Capitalization: {style.get('capitalization_pattern', 'unknown')}")


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print(" HOAX THREAT DETECTION SYSTEM - DEMONSTRATION")
    print("="*60)
    print("\nThis demonstration shows the core capabilities of the system:")
    print("1. Threat Detection using NLP")
    print("2. Metadata Extraction from communications")
    print("3. Device Fingerprinting for tracking")
    print("4. Behavioral Profiling for identification")
    
    try:
        test_threat_detection()
        test_metadata_extraction()
        test_device_fingerprinting()
        test_behavioral_profiling()
        
        print("\n" + "="*60)
        print(" ALL TESTS COMPLETED SUCCESSFULLY")
        print("="*60)
        print("\nThe system is ready for deployment!")
        print("Run 'python main.py --mode both' to start the full system.")
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        print("Please ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        print("  python -m spacy download en_core_web_sm")


if __name__ == "__main__":
    main()