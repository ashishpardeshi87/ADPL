"""
Threat Detection Module
Implements NLP-based threat detection and classification
"""

import json
import re
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import numpy as np
from dataclasses import dataclass
from enum import Enum

import nltk
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
from textblob import TextBlob
import spacy

class ThreatLevel(Enum):
    """Threat severity levels"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ThreatAnalysis:
    """Threat analysis result"""
    threat_level: ThreatLevel
    confidence: float
    detected_keywords: List[str]
    matched_patterns: List[str]
    sentiment_score: float
    urgency_score: float
    credibility_score: float
    timestamp: datetime
    explanation: str
    metadata: Dict

class ThreatDetector:
    """Main threat detection engine using NLP and pattern matching"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize the threat detector with configuration"""
        self.config = self._load_config(config_path)
        self.keywords = self._load_keywords()
        self.patterns = self._load_patterns()
        
        # Initialize NLP models
        self._initialize_nlp_models()
        
        # Compile regex patterns
        self.compiled_patterns = self._compile_patterns()
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from file"""
        import yaml
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except:
            # Return default config if file not found
            return {
                'threat_detection': {
                    'confidence_threshold': 0.75,
                    'risk_levels': {
                        'low': 0.3,
                        'medium': 0.6,
                        'high': 0.85,
                        'critical': 0.95
                    }
                }
            }
    
    def _load_keywords(self) -> Dict:
        """Load threat keywords from database"""
        try:
            with open('data/threat_keywords.json', 'r') as f:
                return json.load(f)
        except:
            return {
                'high_risk_keywords': [],
                'threat_indicators': [],
                'location_keywords': [],
                'time_indicators': [],
                'hoax_indicators': []
            }
    
    def _load_patterns(self) -> Dict:
        """Load threat patterns from database"""
        try:
            with open('data/threat_patterns.json', 'r') as f:
                return json.load(f)
        except:
            return {'linguistic_patterns': []}
    
    def _initialize_nlp_models(self):
        """Initialize NLP models for threat detection"""
        try:
            # Download required NLTK data
            nltk.download('punkt', quiet=True)
            nltk.download('stopwords', quiet=True)
            nltk.download('vader_lexicon', quiet=True)
            
            # Initialize spaCy model
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except:
                # Fallback if model not installed
                import subprocess
                subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"], 
                             capture_output=True)
                self.nlp = spacy.load("en_core_web_sm")
            
            # Initialize transformer model for threat classification
            model_name = "distilbert-base-uncased"
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            
            # Use sentiment analysis as proxy for threat detection
            self.threat_classifier = pipeline(
                "sentiment-analysis",
                model=model_name,
                tokenizer=self.tokenizer,
                device=-1  # Use CPU
            )
            
        except Exception as e:
            print(f"Warning: Could not initialize all NLP models: {e}")
            self.nlp = None
            self.threat_classifier = None
    
    def _compile_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for efficient matching"""
        compiled = []
        for pattern_info in self.patterns.get('linguistic_patterns', []):
            try:
                compiled.append({
                    'regex': re.compile(pattern_info['pattern'], re.IGNORECASE),
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description']
                })
            except:
                continue
        return compiled
    
    def detect_threat(self, text: str, metadata: Optional[Dict] = None) -> ThreatAnalysis:
        """
        Analyze text for potential bomb threats
        
        Args:
            text: The message text to analyze
            metadata: Additional metadata (sender, timestamp, etc.)
            
        Returns:
            ThreatAnalysis object with detection results
        """
        if not text:
            return self._create_empty_analysis()
        
        # Normalize text
        text_lower = text.lower()
        
        # Detect keywords
        detected_keywords = self._detect_keywords(text_lower)
        
        # Match patterns
        matched_patterns = self._match_patterns(text_lower)
        
        # Analyze sentiment and emotion
        sentiment_score = self._analyze_sentiment(text)
        
        # Calculate urgency
        urgency_score = self._calculate_urgency(text_lower)
        
        # Assess credibility
        credibility_score = self._assess_credibility(text, detected_keywords, matched_patterns)
        
        # Calculate overall threat level
        threat_level, confidence = self._calculate_threat_level(
            detected_keywords,
            matched_patterns,
            sentiment_score,
            urgency_score,
            credibility_score
        )
        
        # Generate explanation
        explanation = self._generate_explanation(
            threat_level,
            detected_keywords,
            matched_patterns,
            sentiment_score,
            urgency_score,
            credibility_score
        )
        
        return ThreatAnalysis(
            threat_level=threat_level,
            confidence=confidence,
            detected_keywords=detected_keywords,
            matched_patterns=[p['description'] for p in matched_patterns],
            sentiment_score=sentiment_score,
            urgency_score=urgency_score,
            credibility_score=credibility_score,
            timestamp=datetime.now(),
            explanation=explanation,
            metadata=metadata or {}
        )
    
    def _detect_keywords(self, text: str) -> List[str]:
        """Detect threat keywords in text"""
        detected = []
        
        # Check high risk keywords
        for keyword in self.keywords.get('high_risk_keywords', []):
            if keyword.lower() in text:
                detected.append(f"HIGH_RISK:{keyword}")
        
        # Check threat indicators
        for indicator in self.keywords.get('threat_indicators', []):
            if indicator.lower() in text:
                detected.append(f"THREAT:{indicator}")
        
        # Check location keywords
        for location in self.keywords.get('location_keywords', []):
            if location.lower() in text:
                detected.append(f"LOCATION:{location}")
        
        # Check time indicators
        for time_ind in self.keywords.get('time_indicators', []):
            if time_ind.lower() in text:
                detected.append(f"TIME:{time_ind}")
        
        # Check hoax indicators (reduces threat level)
        for hoax in self.keywords.get('hoax_indicators', []):
            if hoax.lower() in text:
                detected.append(f"HOAX:{hoax}")
        
        return detected
    
    def _match_patterns(self, text: str) -> List[Dict]:
        """Match linguistic patterns in text"""
        matched = []
        for pattern in self.compiled_patterns:
            if pattern['regex'].search(text):
                matched.append(pattern)
        return matched
    
    def _analyze_sentiment(self, text: str) -> float:
        """Analyze sentiment and emotion of the text"""
        try:
            blob = TextBlob(text)
            # Negative sentiment might indicate threat
            # Returns value between -1 (negative) and 1 (positive)
            sentiment = blob.sentiment.polarity
            # Convert to threat score (more negative = higher threat)
            threat_sentiment = max(0, -sentiment)
            return threat_sentiment
        except:
            return 0.5
    
    def _calculate_urgency(self, text: str) -> float:
        """Calculate urgency score based on time indicators"""
        urgency = 0.0
        
        # Immediate time indicators
        immediate_words = ['now', 'immediately', 'right now', 'asap', 'urgent']
        for word in immediate_words:
            if word in text:
                urgency = max(urgency, 0.9)
        
        # Near-term indicators
        near_term = ['today', 'tonight', 'soon', 'hours', 'minutes']
        for word in near_term:
            if word in text:
                urgency = max(urgency, 0.7)
        
        # Future indicators
        future_words = ['tomorrow', 'next week', 'days', 'scheduled']
        for word in future_words:
            if word in text:
                urgency = max(urgency, 0.5)
        
        # Check for specific times
        time_pattern = re.compile(r'\d{1,2}:\d{2}|\d{1,2}\s*(am|pm|AM|PM)')
        if time_pattern.search(text):
            urgency = max(urgency, 0.8)
        
        return urgency
    
    def _assess_credibility(self, text: str, keywords: List[str], patterns: List[Dict]) -> float:
        """Assess credibility of the threat"""
        credibility = 0.5  # Start neutral
        
        # Increase credibility for specific details
        if any('LOCATION:' in k for k in keywords):
            credibility += 0.2
        if any('TIME:' in k for k in keywords):
            credibility += 0.2
        if len(patterns) > 0:
            credibility += 0.1 * min(len(patterns), 3)
        
        # Decrease credibility for hoax indicators
        hoax_count = sum(1 for k in keywords if 'HOAX:' in k)
        credibility -= 0.3 * hoax_count
        
        # Check for ALL CAPS (often indicates less credible)
        if text.isupper() and len(text) > 20:
            credibility -= 0.2
        
        # Check for excessive punctuation
        if text.count('!') > 3 or text.count('?') > 3:
            credibility -= 0.1
        
        # Ensure credibility stays within bounds
        return max(0.0, min(1.0, credibility))
    
    def _calculate_threat_level(self, keywords: List[str], patterns: List[Dict],
                               sentiment: float, urgency: float, 
                               credibility: float) -> Tuple[ThreatLevel, float]:
        """Calculate overall threat level and confidence"""
        
        # Calculate base threat score
        threat_score = 0.0
        
        # Weight different factors
        high_risk_count = sum(1 for k in keywords if 'HIGH_RISK:' in k)
        threat_count = sum(1 for k in keywords if 'THREAT:' in k)
        hoax_count = sum(1 for k in keywords if 'HOAX:' in k)
        
        # Keywords contribution (40%)
        keyword_score = min(1.0, (high_risk_count * 0.3 + threat_count * 0.2) - hoax_count * 0.2)
        threat_score += keyword_score * 0.4
        
        # Patterns contribution (30%)
        pattern_score = min(1.0, len(patterns) * 0.3)
        threat_score += pattern_score * 0.3
        
        # Sentiment contribution (10%)
        threat_score += sentiment * 0.1
        
        # Urgency contribution (10%)
        threat_score += urgency * 0.1
        
        # Credibility contribution (10%)
        threat_score += credibility * 0.1
        
        # Determine threat level based on score
        risk_levels = self.config.get('threat_detection', {}).get('risk_levels', {})
        
        if threat_score >= risk_levels.get('critical', 0.95):
            threat_level = ThreatLevel.CRITICAL
        elif threat_score >= risk_levels.get('high', 0.85):
            threat_level = ThreatLevel.HIGH
        elif threat_score >= risk_levels.get('medium', 0.6):
            threat_level = ThreatLevel.MEDIUM
        elif threat_score >= risk_levels.get('low', 0.3):
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.NONE
        
        # Confidence is based on how many indicators we found
        confidence = min(1.0, (len(keywords) + len(patterns)) * 0.1 + 0.3)
        
        return threat_level, confidence
    
    def _generate_explanation(self, threat_level: ThreatLevel, keywords: List[str],
                             patterns: List[str], sentiment: float,
                             urgency: float, credibility: float) -> str:
        """Generate human-readable explanation of the analysis"""
        
        explanation_parts = []
        
        # Threat level
        explanation_parts.append(f"Threat Level: {threat_level.name}")
        
        # Keywords found
        if keywords:
            high_risk = [k.split(':')[1] for k in keywords if 'HIGH_RISK:' in k]
            if high_risk:
                explanation_parts.append(f"High-risk keywords detected: {', '.join(high_risk[:3])}")
        
        # Patterns matched
        if patterns:
            explanation_parts.append(f"Matched threat patterns: {', '.join(patterns[:2])}")
        
        # Urgency
        if urgency > 0.7:
            explanation_parts.append("High urgency indicated")
        elif urgency > 0.4:
            explanation_parts.append("Moderate urgency indicated")
        
        # Credibility
        if credibility < 0.3:
            explanation_parts.append("Low credibility - possible hoax")
        elif credibility > 0.7:
            explanation_parts.append("High credibility - specific details provided")
        
        # Hoax indicators
        hoax_indicators = [k.split(':')[1] for k in keywords if 'HOAX:' in k]
        if hoax_indicators:
            explanation_parts.append(f"Hoax indicators found: {', '.join(hoax_indicators)}")
        
        return " | ".join(explanation_parts)
    
    def _create_empty_analysis(self) -> ThreatAnalysis:
        """Create empty analysis for invalid input"""
        return ThreatAnalysis(
            threat_level=ThreatLevel.NONE,
            confidence=0.0,
            detected_keywords=[],
            matched_patterns=[],
            sentiment_score=0.0,
            urgency_score=0.0,
            credibility_score=0.0,
            timestamp=datetime.now(),
            explanation="No text provided for analysis",
            metadata={}
        )
    
    def batch_analyze(self, messages: List[Dict[str, any]]) -> List[ThreatAnalysis]:
        """Analyze multiple messages in batch"""
        results = []
        for message in messages:
            text = message.get('text', '')
            metadata = message.get('metadata', {})
            analysis = self.detect_threat(text, metadata)
            results.append(analysis)
        return results