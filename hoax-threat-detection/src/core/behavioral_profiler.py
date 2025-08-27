"""
Behavioral Profiling Module
Analyzes communication patterns and behavior to identify individuals
"""

import json
import numpy as np
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords

class BehavioralProfiler:
    """
    Behavioral profiling system to analyze and link communication patterns
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the behavioral profiler"""
        self.config = config or self._default_config()
        self.profiles = {}
        self.profile_links = defaultdict(set)
        
        # Initialize NLP components
        self._initialize_nlp()
        
        # Load behavioral patterns
        self.behavioral_patterns = self._load_behavioral_patterns()
    
    def _default_config(self) -> Dict:
        """Default configuration for behavioral profiling"""
        return {
            'profile_window_days': 30,
            'minimum_events': 3,
            'similarity_threshold': 0.8,
            'features': [
                'writing_style',
                'posting_time',
                'communication_frequency',
                'language_patterns',
                'device_consistency'
            ]
        }
    
    def _initialize_nlp(self):
        """Initialize NLP components for text analysis"""
        try:
            nltk.download('punkt', quiet=True)
            nltk.download('stopwords', quiet=True)
            nltk.download('averaged_perceptron_tagger', quiet=True)
            self.stop_words = set(stopwords.words('english'))
        except:
            self.stop_words = set()
        
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=100,
            ngram_range=(1, 3),
            stop_words='english'
        )
    
    def _load_behavioral_patterns(self) -> Dict:
        """Load known behavioral patterns"""
        return {
            'temporal_patterns': {
                'night_owl': {'hours': range(0, 6), 'weight': 0.7},
                'business_hours': {'hours': range(9, 17), 'weight': 0.5},
                'weekend_active': {'days': [5, 6], 'weight': 0.6}
            },
            'communication_styles': {
                'aggressive': ['threat', 'kill', 'destroy', 'bomb', 'explode'],
                'technical': ['device', 'timer', 'mechanism', 'trigger', 'detonate'],
                'emotional': ['hate', 'angry', 'revenge', 'unfair', 'justice'],
                'casual': ['lol', 'haha', 'btw', 'gonna', 'wanna']
            },
            'linguistic_markers': {
                'first_person': ['i', 'me', 'my', 'mine', 'myself'],
                'second_person': ['you', 'your', 'yours', 'yourself'],
                'third_person': ['they', 'them', 'their', 'he', 'she'],
                'certainty': ['definitely', 'absolutely', 'certainly', 'surely'],
                'uncertainty': ['maybe', 'perhaps', 'possibly', 'might']
            }
        }
    
    def create_profile(self, communications: List[Dict]) -> Dict:
        """
        Create a behavioral profile from a list of communications
        
        Args:
            communications: List of communication records
            
        Returns:
            Behavioral profile dictionary
        """
        if len(communications) < self.config['minimum_events']:
            return self._create_minimal_profile(communications)
        
        profile_id = self._generate_profile_id(communications)
        
        # Extract features
        writing_style = self._analyze_writing_style(communications)
        temporal_patterns = self._analyze_temporal_patterns(communications)
        communication_patterns = self._analyze_communication_patterns(communications)
        linguistic_features = self._extract_linguistic_features(communications)
        device_patterns = self._analyze_device_patterns(communications)
        network_patterns = self._analyze_network_patterns(communications)
        
        # Calculate behavioral consistency
        consistency_score = self._calculate_consistency(communications)
        
        # Identify unique markers
        unique_markers = self._identify_unique_markers(communications)
        
        profile = {
            'profile_id': profile_id,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'total_communications': len(communications),
            'writing_style': writing_style,
            'temporal_patterns': temporal_patterns,
            'communication_patterns': communication_patterns,
            'linguistic_features': linguistic_features,
            'device_patterns': device_patterns,
            'network_patterns': network_patterns,
            'consistency_score': consistency_score,
            'unique_markers': unique_markers,
            'risk_indicators': self._identify_risk_indicators(communications),
            'profile_confidence': self._calculate_profile_confidence(communications)
        }
        
        # Store profile
        self.profiles[profile_id] = profile
        
        return profile
    
    def _generate_profile_id(self, communications: List[Dict]) -> str:
        """Generate unique profile ID"""
        import hashlib
        data = json.dumps([c.get('text', '') for c in communications[:5]], sort_keys=True)
        return hashlib.md5(data.encode()).hexdigest()[:16]
    
    def _analyze_writing_style(self, communications: List[Dict]) -> Dict:
        """Analyze writing style characteristics"""
        texts = [c.get('text', '') for c in communications if c.get('text')]
        
        if not texts:
            return {}
        
        style_features = {
            'avg_sentence_length': 0,
            'avg_word_length': 0,
            'vocabulary_richness': 0,
            'punctuation_usage': {},
            'capitalization_pattern': '',
            'common_phrases': [],
            'writing_complexity': 0,
            'formality_level': 0
        }
        
        all_sentences = []
        all_words = []
        punctuation_counts = defaultdict(int)
        
        for text in texts:
            # Sentence analysis
            sentences = sent_tokenize(text)
            all_sentences.extend(sentences)
            
            # Word analysis
            words = word_tokenize(text.lower())
            words = [w for w in words if w.isalnum()]
            all_words.extend(words)
            
            # Punctuation analysis
            for char in text:
                if char in '.,!?;:-()[]{}"\'/':
                    punctuation_counts[char] += 1
        
        if all_sentences:
            # Calculate average sentence length
            style_features['avg_sentence_length'] = np.mean([len(word_tokenize(s)) for s in all_sentences])
        
        if all_words:
            # Calculate average word length
            style_features['avg_word_length'] = np.mean([len(w) for w in all_words])
            
            # Vocabulary richness (unique words / total words)
            style_features['vocabulary_richness'] = len(set(all_words)) / len(all_words)
            
            # Common phrases (bigrams and trigrams)
            style_features['common_phrases'] = self._extract_common_phrases(texts)
        
        # Punctuation usage pattern
        total_punctuation = sum(punctuation_counts.values())
        if total_punctuation > 0:
            style_features['punctuation_usage'] = {
                char: count / total_punctuation 
                for char, count in punctuation_counts.items()
            }
        
        # Capitalization pattern
        cap_patterns = []
        for text in texts:
            if text.isupper():
                cap_patterns.append('ALL_CAPS')
            elif text.islower():
                cap_patterns.append('all_lower')
            elif text[0].isupper():
                cap_patterns.append('sentence_case')
            else:
                cap_patterns.append('mixed')
        
        if cap_patterns:
            style_features['capitalization_pattern'] = Counter(cap_patterns).most_common(1)[0][0]
        
        # Writing complexity (using Flesch Reading Ease approximation)
        style_features['writing_complexity'] = self._calculate_text_complexity(texts)
        
        # Formality level
        style_features['formality_level'] = self._calculate_formality(texts)
        
        return style_features
    
    def _analyze_temporal_patterns(self, communications: List[Dict]) -> Dict:
        """Analyze temporal patterns in communications"""
        timestamps = []
        for comm in communications:
            ts = comm.get('timestamp') or comm.get('created_at')
            if ts:
                try:
                    if isinstance(ts, str):
                        timestamps.append(datetime.fromisoformat(ts))
                    else:
                        timestamps.append(ts)
                except:
                    continue
        
        if not timestamps:
            return {}
        
        temporal_features = {
            'preferred_hours': [],
            'preferred_days': [],
            'activity_pattern': '',
            'posting_frequency': {},
            'time_consistency': 0,
            'burst_behavior': False,
            'regular_schedule': False
        }
        
        # Extract hour and day preferences
        hours = [ts.hour for ts in timestamps]
        days = [ts.weekday() for ts in timestamps]
        
        # Most common posting hours
        hour_counts = Counter(hours)
        temporal_features['preferred_hours'] = [h for h, _ in hour_counts.most_common(3)]
        
        # Most common posting days
        day_counts = Counter(days)
        temporal_features['preferred_days'] = [d for d, _ in day_counts.most_common(3)]
        
        # Activity pattern classification
        if all(h in range(0, 6) or h in range(22, 24) for h in temporal_features['preferred_hours']):
            temporal_features['activity_pattern'] = 'night_owl'
        elif all(h in range(9, 17) for h in temporal_features['preferred_hours']):
            temporal_features['activity_pattern'] = 'business_hours'
        elif all(d in [5, 6] for d in temporal_features['preferred_days']):
            temporal_features['activity_pattern'] = 'weekend_only'
        else:
            temporal_features['activity_pattern'] = 'irregular'
        
        # Posting frequency analysis
        if len(timestamps) > 1:
            # Calculate intervals between posts
            timestamps_sorted = sorted(timestamps)
            intervals = []
            for i in range(1, len(timestamps_sorted)):
                interval = (timestamps_sorted[i] - timestamps_sorted[i-1]).total_seconds() / 3600
                intervals.append(interval)
            
            if intervals:
                temporal_features['posting_frequency'] = {
                    'avg_interval_hours': np.mean(intervals),
                    'min_interval_hours': min(intervals),
                    'max_interval_hours': max(intervals),
                    'std_interval_hours': np.std(intervals)
                }
                
                # Check for burst behavior (many posts in short time)
                temporal_features['burst_behavior'] = any(i < 0.5 for i in intervals[:5])
                
                # Check for regular schedule (consistent intervals)
                temporal_features['regular_schedule'] = np.std(intervals) < 12
                
                # Time consistency score
                temporal_features['time_consistency'] = 1 / (1 + np.std(intervals) / 24)
        
        return temporal_features
    
    def _analyze_communication_patterns(self, communications: List[Dict]) -> Dict:
        """Analyze communication patterns"""
        patterns = {
            'message_length_stats': {},
            'response_pattern': '',
            'escalation_pattern': False,
            'repetition_score': 0,
            'target_consistency': [],
            'communication_medium': []
        }
        
        # Message length statistics
        lengths = [len(c.get('text', '')) for c in communications if c.get('text')]
        if lengths:
            patterns['message_length_stats'] = {
                'mean': np.mean(lengths),
                'median': np.median(lengths),
                'std': np.std(lengths),
                'min': min(lengths),
                'max': max(lengths)
            }
        
        # Check for escalation pattern
        if len(communications) > 2:
            # Check if messages get progressively more aggressive
            threat_scores = []
            for comm in communications:
                text = comm.get('text', '').lower()
                threat_score = sum(1 for word in self.behavioral_patterns['communication_styles']['aggressive'] 
                                 if word in text)
                threat_scores.append(threat_score)
            
            if len(threat_scores) > 2:
                # Check if threat scores are increasing
                patterns['escalation_pattern'] = all(threat_scores[i] <= threat_scores[i+1] 
                                                    for i in range(len(threat_scores)-1))
        
        # Repetition score (how similar messages are)
        if len(communications) > 1:
            texts = [c.get('text', '') for c in communications if c.get('text')]
            if len(texts) > 1:
                similarities = []
                for i in range(len(texts)-1):
                    for j in range(i+1, len(texts)):
                        sim = self._calculate_text_similarity(texts[i], texts[j])
                        similarities.append(sim)
                if similarities:
                    patterns['repetition_score'] = np.mean(similarities)
        
        # Target consistency
        targets = [c.get('target') or c.get('recipient') for c in communications]
        targets = [t for t in targets if t]
        if targets:
            target_counts = Counter(targets)
            patterns['target_consistency'] = [t for t, _ in target_counts.most_common(3)]
        
        # Communication medium
        mediums = [c.get('medium') or c.get('platform') for c in communications]
        mediums = [m for m in mediums if m]
        if mediums:
            medium_counts = Counter(mediums)
            patterns['communication_medium'] = [m for m, _ in medium_counts.most_common()]
        
        return patterns
    
    def _extract_linguistic_features(self, communications: List[Dict]) -> Dict:
        """Extract linguistic features from communications"""
        texts = [c.get('text', '') for c in communications if c.get('text')]
        
        if not texts:
            return {}
        
        features = {
            'pronoun_usage': {},
            'sentiment_distribution': {},
            'emotion_markers': [],
            'certainty_level': 0,
            'tense_preference': '',
            'unique_expressions': [],
            'spelling_errors': 0,
            'grammar_patterns': []
        }
        
        all_text = ' '.join(texts).lower()
        words = word_tokenize(all_text)
        
        # Pronoun usage analysis
        for pronoun_type, pronouns in self.behavioral_patterns['linguistic_markers'].items():
            if 'person' in pronoun_type:
                count = sum(1 for w in words if w in pronouns)
                features['pronoun_usage'][pronoun_type] = count / len(words) if words else 0
        
        # Certainty level
        certainty_words = self.behavioral_patterns['linguistic_markers']['certainty']
        uncertainty_words = self.behavioral_patterns['linguistic_markers']['uncertainty']
        
        certainty_count = sum(1 for w in words if w in certainty_words)
        uncertainty_count = sum(1 for w in words if w in uncertainty_words)
        
        if certainty_count + uncertainty_count > 0:
            features['certainty_level'] = certainty_count / (certainty_count + uncertainty_count)
        
        # Emotion markers
        emotion_words = []
        for style, markers in self.behavioral_patterns['communication_styles'].items():
            for text in texts:
                text_lower = text.lower()
                for marker in markers:
                    if marker in text_lower:
                        emotion_words.append(f"{style}:{marker}")
        
        if emotion_words:
            features['emotion_markers'] = list(set(emotion_words))[:10]
        
        # Unique expressions (uncommon phrases)
        features['unique_expressions'] = self._find_unique_expressions(texts)
        
        # Grammar patterns (simplified - POS tagging)
        try:
            pos_tags = nltk.pos_tag(words[:100])  # Limit for performance
            pos_patterns = [tag for _, tag in pos_tags]
            pos_bigrams = [f"{pos_patterns[i]}_{pos_patterns[i+1]}" 
                          for i in range(len(pos_patterns)-1)]
            features['grammar_patterns'] = Counter(pos_bigrams).most_common(5)
        except:
            features['grammar_patterns'] = []
        
        return features
    
    def _analyze_device_patterns(self, communications: List[Dict]) -> Dict:
        """Analyze device usage patterns"""
        device_info = {
            'devices_used': [],
            'primary_device': '',
            'device_consistency': 0,
            'platform_preferences': [],
            'browser_preferences': []
        }
        
        devices = []
        platforms = []
        browsers = []
        
        for comm in communications:
            device = comm.get('device_fingerprint') or comm.get('device_id')
            if device:
                devices.append(device)
            
            platform = comm.get('platform') or comm.get('os')
            if platform:
                platforms.append(platform)
            
            browser = comm.get('browser')
            if browser:
                browsers.append(browser)
        
        if devices:
            device_counts = Counter(devices)
            device_info['devices_used'] = list(device_counts.keys())
            device_info['primary_device'] = device_counts.most_common(1)[0][0]
            
            # Device consistency (1 = always same device, 0 = always different)
            device_info['device_consistency'] = 1 - (len(set(devices)) - 1) / len(devices)
        
        if platforms:
            platform_counts = Counter(platforms)
            device_info['platform_preferences'] = [p for p, _ in platform_counts.most_common()]
        
        if browsers:
            browser_counts = Counter(browsers)
            device_info['browser_preferences'] = [b for b, _ in browser_counts.most_common()]
        
        return device_info
    
    def _analyze_network_patterns(self, communications: List[Dict]) -> Dict:
        """Analyze network patterns"""
        network_info = {
            'ip_addresses': [],
            'ip_consistency': 0,
            'vpn_usage': False,
            'tor_usage': False,
            'geographic_patterns': [],
            'isp_patterns': []
        }
        
        ips = []
        locations = []
        
        for comm in communications:
            ip = comm.get('ip_address') or comm.get('sender_ip')
            if ip:
                ips.append(ip)
            
            location = comm.get('location') or comm.get('geo_location')
            if location:
                locations.append(location)
        
        if ips:
            ip_counts = Counter(ips)
            network_info['ip_addresses'] = list(ip_counts.keys())
            
            # IP consistency
            network_info['ip_consistency'] = 1 - (len(set(ips)) - 1) / len(ips)
            
            # Check for VPN/Tor indicators
            for ip in ips:
                if self._is_vpn_ip(ip):
                    network_info['vpn_usage'] = True
                if self._is_tor_exit_node(ip):
                    network_info['tor_usage'] = True
        
        if locations:
            location_counts = Counter(locations)
            network_info['geographic_patterns'] = [l for l, _ in location_counts.most_common(3)]
        
        return network_info
    
    def compare_profiles(self, profile1: Dict, profile2: Dict) -> float:
        """
        Compare two behavioral profiles and return similarity score
        
        Args:
            profile1: First behavioral profile
            profile2: Second behavioral profile
            
        Returns:
            Similarity score between 0 and 1
        """
        similarity_scores = []
        weights = {
            'writing_style': 0.3,
            'temporal_patterns': 0.2,
            'linguistic_features': 0.25,
            'communication_patterns': 0.15,
            'device_patterns': 0.05,
            'network_patterns': 0.05
        }
        
        # Compare writing style
        if 'writing_style' in profile1 and 'writing_style' in profile2:
            style_sim = self._compare_writing_styles(
                profile1['writing_style'],
                profile2['writing_style']
            )
            similarity_scores.append(('writing_style', style_sim))
        
        # Compare temporal patterns
        if 'temporal_patterns' in profile1 and 'temporal_patterns' in profile2:
            temporal_sim = self._compare_temporal_patterns(
                profile1['temporal_patterns'],
                profile2['temporal_patterns']
            )
            similarity_scores.append(('temporal_patterns', temporal_sim))
        
        # Compare linguistic features
        if 'linguistic_features' in profile1 and 'linguistic_features' in profile2:
            linguistic_sim = self._compare_linguistic_features(
                profile1['linguistic_features'],
                profile2['linguistic_features']
            )
            similarity_scores.append(('linguistic_features', linguistic_sim))
        
        # Compare communication patterns
        if 'communication_patterns' in profile1 and 'communication_patterns' in profile2:
            comm_sim = self._compare_communication_patterns(
                profile1['communication_patterns'],
                profile2['communication_patterns']
            )
            similarity_scores.append(('communication_patterns', comm_sim))
        
        # Calculate weighted average
        if not similarity_scores:
            return 0.0
        
        total_weight = 0
        weighted_sum = 0
        
        for feature, score in similarity_scores:
            weight = weights.get(feature, 0.1)
            weighted_sum += score * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def link_profiles(self, profiles: List[Dict], threshold: Optional[float] = None) -> List[Set[str]]:
        """
        Link profiles that likely belong to the same individual
        
        Args:
            profiles: List of behavioral profiles
            threshold: Similarity threshold for linking (default from config)
            
        Returns:
            List of sets containing linked profile IDs
        """
        if threshold is None:
            threshold = self.config['similarity_threshold']
        
        linked_groups = []
        processed = set()
        
        for i, profile1 in enumerate(profiles):
            profile1_id = profile1['profile_id']
            
            if profile1_id in processed:
                continue
            
            group = {profile1_id}
            processed.add(profile1_id)
            
            for j, profile2 in enumerate(profiles[i+1:], i+1):
                profile2_id = profile2['profile_id']
                
                if profile2_id in processed:
                    continue
                
                similarity = self.compare_profiles(profile1, profile2)
                
                if similarity >= threshold:
                    group.add(profile2_id)
                    processed.add(profile2_id)
                    self.profile_links[profile1_id].add(profile2_id)
                    self.profile_links[profile2_id].add(profile1_id)
            
            if len(group) > 1:
                linked_groups.append(group)
        
        return linked_groups
    
    # Helper methods
    
    def _create_minimal_profile(self, communications: List[Dict]) -> Dict:
        """Create minimal profile when insufficient data"""
        return {
            'profile_id': self._generate_profile_id(communications),
            'created_at': datetime.now().isoformat(),
            'total_communications': len(communications),
            'insufficient_data': True,
            'profile_confidence': 0.0
        }
    
    def _extract_common_phrases(self, texts: List[str]) -> List[str]:
        """Extract common phrases from texts"""
        all_text = ' '.join(texts)
        
        # Extract bigrams and trigrams
        words = word_tokenize(all_text.lower())
        words = [w for w in words if w not in self.stop_words and w.isalnum()]
        
        bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words)-1)]
        trigrams = [f"{words[i]} {words[i+1]} {words[i+2]}" for i in range(len(words)-2)]
        
        phrase_counts = Counter(bigrams + trigrams)
        return [phrase for phrase, count in phrase_counts.most_common(10) if count > 1]
    
    def _calculate_text_complexity(self, texts: List[str]) -> float:
        """Calculate text complexity score"""
        if not texts:
            return 0.0
        
        all_text = ' '.join(texts)
        sentences = sent_tokenize(all_text)
        words = word_tokenize(all_text)
        syllables = sum(self._count_syllables(word) for word in words)
        
        if not sentences or not words:
            return 0.0
        
        # Simplified Flesch Reading Ease
        avg_sentence_length = len(words) / len(sentences)
        avg_syllables_per_word = syllables / len(words)
        
        complexity = 206.835 - 1.015 * avg_sentence_length - 84.6 * avg_syllables_per_word
        
        # Normalize to 0-1 scale (0 = simple, 1 = complex)
        return max(0, min(1, (100 - complexity) / 100))
    
    def _count_syllables(self, word: str) -> int:
        """Count syllables in a word (simplified)"""
        word = word.lower()
        vowels = 'aeiou'
        syllable_count = 0
        previous_was_vowel = False
        
        for char in word:
            is_vowel = char in vowels
            if is_vowel and not previous_was_vowel:
                syllable_count += 1
            previous_was_vowel = is_vowel
        
        if word.endswith('e'):
            syllable_count -= 1
        
        return max(1, syllable_count)
    
    def _calculate_formality(self, texts: List[str]) -> float:
        """Calculate formality level of texts"""
        informal_markers = ['gonna', 'wanna', 'gotta', 'kinda', 'sorta', 'yeah', 
                          'yep', 'nope', 'dunno', 'lemme', 'gimme']
        formal_markers = ['therefore', 'however', 'furthermore', 'moreover', 
                         'consequently', 'nevertheless', 'whereas']
        
        all_text = ' '.join(texts).lower()
        words = word_tokenize(all_text)
        
        informal_count = sum(1 for w in words if w in informal_markers)
        formal_count = sum(1 for w in words if w in formal_markers)
        
        if informal_count + formal_count == 0:
            return 0.5
        
        return formal_count / (informal_count + formal_count)
    
    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts"""
        if not text1 or not text2:
            return 0.0
        
        try:
            # Use TF-IDF vectors
            vectors = self.tfidf_vectorizer.fit_transform([text1, text2])
            similarity = cosine_similarity(vectors[0:1], vectors[1:2])[0][0]
            return similarity
        except:
            # Fallback to simple word overlap
            words1 = set(word_tokenize(text1.lower()))
            words2 = set(word_tokenize(text2.lower()))
            
            if not words1 or not words2:
                return 0.0
            
            intersection = words1.intersection(words2)
            union = words1.union(words2)
            
            return len(intersection) / len(union)
    
    def _find_unique_expressions(self, texts: List[str]) -> List[str]:
        """Find unique or unusual expressions in texts"""
        # This is simplified - in production, would use more sophisticated methods
        unique_expressions = []
        
        common_expressions = set(['in order to', 'as well as', 'on the other hand'])
        
        for text in texts:
            # Look for quoted phrases
            quoted = re.findall(r'"([^"]+)"', text)
            unique_expressions.extend(quoted)
            
            # Look for unusual punctuation patterns
            unusual = re.findall(r'[!?]{2,}|\.{3,}', text)
            if unusual:
                unique_expressions.append('unusual_punctuation')
        
        return list(set(unique_expressions))[:5]
    
    def _calculate_consistency(self, communications: List[Dict]) -> float:
        """Calculate behavioral consistency across communications"""
        if len(communications) < 2:
            return 1.0
        
        # Compare consecutive communications
        consistencies = []
        
        for i in range(len(communications) - 1):
            comm1 = communications[i]
            comm2 = communications[i + 1]
            
            # Compare various attributes
            similarity_scores = []
            
            # Text similarity
            text1 = comm1.get('text', '')
            text2 = comm2.get('text', '')
            if text1 and text2:
                similarity_scores.append(self._calculate_text_similarity(text1, text2))
            
            # Device consistency
            if comm1.get('device_id') == comm2.get('device_id'):
                similarity_scores.append(1.0)
            else:
                similarity_scores.append(0.0)
            
            if similarity_scores:
                consistencies.append(np.mean(similarity_scores))
        
        return np.mean(consistencies) if consistencies else 0.5
    
    def _identify_unique_markers(self, communications: List[Dict]) -> List[str]:
        """Identify unique behavioral markers"""
        markers = []
        
        # Check for consistent typos or misspellings
        all_text = ' '.join([c.get('text', '') for c in communications])
        words = word_tokenize(all_text.lower())
        
        # Find repeated unusual words (potential typos or unique expressions)
        word_counts = Counter(words)
        for word, count in word_counts.items():
            if count > 2 and len(word) > 3:
                # Check if it's likely a typo or unique expression
                if word not in self.stop_words:
                    markers.append(f"unique_word:{word}")
        
        return markers[:10]
    
    def _identify_risk_indicators(self, communications: List[Dict]) -> List[str]:
        """Identify risk indicators in behavioral pattern"""
        indicators = []
        
        # Check for escalation
        if len(communications) > 2:
            threat_progression = []
            for comm in communications:
                text = comm.get('text', '').lower()
                threat_words = ['bomb', 'explode', 'kill', 'destroy', 'attack']
                threat_count = sum(1 for word in threat_words if word in text)
                threat_progression.append(threat_count)
            
            if all(threat_progression[i] <= threat_progression[i+1] 
                  for i in range(len(threat_progression)-1)):
                indicators.append('escalating_threats')
        
        # Check for anonymization attempts
        vpn_count = sum(1 for c in communications if c.get('vpn_detected'))
        if vpn_count > len(communications) * 0.5:
            indicators.append('frequent_vpn_usage')
        
        # Check for multiple identities
        unique_emails = set(c.get('email') for c in communications if c.get('email'))
        if len(unique_emails) > 3:
            indicators.append('multiple_identities')
        
        return indicators
    
    def _calculate_profile_confidence(self, communications: List[Dict]) -> float:
        """Calculate confidence in the profile accuracy"""
        confidence = 0.0
        
        # More data = higher confidence
        data_points = len(communications)
        confidence += min(0.3, data_points * 0.03)
        
        # Consistency = higher confidence
        consistency = self._calculate_consistency(communications)
        confidence += consistency * 0.3
        
        # Time span coverage
        if len(communications) > 1:
            timestamps = []
            for comm in communications:
                ts = comm.get('timestamp')
                if ts:
                    try:
                        timestamps.append(datetime.fromisoformat(ts))
                    except:
                        continue
            
            if len(timestamps) > 1:
                time_span = (max(timestamps) - min(timestamps)).days
                if time_span > 7:
                    confidence += 0.2
                if time_span > 30:
                    confidence += 0.2
        
        return min(1.0, confidence)
    
    def _is_vpn_ip(self, ip: str) -> bool:
        """Check if IP belongs to known VPN provider"""
        # Simplified check - in production would use VPN detection API
        vpn_patterns = ['vpn', 'proxy', 'hide', 'anonymous']
        return any(pattern in ip.lower() for pattern in vpn_patterns)
    
    def _is_tor_exit_node(self, ip: str) -> bool:
        """Check if IP is a Tor exit node"""
        # Simplified check - in production would check against Tor exit node list
        return 'tor' in ip.lower()
    
    def _compare_writing_styles(self, style1: Dict, style2: Dict) -> float:
        """Compare two writing style profiles"""
        if not style1 or not style2:
            return 0.0
        
        similarities = []
        
        # Compare sentence length
        if 'avg_sentence_length' in style1 and 'avg_sentence_length' in style2:
            diff = abs(style1['avg_sentence_length'] - style2['avg_sentence_length'])
            sim = max(0, 1 - diff / 20)
            similarities.append(sim)
        
        # Compare vocabulary richness
        if 'vocabulary_richness' in style1 and 'vocabulary_richness' in style2:
            diff = abs(style1['vocabulary_richness'] - style2['vocabulary_richness'])
            similarities.append(1 - diff)
        
        # Compare capitalization pattern
        if style1.get('capitalization_pattern') == style2.get('capitalization_pattern'):
            similarities.append(1.0)
        else:
            similarities.append(0.0)
        
        return np.mean(similarities) if similarities else 0.0
    
    def _compare_temporal_patterns(self, pattern1: Dict, pattern2: Dict) -> float:
        """Compare two temporal pattern profiles"""
        if not pattern1 or not pattern2:
            return 0.0
        
        similarities = []
        
        # Compare preferred hours
        hours1 = set(pattern1.get('preferred_hours', []))
        hours2 = set(pattern2.get('preferred_hours', []))
        if hours1 and hours2:
            overlap = len(hours1.intersection(hours2))
            union = len(hours1.union(hours2))
            similarities.append(overlap / union if union > 0 else 0)
        
        # Compare activity pattern
        if pattern1.get('activity_pattern') == pattern2.get('activity_pattern'):
            similarities.append(1.0)
        else:
            similarities.append(0.0)
        
        return np.mean(similarities) if similarities else 0.0
    
    def _compare_linguistic_features(self, features1: Dict, features2: Dict) -> float:
        """Compare two linguistic feature profiles"""
        if not features1 or not features2:
            return 0.0
        
        similarities = []
        
        # Compare pronoun usage
        for pronoun_type in ['first_person', 'second_person', 'third_person']:
            if pronoun_type in features1.get('pronoun_usage', {}) and \
               pronoun_type in features2.get('pronoun_usage', {}):
                diff = abs(features1['pronoun_usage'][pronoun_type] - 
                          features2['pronoun_usage'][pronoun_type])
                similarities.append(1 - diff)
        
        # Compare certainty level
        if 'certainty_level' in features1 and 'certainty_level' in features2:
            diff = abs(features1['certainty_level'] - features2['certainty_level'])
            similarities.append(1 - diff)
        
        return np.mean(similarities) if similarities else 0.0
    
    def _compare_communication_patterns(self, pattern1: Dict, pattern2: Dict) -> float:
        """Compare two communication pattern profiles"""
        if not pattern1 or not pattern2:
            return 0.0
        
        similarities = []
        
        # Compare message length statistics
        if 'message_length_stats' in pattern1 and 'message_length_stats' in pattern2:
            stats1 = pattern1['message_length_stats']
            stats2 = pattern2['message_length_stats']
            
            if stats1.get('mean') and stats2.get('mean'):
                diff = abs(stats1['mean'] - stats2['mean'])
                sim = max(0, 1 - diff / 500)
                similarities.append(sim)
        
        # Compare repetition score
        if 'repetition_score' in pattern1 and 'repetition_score' in pattern2:
            diff = abs(pattern1['repetition_score'] - pattern2['repetition_score'])
            similarities.append(1 - diff)
        
        return np.mean(similarities) if similarities else 0.0