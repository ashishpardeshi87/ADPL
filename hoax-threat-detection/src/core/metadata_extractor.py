"""
Metadata Extraction Module
Extracts and analyzes metadata from digital communications
"""

import re
import json
import hashlib
import socket
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from email.parser import BytesParser
from email.policy import default
import ipaddress
from urllib.parse import urlparse

import dns.resolver
import whois
import geoip2.database
from user_agents import parse as parse_user_agent

class MetadataExtractor:
    """Extracts metadata from various communication sources"""
    
    def __init__(self, geoip_db_path: Optional[str] = None):
        """
        Initialize metadata extractor
        
        Args:
            geoip_db_path: Path to GeoIP database file
        """
        self.geoip_reader = None
        if geoip_db_path:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            except:
                print(f"Warning: Could not load GeoIP database from {geoip_db_path}")
        
        # Compile common patterns
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|'
            r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        self.phone_pattern = re.compile(
            r'[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?'
            r'[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}'
        )
    
    def extract_from_email(self, email_content: bytes, headers: Optional[Dict] = None) -> Dict:
        """
        Extract metadata from email content
        
        Args:
            email_content: Raw email content
            headers: Optional additional headers
            
        Returns:
            Dictionary containing extracted metadata
        """
        metadata = {
            'source_type': 'email',
            'extraction_timestamp': datetime.now().isoformat()
        }
        
        try:
            # Parse email
            msg = BytesParser(policy=default).parsebytes(email_content)
            
            # Extract basic headers
            metadata['from'] = msg.get('From', '')
            metadata['to'] = msg.get('To', '')
            metadata['subject'] = msg.get('Subject', '')
            metadata['date'] = msg.get('Date', '')
            metadata['message_id'] = msg.get('Message-ID', '')
            metadata['reply_to'] = msg.get('Reply-To', '')
            
            # Extract sender IP from headers
            received_headers = msg.get_all('Received', [])
            metadata['sender_ips'] = self._extract_ips_from_received(received_headers)
            
            # Extract authentication results
            metadata['spf'] = msg.get('Received-SPF', '')
            metadata['dkim'] = msg.get('DKIM-Signature', '')
            metadata['dmarc'] = msg.get('Authentication-Results', '')
            
            # Extract user agent
            metadata['user_agent'] = msg.get('User-Agent', '') or msg.get('X-Mailer', '')
            
            # Extract originating IP
            metadata['originating_ip'] = msg.get('X-Originating-IP', '')
            
            # Check for suspicious headers
            metadata['suspicious_headers'] = self._check_suspicious_email_headers(msg)
            
            # Extract URLs from body
            body = self._get_email_body(msg)
            metadata['urls'] = self._extract_urls(body)
            metadata['phone_numbers'] = self._extract_phone_numbers(body)
            
            # Calculate email hash for tracking
            metadata['content_hash'] = self._calculate_hash(email_content)
            
            # Analyze sender domain
            if metadata['from']:
                sender_email = self._extract_email_address(metadata['from'])
                if sender_email:
                    metadata['sender_domain'] = sender_email.split('@')[1]
                    metadata['domain_info'] = self._analyze_domain(metadata['sender_domain'])
            
            # GeoIP lookup for sender IPs
            if metadata['sender_ips'] and self.geoip_reader:
                metadata['sender_locations'] = []
                for ip in metadata['sender_ips'][:3]:  # Limit to first 3 IPs
                    location = self._get_ip_location(ip)
                    if location:
                        metadata['sender_locations'].append(location)
            
        except Exception as e:
            metadata['extraction_error'] = str(e)
        
        return metadata
    
    def extract_from_social_media(self, post_data: Dict, platform: str) -> Dict:
        """
        Extract metadata from social media post
        
        Args:
            post_data: Social media post data
            platform: Platform name (twitter, facebook, etc.)
            
        Returns:
            Dictionary containing extracted metadata
        """
        metadata = {
            'source_type': 'social_media',
            'platform': platform,
            'extraction_timestamp': datetime.now().isoformat()
        }
        
        # Common fields across platforms
        metadata['user_id'] = post_data.get('user_id', '')
        metadata['username'] = post_data.get('username', '')
        metadata['post_id'] = post_data.get('id', '')
        metadata['created_at'] = post_data.get('created_at', '')
        metadata['text'] = post_data.get('text', '')
        
        # Platform-specific extraction
        if platform.lower() == 'twitter':
            metadata.update(self._extract_twitter_metadata(post_data))
        elif platform.lower() == 'facebook':
            metadata.update(self._extract_facebook_metadata(post_data))
        elif platform.lower() == 'telegram':
            metadata.update(self._extract_telegram_metadata(post_data))
        
        # Extract URLs and mentions
        if metadata['text']:
            metadata['urls'] = self._extract_urls(metadata['text'])
            metadata['mentions'] = self._extract_mentions(metadata['text'], platform)
            metadata['hashtags'] = self._extract_hashtags(metadata['text'])
        
        # Account age and activity analysis
        metadata['account_age_days'] = self._calculate_account_age(post_data)
        metadata['is_new_account'] = metadata['account_age_days'] < 30 if metadata['account_age_days'] else None
        
        # Calculate content hash
        content = json.dumps(post_data, sort_keys=True)
        metadata['content_hash'] = self._calculate_hash(content.encode())
        
        return metadata
    
    def extract_from_web_request(self, request_headers: Dict, 
                                request_body: Optional[str] = None) -> Dict:
        """
        Extract metadata from web request
        
        Args:
            request_headers: HTTP request headers
            request_body: Optional request body
            
        Returns:
            Dictionary containing extracted metadata
        """
        metadata = {
            'source_type': 'web_request',
            'extraction_timestamp': datetime.now().isoformat()
        }
        
        # Extract IP address
        metadata['client_ip'] = (
            request_headers.get('X-Forwarded-For', '').split(',')[0].strip() or
            request_headers.get('X-Real-IP', '') or
            request_headers.get('Remote-Addr', '')
        )
        
        # Extract user agent
        user_agent_string = request_headers.get('User-Agent', '')
        metadata['user_agent'] = user_agent_string
        
        if user_agent_string:
            ua = parse_user_agent(user_agent_string)
            metadata['browser'] = f"{ua.browser.family} {ua.browser.version_string}"
            metadata['os'] = f"{ua.os.family} {ua.os.version_string}"
            metadata['device'] = ua.device.family
            metadata['is_bot'] = ua.is_bot
            metadata['is_mobile'] = ua.is_mobile
            metadata['is_tablet'] = ua.is_tablet
            metadata['is_pc'] = ua.is_pc
        
        # Extract referer
        metadata['referer'] = request_headers.get('Referer', '')
        
        # Extract accept languages
        metadata['languages'] = request_headers.get('Accept-Language', '')
        
        # Extract cookies (hash for privacy)
        cookies = request_headers.get('Cookie', '')
        if cookies:
            metadata['cookie_hash'] = self._calculate_hash(cookies.encode())
            metadata['has_cookies'] = True
        else:
            metadata['has_cookies'] = False
        
        # Check for proxy/VPN indicators
        metadata['proxy_indicators'] = self._check_proxy_indicators(request_headers)
        
        # GeoIP lookup
        if metadata['client_ip'] and self.geoip_reader:
            metadata['client_location'] = self._get_ip_location(metadata['client_ip'])
        
        # Extract from body if provided
        if request_body:
            metadata['body_urls'] = self._extract_urls(request_body)
            metadata['body_emails'] = self._extract_emails(request_body)
            metadata['body_hash'] = self._calculate_hash(request_body.encode())
        
        return metadata
    
    def _extract_ips_from_received(self, received_headers: List[str]) -> List[str]:
        """Extract IP addresses from Received headers"""
        ips = []
        for header in received_headers:
            found_ips = self.ip_pattern.findall(header)
            for ip in found_ips:
                # Skip private IPs
                try:
                    if not ipaddress.ip_address(ip).is_private:
                        ips.append(ip)
                except:
                    continue
        return list(set(ips))  # Remove duplicates
    
    def _check_suspicious_email_headers(self, msg) -> List[str]:
        """Check for suspicious email headers"""
        suspicious = []
        
        # Check for sender spoofing
        from_addr = msg.get('From', '')
        return_path = msg.get('Return-Path', '')
        if from_addr and return_path:
            from_domain = self._extract_email_address(from_addr)
            return_domain = self._extract_email_address(return_path)
            if from_domain and return_domain:
                if from_domain.split('@')[1] != return_domain.split('@')[1]:
                    suspicious.append('Domain mismatch between From and Return-Path')
        
        # Check for missing Message-ID
        if not msg.get('Message-ID'):
            suspicious.append('Missing Message-ID header')
        
        # Check for suspicious X-headers
        for header, value in msg.items():
            if header.startswith('X-'):
                if 'php' in header.lower() or 'script' in value.lower():
                    suspicious.append(f'Suspicious header: {header}')
        
        # Check SPF fail
        spf = msg.get('Received-SPF', '')
        if 'fail' in spf.lower():
            suspicious.append('SPF check failed')
        
        return suspicious
    
    def _get_email_body(self, msg) -> str:
        """Extract email body text"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        return body
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        return list(set(self.url_pattern.findall(text)))
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        return list(set(self.email_pattern.findall(text)))
    
    def _extract_phone_numbers(self, text: str) -> List[str]:
        """Extract phone numbers from text"""
        phones = self.phone_pattern.findall(text)
        # Filter out too short or too long matches
        return [p for p in phones if 7 <= len(re.sub(r'\D', '', p)) <= 15]
    
    def _extract_email_address(self, email_field: str) -> Optional[str]:
        """Extract email address from email field"""
        match = self.email_pattern.search(email_field)
        return match.group() if match else None
    
    def _calculate_hash(self, content: bytes) -> str:
        """Calculate SHA256 hash of content"""
        return hashlib.sha256(content).hexdigest()
    
    def _analyze_domain(self, domain: str) -> Dict:
        """Analyze domain information"""
        domain_info = {'domain': domain}
        
        try:
            # DNS lookup
            answers = dns.resolver.resolve(domain, 'A')
            domain_info['ip_addresses'] = [str(rdata) for rdata in answers]
            
            # MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            domain_info['mx_records'] = [str(rdata.exchange) for rdata in mx_records]
            
            # WHOIS lookup
            try:
                w = whois.whois(domain)
                domain_info['registrar'] = w.registrar
                domain_info['creation_date'] = str(w.creation_date)
                domain_info['expiration_date'] = str(w.expiration_date)
            except:
                pass
            
        except Exception as e:
            domain_info['lookup_error'] = str(e)
        
        return domain_info
    
    def _get_ip_location(self, ip: str) -> Optional[Dict]:
        """Get geographic location of IP address"""
        if not self.geoip_reader:
            return None
        
        try:
            response = self.geoip_reader.city(ip)
            return {
                'ip': ip,
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone
            }
        except:
            return None
    
    def _extract_twitter_metadata(self, post_data: Dict) -> Dict:
        """Extract Twitter-specific metadata"""
        metadata = {}
        metadata['retweet_count'] = post_data.get('retweet_count', 0)
        metadata['favorite_count'] = post_data.get('favorite_count', 0)
        metadata['reply_count'] = post_data.get('reply_count', 0)
        metadata['is_retweet'] = 'retweeted_status' in post_data
        metadata['is_reply'] = bool(post_data.get('in_reply_to_status_id'))
        metadata['user_followers'] = post_data.get('user', {}).get('followers_count', 0)
        metadata['user_following'] = post_data.get('user', {}).get('friends_count', 0)
        metadata['user_verified'] = post_data.get('user', {}).get('verified', False)
        metadata['user_created_at'] = post_data.get('user', {}).get('created_at', '')
        metadata['user_tweet_count'] = post_data.get('user', {}).get('statuses_count', 0)
        return metadata
    
    def _extract_facebook_metadata(self, post_data: Dict) -> Dict:
        """Extract Facebook-specific metadata"""
        metadata = {}
        metadata['likes_count'] = post_data.get('likes', {}).get('summary', {}).get('total_count', 0)
        metadata['comments_count'] = post_data.get('comments', {}).get('summary', {}).get('total_count', 0)
        metadata['shares_count'] = post_data.get('shares', {}).get('count', 0)
        metadata['post_type'] = post_data.get('type', '')
        metadata['privacy'] = post_data.get('privacy', {}).get('value', '')
        return metadata
    
    def _extract_telegram_metadata(self, post_data: Dict) -> Dict:
        """Extract Telegram-specific metadata"""
        metadata = {}
        metadata['chat_id'] = post_data.get('chat', {}).get('id', '')
        metadata['chat_type'] = post_data.get('chat', {}).get('type', '')
        metadata['forward_from'] = post_data.get('forward_from', {}).get('username', '')
        metadata['forward_date'] = post_data.get('forward_date', '')
        metadata['edit_date'] = post_data.get('edit_date', '')
        metadata['views'] = post_data.get('views', 0)
        return metadata
    
    def _extract_mentions(self, text: str, platform: str) -> List[str]:
        """Extract mentions from text based on platform"""
        if platform.lower() in ['twitter', 'telegram']:
            pattern = r'@[A-Za-z0-9_]+'
        else:
            pattern = r'@[A-Za-z0-9\.]+'
        
        return list(set(re.findall(pattern, text)))
    
    def _extract_hashtags(self, text: str) -> List[str]:
        """Extract hashtags from text"""
        return list(set(re.findall(r'#[A-Za-z0-9_]+', text)))
    
    def _calculate_account_age(self, post_data: Dict) -> Optional[int]:
        """Calculate account age in days"""
        created_at = post_data.get('user', {}).get('created_at', '')
        if not created_at:
            return None
        
        try:
            # Try parsing different date formats
            for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%a %b %d %H:%M:%S %z %Y']:
                try:
                    created_date = datetime.strptime(created_at, fmt)
                    age = (datetime.now() - created_date).days
                    return age
                except:
                    continue
        except:
            return None
        
        return None
    
    def _check_proxy_indicators(self, headers: Dict) -> List[str]:
        """Check for proxy/VPN indicators in headers"""
        indicators = []
        
        proxy_headers = [
            'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto',
            'Via', 'Forwarded', 'X-Real-IP', 'X-ProxyUser-Ip'
        ]
        
        for header in proxy_headers:
            if header in headers:
                indicators.append(f"Proxy header detected: {header}")
        
        # Check for multiple IPs in X-Forwarded-For
        xff = headers.get('X-Forwarded-For', '')
        if ',' in xff:
            indicators.append("Multiple IPs in X-Forwarded-For (proxy chain)")
        
        return indicators