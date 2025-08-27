"""
Email Monitoring Module
Monitors email accounts for potential threats
"""

import asyncio
import imaplib
import email
from email.parser import BytesParser
from email.policy import default
from typing import Dict, List, Optional
from datetime import datetime
import logging
import re

class EmailMonitor:
    """Monitor email accounts for threats"""
    
    def __init__(self, config: Dict, output_queue: asyncio.Queue):
        """
        Initialize email monitor
        
        Args:
            config: Email monitoring configuration
            output_queue: Queue to send detected messages
        """
        self.config = config
        self.output_queue = output_queue
        self.logger = logging.getLogger('EmailMonitor')
        
        # IMAP connection
        self.imap_client = None
        self.connected = False
        
        # Monitoring state
        self.last_check = None
        self.processed_uids = set()
        self.running = False
    
    async def start(self):
        """Start email monitoring"""
        self.logger.info("Starting Email Monitor...")
        self.running = True
        
        # Connect to email server
        await self.connect()
        
        # Start monitoring loop
        while self.running:
            try:
                await self.check_emails()
                await asyncio.sleep(self.config.get('check_interval', 30))
            except Exception as e:
                self.logger.error(f"Error in email monitoring: {e}")
                await asyncio.sleep(60)  # Wait before retry
                await self.reconnect()
    
    async def connect(self):
        """Connect to IMAP server"""
        try:
            # Create IMAP connection
            self.imap_client = imaplib.IMAP4_SSL(
                self.config.get('imap_server', 'imap.gmail.com'),
                self.config.get('imap_port', 993)
            )
            
            # Login
            self.imap_client.login(
                self.config.get('username', ''),
                self.config.get('password', '')
            )
            
            # Select inbox
            self.imap_client.select('INBOX')
            
            self.connected = True
            self.logger.info("Connected to IMAP server")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to IMAP server: {e}")
            self.connected = False
            raise
    
    async def reconnect(self):
        """Reconnect to IMAP server"""
        self.logger.info("Attempting to reconnect to IMAP server...")
        
        if self.imap_client:
            try:
                self.imap_client.close()
                self.imap_client.logout()
            except:
                pass
        
        await self.connect()
    
    async def check_emails(self):
        """Check for new emails"""
        if not self.connected:
            return
        
        try:
            # Search for unread emails
            typ, data = self.imap_client.search(None, 'UNSEEN')
            
            if typ != 'OK':
                self.logger.warning("Failed to search emails")
                return
            
            email_ids = data[0].split()
            
            for email_id in email_ids:
                if email_id not in self.processed_uids:
                    await self.process_email(email_id)
                    self.processed_uids.add(email_id)
            
            # Clean up old UIDs to prevent memory growth
            if len(self.processed_uids) > 10000:
                self.processed_uids = set(list(self.processed_uids)[-5000:])
            
        except Exception as e:
            self.logger.error(f"Error checking emails: {e}")
            self.connected = False
    
    async def process_email(self, email_id: bytes):
        """Process individual email"""
        try:
            # Fetch email
            typ, data = self.imap_client.fetch(email_id, '(RFC822)')
            
            if typ != 'OK':
                self.logger.warning(f"Failed to fetch email {email_id}")
                return
            
            # Parse email
            raw_email = data[0][1]
            msg = BytesParser(policy=default).parsebytes(raw_email)
            
            # Extract relevant information
            email_data = self.extract_email_data(msg, raw_email)
            
            # Check if email should be flagged
            if self.should_flag_email(email_data):
                # Add to output queue
                await self.output_queue.put(email_data)
                
                self.logger.info(f"Flagged email from {email_data.get('from')}")
            
        except Exception as e:
            self.logger.error(f"Error processing email {email_id}: {e}")
    
    def extract_email_data(self, msg, raw_content: bytes) -> Dict:
        """Extract data from email message"""
        # Get email body
        body = self.get_email_body(msg)
        
        # Extract headers
        headers = {}
        for header, value in msg.items():
            headers[header] = value
        
        return {
            'source_type': 'email',
            'timestamp': datetime.now().isoformat(),
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', ''),
            'text': body,
            'headers': headers,
            'raw_content': raw_content,
            'attachments': self.get_attachments(msg)
        }
    
    def get_email_body(self, msg) -> str:
        """Extract email body text"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(msg.get_payload())
        
        return body
    
    def get_attachments(self, msg) -> List[Dict]:
        """Extract attachment information"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': len(part.get_payload())
                        })
        
        return attachments
    
    def should_flag_email(self, email_data: Dict) -> bool:
        """Determine if email should be flagged for analysis"""
        # Check subject and body for threat keywords
        text_to_check = f"{email_data.get('subject', '')} {email_data.get('text', '')}"
        text_lower = text_to_check.lower()
        
        # Basic threat keywords (would be more sophisticated in production)
        threat_keywords = [
            'bomb', 'explosive', 'detonate', 'threat', 'attack',
            'explode', 'device', 'timer', 'warning'
        ]
        
        # Check for keywords
        for keyword in threat_keywords:
            if keyword in text_lower:
                return True
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'will\s+(?:explode|detonate|blow)',
            r'bomb\s+(?:threat|warning|alert)',
            r'planted\s+(?:a\s+)?(?:bomb|device|explosive)'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, text_lower):
                return True
        
        # Check for suspicious sender patterns
        sender = email_data.get('from', '').lower()
        if any(domain in sender for domain in ['guerrillamail', 'mailinator', '10minutemail']):
            # Check body more carefully for disposable email addresses
            if any(keyword in text_lower for keyword in ['threat', 'bomb', 'attack']):
                return True
        
        return False
    
    async def stop(self):
        """Stop email monitoring"""
        self.logger.info("Stopping Email Monitor...")
        self.running = False
        
        if self.imap_client and self.connected:
            try:
                self.imap_client.close()
                self.imap_client.logout()
            except:
                pass
        
        self.connected = False