"""
Social Media Monitoring Module
Monitors various social media platforms for threats
"""

import asyncio
import json
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import logging
import re
import tweepy
from telegram import Bot
from telegram.ext import Updater, MessageHandler, Filters
import aiohttp

class SocialMediaMonitor:
    """Base class for social media monitors"""
    
    def __init__(self, config: Dict, output_queue: asyncio.Queue):
        """Initialize social media monitor"""
        self.config = config
        self.output_queue = output_queue
        self.logger = logging.getLogger(self.__class__.__name__)
        self.running = False
        self.processed_ids = set()
    
    async def start(self):
        """Start monitoring - to be implemented by subclasses"""
        raise NotImplementedError
    
    async def stop(self):
        """Stop monitoring"""
        self.running = False
    
    def should_flag_post(self, text: str) -> bool:
        """Check if post should be flagged"""
        text_lower = text.lower()
        
        # Threat keywords
        threat_keywords = [
            'bomb', 'explosive', 'detonate', 'threat', 'attack',
            'explode', 'device', 'timer', 'warning', 'evacuate'
        ]
        
        for keyword in threat_keywords:
            if keyword in text_lower:
                return True
        
        # Threat patterns
        threat_patterns = [
            r'will\s+(?:explode|detonate|blow)',
            r'bomb\s+(?:threat|warning|alert)',
            r'planted\s+(?:a\s+)?(?:bomb|device|explosive)',
            r'going\s+to\s+(?:blow|explode|detonate)'
        ]
        
        for pattern in threat_patterns:
            if re.search(pattern, text_lower):
                return True
        
        return False


class TwitterMonitor(SocialMediaMonitor):
    """Monitor Twitter for threats"""
    
    def __init__(self, config: Dict, output_queue: asyncio.Queue):
        """Initialize Twitter monitor"""
        super().__init__(config, output_queue)
        
        # Initialize Twitter API
        self.api = None
        self.stream_listener = None
        self.stream = None
        
        self._setup_twitter_api()
    
    def _setup_twitter_api(self):
        """Setup Twitter API connection"""
        try:
            # Authentication
            auth = tweepy.OAuthHandler(
                self.config.get('api_key', ''),
                self.config.get('api_secret', '')
            )
            auth.set_access_token(
                self.config.get('access_token', ''),
                self.config.get('access_token_secret', '')
            )
            
            # Create API object
            self.api = tweepy.API(auth, wait_on_rate_limit=True)
            
            # Verify credentials
            self.api.verify_credentials()
            self.logger.info("Twitter API connected successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to setup Twitter API: {e}")
            self.api = None
    
    async def start(self):
        """Start Twitter monitoring"""
        if not self.api:
            self.logger.error("Twitter API not configured")
            return
        
        self.logger.info("Starting Twitter Monitor...")
        self.running = True
        
        # Start streaming
        await self.start_streaming()
        
        # Also periodically search for keywords
        asyncio.create_task(self.search_loop())
    
    async def start_streaming(self):
        """Start Twitter streaming"""
        try:
            # Create stream listener
            self.stream_listener = TwitterStreamListener(self.output_queue, self)
            
            # Create stream
            self.stream = tweepy.Stream(
                auth=self.api.auth,
                listener=self.stream_listener,
                tweet_mode='extended'
            )
            
            # Define keywords to track
            keywords = [
                'bomb threat', 'explosive device', 'detonate',
                'evacuation', 'suspicious package'
            ]
            
            # Start streaming in background
            self.stream.filter(track=keywords, is_async=True)
            
            self.logger.info("Twitter streaming started")
            
        except Exception as e:
            self.logger.error(f"Failed to start Twitter streaming: {e}")
    
    async def search_loop(self):
        """Periodically search for threats"""
        while self.running:
            try:
                await self.search_threats()
                await asyncio.sleep(300)  # Search every 5 minutes
            except Exception as e:
                self.logger.error(f"Error in Twitter search loop: {e}")
                await asyncio.sleep(60)
    
    async def search_threats(self):
        """Search for threat-related tweets"""
        if not self.api:
            return
        
        try:
            # Define search queries
            queries = [
                'bomb threat -filter:retweets',
                'explosive device -filter:retweets',
                '"going to explode" -filter:retweets'
            ]
            
            for query in queries:
                # Search tweets
                tweets = self.api.search_tweets(
                    q=query,
                    count=100,
                    result_type='recent',
                    tweet_mode='extended'
                )
                
                for tweet in tweets:
                    if tweet.id_str not in self.processed_ids:
                        await self.process_tweet(tweet)
                        self.processed_ids.add(tweet.id_str)
            
            # Clean up processed IDs
            if len(self.processed_ids) > 10000:
                self.processed_ids = set(list(self.processed_ids)[-5000:])
                
        except Exception as e:
            self.logger.error(f"Error searching tweets: {e}")
    
    async def process_tweet(self, tweet):
        """Process individual tweet"""
        try:
            # Extract tweet text
            if hasattr(tweet, 'full_text'):
                text = tweet.full_text
            else:
                text = tweet.text
            
            # Check if should flag
            if self.should_flag_post(text):
                # Extract tweet data
                tweet_data = {
                    'source_type': 'social_media',
                    'platform': 'twitter',
                    'timestamp': datetime.now().isoformat(),
                    'post_data': {
                        'id': tweet.id_str,
                        'text': text,
                        'user_id': tweet.user.id_str,
                        'username': tweet.user.screen_name,
                        'user': {
                            'id': tweet.user.id_str,
                            'screen_name': tweet.user.screen_name,
                            'followers_count': tweet.user.followers_count,
                            'friends_count': tweet.user.friends_count,
                            'created_at': tweet.user.created_at.isoformat(),
                            'verified': tweet.user.verified,
                            'statuses_count': tweet.user.statuses_count
                        },
                        'created_at': tweet.created_at.isoformat(),
                        'retweet_count': tweet.retweet_count,
                        'favorite_count': tweet.favorite_count,
                        'in_reply_to_status_id': tweet.in_reply_to_status_id_str,
                        'coordinates': tweet.coordinates,
                        'place': tweet.place.full_name if tweet.place else None
                    },
                    'text': text
                }
                
                # Add to output queue
                await self.output_queue.put(tweet_data)
                
                self.logger.info(f"Flagged tweet from @{tweet.user.screen_name}")
                
        except Exception as e:
            self.logger.error(f"Error processing tweet: {e}")
    
    async def stop(self):
        """Stop Twitter monitoring"""
        await super().stop()
        
        if self.stream:
            self.stream.disconnect()
        
        self.logger.info("Twitter Monitor stopped")


class TwitterStreamListener(tweepy.StreamListener):
    """Custom Twitter stream listener"""
    
    def __init__(self, output_queue: asyncio.Queue, monitor: TwitterMonitor):
        """Initialize stream listener"""
        super().__init__()
        self.output_queue = output_queue
        self.monitor = monitor
        self.logger = logging.getLogger('TwitterStreamListener')
    
    def on_status(self, status):
        """Handle new tweet"""
        # Process tweet asynchronously
        asyncio.create_task(self.monitor.process_tweet(status))
        return True
    
    def on_error(self, status_code):
        """Handle errors"""
        self.logger.error(f"Twitter streaming error: {status_code}")
        if status_code == 420:
            # Rate limited
            return False
        return True


class TelegramMonitor(SocialMediaMonitor):
    """Monitor Telegram for threats"""
    
    def __init__(self, config: Dict, output_queue: asyncio.Queue):
        """Initialize Telegram monitor"""
        super().__init__(config, output_queue)
        
        self.bot = None
        self.monitored_channels = config.get('monitored_channels', [])
        self.monitored_groups = config.get('monitored_groups', [])
    
    async def start(self):
        """Start Telegram monitoring"""
        self.logger.info("Starting Telegram Monitor...")
        self.running = True
        
        # Initialize bot
        bot_token = self.config.get('bot_token')
        if not bot_token:
            self.logger.error("Telegram bot token not configured")
            return
        
        try:
            self.bot = Bot(token=bot_token)
            
            # Start monitoring channels
            asyncio.create_task(self.monitor_channels())
            
            self.logger.info("Telegram Monitor started")
            
        except Exception as e:
            self.logger.error(f"Failed to start Telegram monitor: {e}")
    
    async def monitor_channels(self):
        """Monitor Telegram channels"""
        while self.running:
            try:
                for channel_id in self.monitored_channels:
                    await self.check_channel_messages(channel_id)
                
                for group_id in self.monitored_groups:
                    await self.check_group_messages(group_id)
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error monitoring Telegram: {e}")
                await asyncio.sleep(60)
    
    async def check_channel_messages(self, channel_id: str):
        """Check messages in a Telegram channel"""
        try:
            # Get recent messages
            # Note: This is simplified - actual implementation would need proper Telegram API integration
            updates = await self.bot.get_updates()
            
            for update in updates:
                if update.message and update.message.chat.id == channel_id:
                    await self.process_telegram_message(update.message)
                    
        except Exception as e:
            self.logger.error(f"Error checking channel {channel_id}: {e}")
    
    async def check_group_messages(self, group_id: str):
        """Check messages in a Telegram group"""
        # Similar to channel checking
        await self.check_channel_messages(group_id)
    
    async def process_telegram_message(self, message):
        """Process Telegram message"""
        try:
            text = message.text or message.caption or ''
            
            if not text:
                return
            
            # Check if should flag
            if self.should_flag_post(text):
                # Extract message data
                message_data = {
                    'source_type': 'social_media',
                    'platform': 'telegram',
                    'timestamp': datetime.now().isoformat(),
                    'post_data': {
                        'id': str(message.message_id),
                        'text': text,
                        'chat': {
                            'id': str(message.chat.id),
                            'type': message.chat.type,
                            'title': getattr(message.chat, 'title', None),
                            'username': getattr(message.chat, 'username', None)
                        },
                        'from_user': {
                            'id': str(message.from_user.id) if message.from_user else None,
                            'username': message.from_user.username if message.from_user else None,
                            'first_name': message.from_user.first_name if message.from_user else None
                        },
                        'date': message.date.isoformat(),
                        'forward_from': getattr(message, 'forward_from', None),
                        'forward_date': getattr(message, 'forward_date', None)
                    },
                    'text': text
                }
                
                # Add to output queue
                await self.output_queue.put(message_data)
                
                self.logger.info(f"Flagged Telegram message from chat {message.chat.id}")
                
        except Exception as e:
            self.logger.error(f"Error processing Telegram message: {e}")
    
    async def stop(self):
        """Stop Telegram monitoring"""
        await super().stop()
        self.logger.info("Telegram Monitor stopped")


class FacebookMonitor(SocialMediaMonitor):
    """Monitor Facebook for threats (simplified implementation)"""
    
    def __init__(self, config: Dict, output_queue: asyncio.Queue):
        """Initialize Facebook monitor"""
        super().__init__(config, output_queue)
        self.access_token = config.get('access_token')
        self.monitored_pages = config.get('monitored_pages', [])
    
    async def start(self):
        """Start Facebook monitoring"""
        if not self.access_token:
            self.logger.error("Facebook access token not configured")
            return
        
        self.logger.info("Starting Facebook Monitor...")
        self.running = True
        
        # Start monitoring loop
        asyncio.create_task(self.monitor_loop())
    
    async def monitor_loop(self):
        """Monitor Facebook pages"""
        while self.running:
            try:
                for page_id in self.monitored_pages:
                    await self.check_page_posts(page_id)
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error monitoring Facebook: {e}")
                await asyncio.sleep(60)
    
    async def check_page_posts(self, page_id: str):
        """Check posts on a Facebook page"""
        try:
            # Facebook Graph API endpoint
            url = f"https://graph.facebook.com/v12.0/{page_id}/posts"
            params = {
                'access_token': self.access_token,
                'fields': 'id,message,created_time,from',
                'limit': 25
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for post in data.get('data', []):
                            if post['id'] not in self.processed_ids:
                                await self.process_facebook_post(post)
                                self.processed_ids.add(post['id'])
                    else:
                        self.logger.error(f"Facebook API error: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Error checking Facebook page {page_id}: {e}")
    
    async def process_facebook_post(self, post):
        """Process Facebook post"""
        try:
            text = post.get('message', '')
            
            if not text:
                return
            
            # Check if should flag
            if self.should_flag_post(text):
                # Extract post data
                post_data = {
                    'source_type': 'social_media',
                    'platform': 'facebook',
                    'timestamp': datetime.now().isoformat(),
                    'post_data': post,
                    'text': text
                }
                
                # Add to output queue
                await self.output_queue.put(post_data)
                
                self.logger.info(f"Flagged Facebook post {post['id']}")
                
        except Exception as e:
            self.logger.error(f"Error processing Facebook post: {e}")
    
    async def stop(self):
        """Stop Facebook monitoring"""
        await super().stop()
        self.logger.info("Facebook Monitor stopped")