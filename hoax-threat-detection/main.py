"""
Hoax Threat Detection System - Main Application
Entry point for the threat detection system
"""

import asyncio
import argparse
import logging
import sys
import yaml
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / 'src'))

from monitoring.realtime_processor import RealtimeProcessor
from dashboard.app import main as run_dashboard


def setup_logging(level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/threat_detection.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('HoaxThreatDetection')


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file"""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


async def start_monitoring(config: dict):
    """Start the real-time monitoring system"""
    processor = RealtimeProcessor(config)
    await processor.start()


def start_dashboard():
    """Start the investigator dashboard"""
    import subprocess
    subprocess.run([sys.executable, "-m", "streamlit", "run", "src/dashboard/app.py"])


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Hoax Threat Detection System')
    parser.add_argument(
        '--mode',
        choices=['monitor', 'dashboard', 'both'],
        default='both',
        help='Run mode: monitor (real-time monitoring), dashboard (web interface), or both'
    )
    parser.add_argument(
        '--config',
        default='config/config.yaml',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Logging level'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    
    # Create logs directory if it doesn't exist
    Path('logs').mkdir(exist_ok=True)
    
    # Load configuration
    try:
        config = load_config(args.config)
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Start services based on mode
    if args.mode == 'monitor':
        logger.info("Starting monitoring system...")
        try:
            asyncio.run(start_monitoring(config))
        except KeyboardInterrupt:
            logger.info("Monitoring system stopped by user")
    
    elif args.mode == 'dashboard':
        logger.info("Starting dashboard...")
        start_dashboard()
    
    elif args.mode == 'both':
        logger.info("Starting both monitoring and dashboard...")
        
        # Start monitoring in background
        import threading
        monitor_thread = threading.Thread(
            target=lambda: asyncio.run(start_monitoring(config)),
            daemon=True
        )
        monitor_thread.start()
        
        # Start dashboard in foreground
        start_dashboard()
    
    logger.info("Application terminated")


if __name__ == "__main__":
    main()