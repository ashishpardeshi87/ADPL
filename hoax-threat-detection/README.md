# Hoax Threat Detection System

## Overview

The Hoax Threat Detection System is a comprehensive solution for identifying and tracking individuals responsible for hoax bomb threats using digital communication channels. It leverages advanced data mining, natural language processing, and digital forensics to detect threatening language, trace sender metadata, and analyze communication patterns.

## Features

### Core Capabilities

- **Real-time Threat Detection**: Monitors multiple communication channels simultaneously
- **Natural Language Processing**: Automatically detects threatening language patterns
- **Metadata Extraction**: Extracts and analyzes sender information from communications
- **Device Fingerprinting**: Tracks devices across sessions even with anonymization attempts
- **Behavioral Profiling**: Analyzes communication patterns to identify individuals
- **Investigation Dashboard**: User-friendly interface for law enforcement

### Key Components

1. **Threat Detection Engine**
   - NLP-based threat analysis
   - Pattern matching and keyword detection
   - Urgency and credibility assessment
   - Multi-level threat classification

2. **Metadata Analysis**
   - IP tracking and geolocation
   - Email header analysis
   - Social media metadata extraction
   - Device information collection

3. **Device Fingerprinting**
   - Canvas fingerprinting
   - WebGL fingerprinting
   - Browser attribute tracking
   - Cross-session device linking

4. **Behavioral Profiling**
   - Writing style analysis
   - Temporal pattern detection
   - Communication pattern analysis
   - Profile linking and matching

5. **Real-time Monitoring**
   - Email monitoring
   - Social media monitoring (Twitter, Telegram, Facebook)
   - WebSocket-based live updates
   - Automated alert generation

6. **Investigation Dashboard**
   - Real-time threat feed
   - Threat analysis tools
   - Device tracking interface
   - Report generation

## Installation

### Prerequisites

- Python 3.8 or higher
- PostgreSQL database
- Redis server
- Git

### Setup Instructions

1. **Clone the repository**
```bash
git clone https://github.com/your-org/hoax-threat-detection.git
cd hoax-threat-detection
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Download NLP models**
```bash
python -m spacy download en_core_web_sm
python -m spacy download en_core_web_lg
python -m nltk.downloader all
```

5. **Configure the system**
```bash
cp config/config.yaml.example config/config.yaml
# Edit config/config.yaml with your settings
```

6. **Set up the database**
```bash
# Create PostgreSQL database
createdb threat_detection

# Run migrations (if using alembic)
alembic upgrade head
```

7. **Start Redis server**
```bash
redis-server
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Database
DB_PASSWORD=your_database_password

# API Keys
TWITTER_API_KEY=your_twitter_api_key
TWITTER_API_SECRET=your_twitter_api_secret
TWITTER_ACCESS_TOKEN=your_twitter_access_token
TWITTER_ACCESS_TOKEN_SECRET=your_twitter_access_token_secret

TELEGRAM_BOT_TOKEN=your_telegram_bot_token

FACEBOOK_APP_ID=your_facebook_app_id
FACEBOOK_APP_SECRET=your_facebook_app_secret

# Security
JWT_SECRET=your_jwt_secret_key

# Email Monitoring
EMAIL_USERNAME=monitoring@example.com
EMAIL_PASSWORD=your_email_password
```

### Configuration File

Edit `config/config.yaml` to customize:
- Threat detection thresholds
- Monitoring settings
- API endpoints
- Security settings
- Compliance requirements

## Usage

### Starting the System

**Run both monitoring and dashboard:**
```bash
python main.py --mode both
```

**Run monitoring only:**
```bash
python main.py --mode monitor
```

**Run dashboard only:**
```bash
python main.py --mode dashboard
```

### Command Line Options

```bash
python main.py --help

Options:
  --mode {monitor,dashboard,both}  Run mode
  --config CONFIG                   Path to configuration file
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}  Logging level
```

### Accessing the Dashboard

Once started, access the dashboard at:
```
http://localhost:8501
```

### API Endpoints

The system provides REST API endpoints for integration:

- `GET /api/threats` - List recent threats
- `POST /api/analyze` - Analyze text for threats
- `GET /api/device/{id}` - Get device information
- `GET /api/profile/{id}` - Get behavioral profile
- `POST /api/alert` - Create manual alert

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   User Interface Layer                   │
│                  (Streamlit Dashboard)                   │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                    API/WebSocket Layer                   │
│                    (FastAPI/WebSocket)                   │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                   Processing Layer                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │  Threat  │ │ Metadata │ │  Device  │ │Behavioral│  │
│  │ Detection│ │Extraction│ │Fingerprt │ │ Profiling│  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                   Monitoring Layer                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │  Email   │ │ Twitter  │ │ Telegram │ │ Facebook │  │
│  │ Monitor  │ │ Monitor  │ │ Monitor  │ │ Monitor  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                     Storage Layer                        │
│         PostgreSQL        Redis        MongoDB           │
└─────────────────────────────────────────────────────────┘
```

## Security and Compliance

### Security Features

- **Encryption**: AES-256 encryption for sensitive data
- **Authentication**: JWT-based authentication
- **Access Control**: Role-based access control (RBAC)
- **Rate Limiting**: API rate limiting to prevent abuse
- **Input Sanitization**: Protection against injection attacks
- **Audit Logging**: Comprehensive audit trail

### Compliance

- **GDPR Compliant**: Data anonymization and retention policies
- **Data Protection**: Secure storage and transmission
- **Legal Compliance**: Configurable for different jurisdictions
- **Privacy Protection**: PII anonymization capabilities

### Best Practices

1. **Regular Updates**: Keep all dependencies updated
2. **Secure Configuration**: Use strong passwords and API keys
3. **Network Security**: Use HTTPS/TLS for all communications
4. **Access Control**: Limit access to authorized personnel only
5. **Data Backup**: Regular backup of threat intelligence data

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_threat_detector.py
```

### Test Categories

- Unit tests for core modules
- Integration tests for monitoring systems
- End-to-end tests for threat detection pipeline
- Security tests for authentication and authorization

## Deployment

### Docker Deployment

```bash
# Build Docker image
docker build -t hoax-threat-detection .

# Run with Docker Compose
docker-compose up -d
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n threat-detection
```

### Production Considerations

1. **Scalability**: Use load balancers for high traffic
2. **High Availability**: Deploy across multiple availability zones
3. **Monitoring**: Implement application monitoring (Prometheus/Grafana)
4. **Backup**: Regular database backups
5. **Security**: Regular security audits and penetration testing

## Troubleshooting

### Common Issues

**Issue**: Dashboard not loading
```bash
# Check if Streamlit is running
ps aux | grep streamlit

# Restart dashboard
streamlit run src/dashboard/app.py
```

**Issue**: Monitoring not detecting threats
```bash
# Check Redis connection
redis-cli ping

# Check monitoring logs
tail -f logs/threat_detection.log
```

**Issue**: Database connection errors
```bash
# Check PostgreSQL status
pg_isready

# Check database credentials in config
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Email: support@threatdetection.example.com
- Documentation: https://docs.threatdetection.example.com
- Issues: https://github.com/your-org/hoax-threat-detection/issues

## Acknowledgments

- NLP models powered by spaCy and Transformers
- Dashboard built with Streamlit
- Real-time processing with AsyncIO
- Machine learning with scikit-learn

## Disclaimer

This system is designed for authorized law enforcement use only. Ensure compliance with all applicable laws and regulations in your jurisdiction before deployment.