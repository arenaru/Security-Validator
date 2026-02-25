# Security Validator (SecVal)

A comprehensive web application vulnerability scanner built with Streamlit, designed to perform automated security assessments on web applications.

## Quick Start (For Your Friend)

```bash
# 1. Install Docker Desktop (if not already installed)
# Download from: https://www.docker.com/products/docker-desktop/

# 2. Clone this repository
git clone https://github.com/arenaru/Security-Validator.git
cd Security-Validator

# 3. Run with Docker Compose (everything bundled)
docker-compose up -d

# 4. Open browser
# Go to: http://localhost:8501

# 5. Start scanning!
```

That's it! No Python, no nmap installation needed. Docker handles everything.

## Features

### Vulnerability Detection Modules

- **SSL/TLS Certificate Validation**
  - Certificate expiry checking
  - Hostname mismatch detection
  - Self-signed certificate detection
  
- **Protocol Security Checks**
  - SSLv3 detection
  - TLS 1.0 detection
  - TLS 1.1 detection
  
- **Security Headers Analysis**
  - HSTS (HTTP Strict Transport Security)
  - X-Frame-Options
  - X-Content-Type-Options
  - Content-Security-Policy
  - Referrer-Policy
  
- **Cookie Security**
  - Secure flag validation
  - HTTPOnly flag checking
  
- **Framework Vulnerability Detection**
  - Laravel Debug Mode exposure
  - Node.js Debug Mode detection
  - PHP Version disclosure

### Key Capabilities

- **Multi-target scanning** - Scan multiple domains/IPs simultaneously
- **Parallel execution** - Concurrent scanning for faster results
- **Interactive UI** - Card-based result visualization
- **Report generation** - Export findings to XLSX format
- **Customizable scans** - Select specific modules to run

## Installation

### Prerequisites

- Python 3.11+
- nmap (for SSL/TLS protocol detection)
- bash (for cookie security checks)

### Local Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/arenaru/Security-Validator.git
   cd Security-Validator
   ```

2. **Create virtual environment**
   ```bash
   python -m venv myenv
   
   # Windows
   myenv\Scripts\activate
   
   # Linux/Mac
   source myenv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install system dependencies**
   
   **Windows:**
   - Download and install [Nmap](https://nmap.org/download.html)
   - Install Git Bash or WSL for bash script support
   
   **Linux/Mac:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get install nmap
   
   # macOS
   brew install nmap
   ```

## Usage

### Running the Application

```bash
streamlit run app.py
```

Access the application at `http://localhost:8501`

### Scanning Workflow

1. **Select Scan Modules**
   - Use the sidebar to choose which security checks to perform
   - Enable "Choose All" to select all modules

2. **Enter Targets**
   - Add target URLs or IP addresses (one per line)
   - Examples:
     ```
     example.com
     192.168.1.1
     https://target.tld
     ```

3. **Run Scan**
   - Click "🚀 Run Scan"
   - Wait for results to appear in card format

4. **Export Results**
   - Click "📥 Download XLSX Report"
   - Opens a comprehensive Excel report with findings

## Sharing with Others

The easiest way to share this tool with friends/colleagues:

### Option 1: Share the Repository (Recommended)

```bash
# Your friend clones the repo
git clone https://github.com/arenaru/Security-Validator.git
cd Security-Validator

# Run with Docker (easiest - no manual setup needed)
docker-compose up -d

# Access at http://localhost:8501
```

### Option 2: Docker Image Distribution

```bash
# You: Build and save the image
docker build -t secval:latest .
docker save secval:latest -o secval-image.tar

# Share the .tar file with your friend

# Friend: Load and run the image
docker load -i secval-image.tar
docker run -d -p 8501:8501 --name secval-app secval:latest
```

## Docker Deployment

**Why Docker?** This tool requires `nmap` for SSL/TLS scanning. Cloud platforms like Vercel, Streamlit Cloud, and Heroku don't support nmap or system package installations. Docker bundles all dependencies (Python + nmap) in one container.

### Quick Start with Docker Compose (Recommended)

```bash
# Clone and run
git clone https://github.com/arenaru/Security-Validator.git
cd Security-Validator
docker-compose up -d

# Access at http://localhost:8501
```

The `docker-compose.yml` file is already included in the repository.

### Manual Docker Build

```bash
# Build the image
docker build -t secval:latest .

# Run the container
docker run -d -p 8501:8501 --name secval-app secval:latest

# Access at http://localhost:8501
```

### Management Commands

```bash
# View logs
docker logs -f secval-app

# Stop/Start
docker stop secval-app
docker start secval-app

# Rebuild after changes
docker build -t secval:latest . --no-cache
docker-compose up -d --build
```

## Deployment Options

### ✅ Supported Platforms

- **Docker** (Recommended) - Full feature support including nmap
- **Self-hosted VPS/Server** (Linux) - Install Python + nmap manually
- **Local Machine** - Development and testing

### ❌ Unsupported Platforms

- **Vercel** - No system package support (nmap unavailable)
- **Streamlit Cloud** - No nmap support
- **Heroku** - Limited system package support
- **Netlify** - Static hosting only

**Why these platforms don't work:** SSLv3/TLS detection modules require `nmap`, which needs system-level installation. Most serverless/PaaS platforms don't allow custom system packages.

## Project Structure

```
SecVal/
├── app.py                      # Main Streamlit application
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker configuration
├── docker-compose.yml          # Docker Compose setup
├── .dockerignore              # Docker build exclusions
├── components/                # UI component modules
│   ├── ui_ssl.py
│   ├── ui_hsts.py
│   ├── ui_cookie.py
│   ├── ui_header.py
│   ├── ui_laravel.py
│   ├── ui_nodejs.py
│   ├── ui_phpversion.py
│   ├── ui_sslv3.py
│   ├── ui_tlsv10.py
│   └── ui_tlsv11.py
├── script/                    # Scanning engine scripts
│   ├── certifExpired.py      # SSL certificate checker
│   ├── hstsChecker.py        # HSTS scanner
│   ├── headerCheck.py        # Security headers validator
│   ├── check_secure.sh       # Cookie security (bash)
│   ├── laravelCheck.py       # Laravel debug detector
│   ├── nodeDebug.py          # Node.js debug detector
│   ├── phpVersion.py         # PHP version disclosure
│   ├── sslv3.py              # SSLv3 detection
│   ├── tlsv10.py             # TLS 1.0 detection
│   └── tlsv11.py             # TLS 1.1 detection
├── utils/                     # Utility modules
│   ├── scanner_engine.py     # Core scanning orchestrator
│   ├── scraper.py            # Acunetix DB scraper
│   ├── acunetix_vulnerabilities.json
│   └── burp_vulnerabilities.json
└── static/                    # CSS styles
    └── style.css
```

## Technologies Used

- **Streamlit** - Web UI framework
- **Pandas** - Data manipulation & Excel export
- **Requests** - HTTP client
- **BeautifulSoup4** - HTML parsing
- **OpenPyXL** - Excel file generation
- **Nmap** - SSL/TLS protocol scanning
- **Python SSL** - Certificate validation

## Configuration

### Timeout Settings

Edit timeout values in individual scanner scripts:
- HSTS: `_HSTS_TIMEOUT = 10` in `script/hstsChecker.py`
- SSL: `timeout=5` in `script/certifExpired.py`

### Thread Pool

Adjust concurrent workers in `script/hstsChecker.py`:
```python
_HSTS_THREADS = 20  # Modify this value
```

## Security Considerations

- **Target Authorization** - Only scan systems you have permission to test
- **Rate Limiting** - Aggressive scanning may trigger security controls
- **Network Access** - Container needs network permissions for external scans
- **SSL Verification** - Disabled by default for testing; enable in production

## Troubleshooting

### Common Issues

**Nmap not found:**
```bash
# Ensure nmap is in PATH
nmap --version

# Windows: Add C:\Program Files (x86)\Nmap to PATH
```

**Bash script errors:**
```bash
# Windows: Ensure Git Bash or WSL is installed
# Verify bash availability
where bash
```

**Permission denied:**
```bash
# Linux: Make scripts executable
chmod +x script/*.sh
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open a Pull Request

## License

This project is for educational and authorized security testing purposes only.

## Disclaimer

This tool is provided for security research and testing purposes. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized scanning may be illegal in your jurisdiction.

## Author

**arenaru**

GitHub: [https://github.com/arenaru/Security-Validator](https://github.com/arenaru/Security-Validator)

---

**Last Updated:** February 2026
