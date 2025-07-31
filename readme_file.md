# Website Security Scanner 🔒

A comprehensive web application that performs automated security assessments of websites using Selenium WebDriver and Flask. This tool provides real-time URL safety checks, vulnerability scanning, and generates detailed security reports with screenshots.

## 🌟 Features

### Real-time URL Security Check
- **HTTPS Validation**: Ensures websites use secure connections
- **SSL/TLS Certificate Analysis**: Verifies certificate validity and expiration
- **Security Headers Assessment**: Checks for essential security headers (HSTS, CSP, X-Frame-Options, etc.)
- **Risk Level Classification**: Categorizes websites as Low, Medium, or High risk

### Automated Security Scanning
- **Screenshot Capture**: Takes full-page screenshots of target websites
- **Vulnerability Detection**: Identifies common security vulnerabilities
- **Sensitive File Detection**: Checks for exposed sensitive files (robots.txt, .env, .git/config)
- **Comprehensive Reporting**: Generates detailed Word documents with findings

### Report Generation & Notification
- **Professional Reports**: Creates formatted Word documents with screenshots and analysis
- **Email Integration**: Automatically sends reports via email
- **Timestamp Management**: Organizes reports with timestamps for tracking

## 🛠️ Technology Stack

- **Backend**: Python Flask
- **Web Automation**: Selenium WebDriver
- **Document Generation**: python-docx
- **Email Service**: SMTP (Gmail)
- **Frontend**: HTML5, CSS3, JavaScript
- **Security Analysis**: SSL, Requests library
- **Cross-Origin Support**: Flask-CORS

## 📋 Prerequisites

Before running this application, ensure you have:

- Python 3.7 or higher
- Chrome browser installed
- ChromeDriver executable
- Gmail account for email notifications (with app password)

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/website-security-scanner.git
   cd website-security-scanner
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv project_env
   source project_env/bin/activate  # On Windows: project_env\Scripts\activate
   ```

3. **Install required packages**
   ```bash
   pip install flask flask-cors selenium requests python-docx
   ```

4. **Download ChromeDriver**
   - Download from [ChromeDriver Downloads](https://chromedriver.chromium.org/)
   - Extract and note the path to chromedriver.exe

5. **Configure the application**
   - Update `chromedriver_path` in the code with your ChromeDriver location
   - Update `output_dir` for screenshot storage
   - Configure email credentials (use app passwords for Gmail)

## ⚙️ Configuration

Update the following variables in `combine.py`:

```python
# ChromeDriver path
chromedriver_path = r"path/to/your/chromedriver.exe"

# Screenshot output directory
output_dir = r"path/to/screenshots/folder"

# Email configuration
from_email = "your-email@gmail.com"
password = "your-app-password"  # Use Gmail app password
to_email = "recipient@gmail.com"

# Target URLs for bulk scanning
urls = [
    "https://example1.com",
    "https://example2.com",
    # Add more URLs as needed
]
```

## 🏃‍♂️ Usage

1. **Start the application**
   ```bash
   python combine.py
   ```

2. **Access the web interface**
   - Open your browser and navigate to `http://localhost:5000`

3. **Check individual URLs**
   - Enter a URL in the input field
   - Click "Check URL" to get immediate security assessment
   - View safety status, reasons, and recommendations

4. **Generate comprehensive reports**
   - Click "Generate Report" to scan all configured URLs
   - Screenshots and security analysis will be compiled into a Word document
   - Report will be automatically emailed to the configured recipient

## 🔍 Security Checks Performed

### URL Validation
- ✅ URL format validation
- ✅ HTTPS implementation check
- ✅ SSL/TLS certificate verification
- ✅ Certificate expiration monitoring

### Security Headers Analysis
- ✅ Strict-Transport-Security (HSTS)
- ✅ X-Content-Type-Options
- ✅ X-Frame-Options
- ✅ Content-Security-Policy (CSP)

### Vulnerability Detection
- ✅ Exposed sensitive files
- ✅ SSL/TLS configuration issues
- ✅ Missing security configurations
- ✅ Connection security assessment

## 📁 Project Structure

```
website-security-scanner/
│
├── combine.py                 # Main application file
├── Screenshots/              # Generated screenshots directory
├── website_report.docx       # Generated security reports
├── requirements.txt          # Python dependencies
└── README.md                # Project documentation
```

## 🔒 Security Considerations

- **Email Credentials**: Use app passwords instead of regular passwords
- **SSL Verification**: The tool temporarily disables SSL verification for testing
- **Rate Limiting**: Implement rate limiting for production use
- **Input Validation**: URLs are validated before processing

## 🚨 Important Notes

- **ChromeDriver**: Ensure ChromeDriver version matches your Chrome browser version
- **Email Configuration**: Gmail requires app passwords for SMTP authentication
- **Path Separators**: Use raw strings (r"") for Windows file paths
- **Firewall**: Ensure ports 5000 and 587 (SMTP) are not blocked

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Known Issues

- Chrome browser must be installed for Selenium WebDriver
- Email sending requires proper Gmail app password configuration
- Large websites may take longer to load and screenshot

## 🔮 Future Enhancements

- [ ] Support for multiple browser engines
- [ ] Database integration for historical reports
- [ ] REST API for programmatic access
- [ ] Dashboard for monitoring multiple websites
- [ ] Scheduled scanning capabilities
- [ ] Integration with security vulnerability databases

## 📞 Support

If you encounter any issues or have questions:
1. Check the [Issues](https://github.com/yourusername/website-security-scanner/issues) page
2. Create a new issue with detailed information
3. Include error messages and system information

---

**⚠️ Disclaimer**: This tool is for educational and legitimate security testing purposes only. Always ensure you have proper authorization before scanning websites you don't own.