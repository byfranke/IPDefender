# Security Policy

## 🔒 Security Overview

IPDefender Pro takes security seriously. This document outlines our security practices and how to report security vulnerabilities.

## 🚨 Reporting Security Vulnerabilities

If you discover a security vulnerability in IPDefender Pro, please report it responsibly:

### Preferred Reporting Methods

1. **GitHub Security Advisory** (Recommended)
   - Go to the [Security tab](https://github.com/byfranke/IPDefender/security) in this repository
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Direct Contact**
   - **Website**: Contact form at [byfranke.com](https://byfranke.com/#Contact)
   - **Email**: Use the contact information available on the website

### What to Include in Your Report

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fix (if available)
- Your contact information for follow-up

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix Development**: Based on severity (Critical: 24-72h, High: 1-2 weeks)
- **Public Disclosure**: After fix is released and users have time to update

## 🛡️ Security Best Practices

### For Users

#### 1. Configuration Security

```yaml
# ✅ DO: Use environment variables
api_key: "${VIRUSTOTAL_API_KEY}"

# ❌ DON'T: Hardcode secrets
api_key: "abc123xyz789"
```

#### 2. File Permissions

```bash
# Set secure permissions on configuration files
chmod 600 /opt/ipdefender/config/config.yaml
chmod 700 /opt/ipdefender/config/

# Ensure log directory permissions
chmod 755 /var/log/ipdefender/
```

#### 3. API Key Management

- **Rotate API keys regularly** (every 90 days)
- **Use least privilege** - only grant necessary permissions
- **Monitor API usage** - watch for unusual activity
- **Never commit API keys** to version control

#### 4. Network Security

```yaml
# Bind to localhost only if not serving external requests
api:
  host: "127.0.0.1"  # Instead of "0.0.0.0"
  
# Use strong API keys (minimum 32 characters)
authentication:
  api_keys:
    - "your-very-long-secure-random-api-key-here-32chars+"
```

#### 5. Database Security

```yaml
# Use PostgreSQL with SSL in production
database:
  url: "postgresql://user:pass@host:5432/db?sslmode=require"
```

### For Developers

#### 1. Input Validation

- All user inputs must be validated using Pydantic models
- Sanitize data before database operations
- Use parameterized queries to prevent SQL injection

#### 2. Authentication & Authorization

- Implement proper API key validation
- Use rate limiting to prevent abuse
- Log all authentication attempts

#### 3. Error Handling

- Never expose sensitive information in error messages
- Log detailed errors securely for debugging
- Return generic error messages to clients

#### 4. Dependencies

- Keep all dependencies up to date
- Regularly audit dependencies for vulnerabilities
- Use tools like `safety` and `bandit` for security scanning

## 🔍 Security Features

### Built-in Security Measures

1. **Input Validation**
   - Pydantic model validation for all inputs
   - IP address format validation
   - Request size limitations

2. **Rate Limiting**
   - Configurable request limits per IP
   - Burst protection
   - Automatic blocking of abusive clients

3. **Audit Logging**
   - All security-relevant events logged
   - Structured logging format
   - Log rotation and retention policies

4. **Secure Configuration**
   - Environment variable support
   - Configuration validation
   - Secure defaults

5. **Database Security**
   - SQLAlchemy ORM to prevent SQL injection
   - Connection pooling with limits
   - Encrypted connections support

### Security Headers

The API server automatically includes security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
```

## 🔐 Deployment Security

### Production Checklist

- [ ] Change all default passwords and API keys
- [ ] Enable SSL/TLS for all connections
- [ ] Configure proper file permissions
- [ ] Set up log monitoring and alerting
- [ ] Enable audit logging
- [ ] Configure firewall rules
- [ ] Regular security updates
- [ ] Monitor for suspicious activity

### Environment Variables

Use environment variables for sensitive configuration:

```bash
export VIRUSTOTAL_API_KEY="your-api-key"
export ABUSEIPDB_API_KEY="your-api-key"
export CLOUDFLARE_TOKEN="your-token"
export POSTGRES_PASSWORD="your-db-password"
```

### Docker Security

If using Docker:

```bash
# Run as non-root user
docker run --user 1000:1000 ipdefender

# Use secrets for sensitive data
docker run --secret virustotal_key ipdefender

# Limit resources
docker run --memory=512m --cpus=1 ipdefender
```

## 📊 Security Monitoring

### Metrics to Monitor

- Failed authentication attempts
- Unusual API usage patterns
- High error rates
- Memory and CPU usage spikes
- Database connection failures

### Log Analysis

Monitor these log patterns:

```bash
# Failed API authentication
grep "Authentication failed" /var/log/ipdefender/ipdefender.log

# Rate limit violations
grep "Rate limit exceeded" /var/log/ipdefender/ipdefender.log

# High-severity threats
grep "CRITICAL\|ERROR" /var/log/ipdefender/ipdefender.log
```

## 🔄 Security Updates

### Vulnerability Disclosure Process

1. **Discovery** - Vulnerability identified and verified
2. **Assessment** - Impact and severity evaluation
3. **Development** - Fix development and testing
4. **Testing** - Security fix validation
5. **Release** - Patched version release
6. **Notification** - User notification and advisory publication
7. **Disclosure** - Public vulnerability disclosure (if applicable)

### Update Notifications

Stay informed about security updates:

- Watch this repository for releases
- Subscribe to security advisories
- Follow [@byfrankesec](https://www.youtube.com/@byfrankesec) for updates

## 🛠️ Security Testing

### Automated Security Scanning

We recommend running these tools regularly:

```bash
# Python security linter
bandit -r src/

# Dependency vulnerability scanner
safety check

# Code quality and security
prospector src/

# Static analysis
pylint src/
```

### Manual Security Testing

- API endpoint testing with invalid inputs
- Rate limiting validation
- Authentication bypass attempts
- SQL injection testing
- Cross-site scripting (XSS) testing

## 📞 Contact

For security-related questions or concerns:

- **Security Issues**: Use GitHub Security Advisory or contact via [byfranke.com](https://byfranke.com/#Contact)
- **General Questions**: GitHub Issues or Discussions
- **Documentation**: Check the `/Documentation` folder

---

## 🏆 Acknowledgments

We appreciate responsible security researchers who help make IPDefender Pro more secure. Contributors who report valid security vulnerabilities will be acknowledged in our security advisories (with their permission).

---

<div align="center">

**🔒 Security is a shared responsibility 🔒**

*Help us keep IPDefender Pro secure for everyone*

</div>
