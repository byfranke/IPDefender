# Contributing to IPDefender Pro

Thank you for your interest in contributing to IPDefender Pro! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Types of Contributions

We welcome various types of contributions:

- 🐛 **Bug Reports** - Help us identify and fix issues
- 💡 **Feature Requests** - Suggest new functionality
- 🔧 **Code Contributions** - Bug fixes and new features
- 📖 **Documentation** - Improve or add documentation
- 🧪 **Testing** - Help test new features and find bugs
- 🔌 **Plugins** - Develop new threat intelligence or firewall providers

### Getting Started

1. **Fork the Repository**
   ```bash
   # Fork the repo on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/IPDefender.git
   cd IPDefender
   ```

2. **Set Up Development Environment**
   ```bash
   # Create virtual environment
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   cd IPDefender
   pip install -r requirements.txt
   
   # Install development dependencies
   pip install pytest pytest-cov black isort pylint bandit
   ```

3. **Create a Branch**
   ```bash
   # Create a feature branch
   git checkout -b feature/your-feature-name
   # or for bug fixes
   git checkout -b fix/bug-description
   ```

## 🔍 Development Guidelines

### Code Style

We use Python best practices and tools to maintain code quality:

```bash
# Format code with Black
black src/ tests/

# Sort imports with isort
isort src/ tests/

# Lint with pylint
pylint src/

# Security check with bandit
bandit -r src/
```

### Code Standards

- **Python Version**: 3.8+ compatibility required
- **Type Hints**: Use type hints for all function parameters and returns
- **Docstrings**: Follow Google-style docstrings
- **Error Handling**: Proper exception handling with logging
- **Testing**: Write tests for new functionality

### Example Code Structure

```python
"""Module docstring describing the purpose."""

from typing import Optional, List, Dict
import logging
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class ThreatProvider(BaseModel):
    """Example class with proper documentation.
    
    Args:
        name: The provider name
        api_key: API key for authentication
        enabled: Whether the provider is enabled
    """
    
    name: str
    api_key: str
    enabled: bool = True
    
    async def analyze_ip(self, ip_address: str) -> Optional[Dict]:
        """Analyze an IP address for threats.
        
        Args:
            ip_address: The IP address to analyze
            
        Returns:
            Threat analysis results or None if analysis fails
            
        Raises:
            ValueError: If IP address format is invalid
        """
        try:
            # Implementation here
            logger.info(f"Analyzing IP: {ip_address}")
            return {"score": 0, "threats": []}
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise
```

### Testing

Write comprehensive tests for your contributions:

```python
import pytest
from unittest.mock import Mock, patch
from src.core.threat_intel_v2 import ThreatIntelligence

class TestThreatIntelligence:
    """Test suite for ThreatIntelligence class."""
    
    @pytest.fixture
    def threat_intel(self):
        """Create a ThreatIntelligence instance for testing."""
        config = Mock()
        return ThreatIntelligence(config)
    
    async def test_analyze_ip_success(self, threat_intel):
        """Test successful IP analysis."""
        result = await threat_intel.analyze_ip("8.8.8.8")
        assert result is not None
        assert "score" in result
    
    async def test_analyze_ip_invalid(self, threat_intel):
        """Test IP analysis with invalid IP."""
        with pytest.raises(ValueError):
            await threat_intel.analyze_ip("invalid-ip")
```

Run tests:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_threat_intel.py
```

## 📝 Submitting Changes

### Pull Request Process

1. **Update Documentation**
   - Update README if needed
   - Add docstrings to new functions/classes
   - Update configuration examples if applicable

2. **Test Your Changes**
   ```bash
   # Run full test suite
   pytest tests/
   
   # Check code quality
   black --check src/ tests/
   isort --check-only src/ tests/
   pylint src/
   bandit -r src/
   ```

3. **Commit Changes**
   ```bash
   # Use conventional commit format
   git commit -m "feat: add new threat intelligence provider"
   git commit -m "fix: resolve API timeout issue"
   git commit -m "docs: update installation guide"
   ```

4. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   - Create a Pull Request on GitHub
   - Fill out the PR template completely
   - Link any related issues

### Pull Request Template

When creating a PR, please include:

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No sensitive information in commit
```

## 🐛 Reporting Bugs

### Before Reporting

1. Check existing issues for duplicates
2. Verify the bug exists in the latest version
3. Gather relevant information

### Bug Report Template

```markdown
**Bug Description**
A clear description of the bug.

**Steps to Reproduce**
1. Go to '...'
2. Run command '....'
3. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: [e.g., Ubuntu 20.04]
- Python Version: [e.g., 3.9.7]
- IPDefender Version: [e.g., 2.0.0]
- Configuration: [relevant config sections]

**Logs**
```bash
[Include relevant log entries]
```

**Additional Context**
Any other context about the problem.
```

## 💡 Suggesting Features

### Feature Request Template

```markdown
**Feature Description**
Clear description of the feature you'd like to see.

**Problem Statement**
What problem does this feature solve?

**Proposed Solution**
How do you envision this feature working?

**Alternatives Considered**
Other approaches you've considered.

**Additional Context**
Any other context, mockups, or examples.
```

## 🔌 Plugin Development

### Creating a New Provider

1. **Threat Intelligence Provider**
   ```python
   # src/plugins/threat_providers/my_provider.py
   from ..base_provider import BaseThreatProvider
   
   class MyThreatProvider(BaseThreatProvider):
       """Custom threat intelligence provider."""
       
       def __init__(self, config):
           super().__init__(config)
           self.api_key = config.get('api_key')
       
       async def analyze_ip(self, ip_address: str) -> dict:
           # Implementation
           pass
   ```

2. **Firewall Provider**
   ```python
   # src/plugins/firewall_providers/my_firewall.py
   from ..base_provider import BaseFirewallProvider
   
   class MyFirewallProvider(BaseFirewallProvider):
       """Custom firewall provider."""
       
       async def block_ip(self, ip_address: str, reason: str) -> bool:
           # Implementation
           pass
   ```

### Plugin Guidelines

- Follow the base provider interface
- Include comprehensive error handling
- Add configuration validation
- Write tests for your plugin
- Document configuration options

## 📖 Documentation

### Documentation Standards

- Use Markdown for all documentation
- Include code examples where helpful
- Keep language clear and concise
- Update relevant sections when making changes

### Building Documentation

```bash
# Install documentation dependencies
pip install mkdocs mkdocs-material

# Serve documentation locally
mkdocs serve

# Build documentation
mkdocs build
```

## 🎯 Code of Conduct

### Our Standards

- **Be Respectful**: Treat everyone with respect and courtesy
- **Be Inclusive**: Welcome contributors from all backgrounds
- **Be Collaborative**: Work together constructively
- **Be Patient**: Help others learn and grow

### Unacceptable Behavior

- Harassment or discrimination of any kind
- Trolling, insulting comments, or personal attacks
- Public or private harassment
- Publishing others' private information
- Other conduct inappropriate in a professional setting

### Reporting Issues

Report code of conduct violations to:
- Contact via [byfranke.com](https://byfranke.com/#Contact)
- Create a private issue if needed

## 🏷️ Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in appropriate files
- [ ] Security review completed
- [ ] Performance impact assessed

## 🎉 Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to IPDefender Pro! 🛡️

---

## 📞 Questions?

- **Technical Questions**: GitHub Discussions
- **Bug Reports**: GitHub Issues
- **Security Issues**: See SECURITY.md
- **General Contact**: [byfranke.com](https://byfranke.com/#Contact)

---

<div align="center">

**🤝 Together we build better security tools 🤝**

</div>
