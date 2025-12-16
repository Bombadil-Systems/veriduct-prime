# Contributing to Veriduct Prime

Thank you for your interest in contributing to Veriduct Prime. This document outlines how to contribute effectively.

## Ways to Contribute

### 1. Report Bugs
Found something that doesn't work? Open an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, Python version)
- Relevant log output

### 2. Improve Documentation
- Fix typos or unclear explanations
- Add examples
- Improve API documentation
- Translate documentation

### 3. Submit Code
- Bug fixes
- New features
- Performance improvements
- Test coverage

### 4. Security Research
- Report vulnerabilities responsibly (see SECURITY.md)
- Share bypass techniques
- Propose detection methods
- Contribute to threat modeling

## Development Setup

```bash
# Clone repository
git clone https://github.com/bombadil-systems/veriduct-prime.git
cd veriduct-prime

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install black isort mypy pytest pytest-cov

# Run tests
pytest tests/ -v

# Check formatting
black --check src/
isort --check-only src/

# Type checking
mypy src/
```

## Code Style

### Python
- Follow PEP 8
- Use Black for formatting (line length: 100)
- Use isort for import sorting
- Type hints encouraged but not required
- Docstrings for public functions

### C (for agent)
- K&R style bracing
- 4-space indentation
- Clear variable names
- Comments for complex logic

### Documentation
- Markdown format
- Clear headings
- Code examples where helpful
- Keep technical but accessible

## Submitting Changes

### For Small Changes (typos, minor fixes)
1. Fork the repository
2. Make changes
3. Submit pull request

### For Larger Changes
1. Open an issue first to discuss
2. Fork the repository
3. Create feature branch (`git checkout -b feature/amazing-feature`)
4. Make changes with clear commits
5. Add/update tests
6. Update documentation
7. Submit pull request

### Pull Request Guidelines
- Clear title and description
- Reference related issues
- Include test results
- Update CHANGELOG if applicable

## Testing

### Running Tests
```bash
# All tests
pytest tests/ -v

# Specific test file
pytest tests/test_veriduct_prime.py -v

# With coverage
pytest tests/ --cov=src --cov-report=html
```

### Adding Tests
- Place tests in `tests/` directory
- Name test files `test_*.py`
- Use descriptive test function names
- Test both success and failure cases

### Test Categories
- Unit tests: Individual functions
- Integration tests: Full pipelines
- Binary tests: Real executable handling

## Priority Areas

Current areas where contributions are most valuable:

### High Priority
1. **ELF stack initialization** — Fix Linux execution
2. **Test coverage** — More edge cases
3. **Error messages** — User-friendly failures
4. **Documentation** — Real-world examples

### Medium Priority
1. **GUI improvements** — Better UX
2. **Performance** — Large file handling
3. **32-bit SEH** — Windows x86 support
4. **CI/CD** — Automated testing

### Research Areas
1. **Detection methods** — How can this be detected?
2. **macOS support** — Mach-O loader
3. **Alternative storage** — Beyond SQLite
4. **Distributed chunks** — Network storage

## Communication

### Issues
- Use issue templates
- Be respectful and constructive
- Provide context

### Pull Requests
- Keep focused (one feature/fix per PR)
- Respond to feedback
- Be patient with review process

### General
- Be excellent to each other
- Assume good faith
- Focus on technical merit

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Acknowledged in documentation (if desired)

## Legal

By submitting contributions, you agree that:
- Your contributions are your original work
- You grant Bombadil Systems LLC license to use your contributions
- Your contributions comply with the MIT license

## Questions?

- Open a discussion issue
- Email: research@bombadil.systems

---

Thank you for contributing to Veriduct Prime. Together, we can advance security research.
