# Contributing to File Integrity Monitor (FIM)

Thank you for contributing to FIM!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Jaswanth2609/file-integrity-monitor.git
   cd file-integrity-monitor
   ```

2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -e .[dev,api]
   ```

3. Run the test suite:
   ```bash
   python3 -m unittest tests/test_fim_v2.py
   ```

4. Code Style & Quality:
   - Format with `black` and lint with `ruff`.
   - Run security checks with `bandit -r src/fim`.
