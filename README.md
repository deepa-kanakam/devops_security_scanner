# DevOps Security Vulnerability Scanner and Prioritizer

This project scans code repositories and container images for vulnerabilities, prioritizes them based on risk using a simple ML model, and provides remediation suggestions.

## Tools Used
- Python
- Semgrep (code scan)
- Trivy (container scan)
- Scikit-learn (ML model for risk scoring)

## Setup
1. Install dependencies:
```
pip install -r requirements.txt
brew install trivy
pip install semgrep
```

2. Run the scanner:
```
python security_scanner.py
```

## Output
- `output/final_report.json`: JSON report with vulnerabilities, risk scores, and remediations.
