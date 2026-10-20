# Brute Force Detection System with Python

## Overview

This project is a Python-based security tool that analyzes authentication logs and detects repeated failed login attempts that may indicate a brute-force attack.

## Features

- Analyzes authentication log files.
- Groups failed login attempts by source IP address.
- Detects repeated attempts within a configurable 60-second window.
- Generates alerts for suspicious activity.
- Exports detection results to a CSV report.
- Handles missing log files.

## Technologies

- Python 3
- Regular Expressions
- CSV
- Log Analysis
- Cybersecurity Fundamentals

## Project Structure

```text
BruteForceDetector/
├── detector.py
├── auth.log
├── report.csv
└── README.md
```

## Requirements

- Python 3.7 or later
- No external libraries required

## How to Run

Open a terminal in the project directory and execute:

```bash
python detector.py
```

The program analyzes `auth.log` and generates `report.csv`.

## Detection Configuration

- Failed login threshold: 5 attempts
- Detection window: 60 seconds

## Testing

The tool was tested using fictional authentication logs, including repeated failed attempts and attempts spread over time.

## Limitations

This is an educational prototype that analyzes predefined log files. It does not block IP addresses or monitor live systems. An alert indicates suspicious activity, not proof of an actual attack.

## Disclaimer

Use this tool only with logs you own or are authorized to analyze. The sample log data is fictional.

## Author

GitHub: https://github.com/ghofranelouza