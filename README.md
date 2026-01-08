# Dynatrace Vulnerability Reports

Python solution for generating PDF and HTML reports of security vulnerabilities detected by Dynatrace, organized by team using Management Zones.

## Features

- Fetches vulnerability data from Dynatrace API
- Generates reports per team (based on Management Zones)
- Shows vulnerabilities open in the last 7 days
- Highlights severity distribution (Critical, High, Medium, Low)
- Identifies new vulnerabilities detected in the timeframe
- Aggregates data by Process Group and Host
- Exports to both PDF and HTML formats

## Prerequisites

- Python 3.8+
- Dynatrace API Token with the following scopes:
  - Read security problems (`securityProblems.read`)
  - Read entities (`entities.read`)
  - Read configuration (`ReadConfig`)
- Dynatrace Environment URL (e.g., `https://xxxyyyyy.live.dynatrace.com`)

## Installation

1. **Create and activate virtual environment**:

   ```bash
   # Create virtual environment
   python3 -m venv venv
   
   # Activate virtual environment
   # On macOS/Linux:
   source venv/bin/activate
   
   # On Windows:
   venv\Scripts\activate
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**:

   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Edit .env and add your Dynatrace credentials
   # DYNATRACE_ENV=https://xxxyyyyy.live.dynatrace.com
   # DYNATRACE_TOKEN=dt0c01.XXX...
   ```

   Note: When you're done working, deactivate the virtual environment with:
   ```bash
   deactivate
   ```

## Usage

**Note**: Make sure the virtual environment is activated before running the application:
```bash
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate     # Windows
```

### Option 1: Using .env file (Recommended)

If you've configured `.env` with your credentials:
```bash
python main.py
```

### Option 2: Using command-line arguments

```bash
python main.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX...
```

### Option 3: Mix of both

You can override .env values with command-line arguments:
```bash
python main.py -d 14  # Uses .env credentials but overrides days to 14
```

### Arguments

All arguments can be set via command-line or `.env` file:

- `-e, --env ENVIRONMENT` - The Dynatrace Environment URL (env: `DYNATRACE_ENV`)
- `-t, --token TOKEN` - The Dynatrace API Token (env: `DYNATRACE_TOKEN`)
- `-d, --days DAYS` - Number of days to look back (env: `DAYS`, default: 7)
- `-o, --output OUTPUT` - Output directory for reports (env: `OUTPUT_DIR`, default: ./reports)
- `--html-only` - Generate only HTML reports
- `--pdf-only` - Generate only PDF reports
- `-k, --insecure` - Skip SSL certificate validation (env: `INSECURE`)
- `--debug` - Set log level to DEBUG (env: `DEBUG`)

### Examples

Generate reports using .env configuration:
```bash
python main.py
```

Generate reports for the last 14 days (override .env):
```bash
python main.py -d 14
```

Generate only HTML reports:
```bash
python main.py --html-only
```

Use command-line arguments only (without .env):
```bash
python main.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX...
```

## Project Structure

```
.
├── src/
│   ├── api/
│   │   └── dynatrace_api.py      # Dynatrace API wrapper
│   ├── models/
│   │   ├── vulnerability.py      # Vulnerability data models
│   │   └── report_data.py        # Report data structures
│   ├── generators/
│   │   ├── html_generator.py     # HTML report generation
│   │   └── pdf_generator.py      # PDF report generation
│   └── utils/
│       ├── helpers.py             # Utility functions
│       └── logger.py              # Logging configuration
├── templates/
│   └── report_template.html      # HTML report template
├── main.py                        # Main entry point
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

## Output

Reports are generated in the `./reports` directory (or specified output directory) with the following structure:

```
reports/
├── {management_zone_name}/
│   ├── vulnerability_report_{date}.html
│   └── vulnerability_report_{date}.pdf
```

Each report contains:
- Executive summary with vulnerability counts by severity
- New vulnerabilities detected in the timeframe
- Aggregation by Process Group showing vulnerability distribution
- Aggregation by Host showing affected infrastructure
- Detailed vulnerability list with CVE information, risk scores, and affected entities

## Logging

Logs are written to `output.log`. Default log level is INFO, can be changed to DEBUG with the `--debug` flag.
# appsec-reports-managed
