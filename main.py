#!/usr/bin/env python
"""
Main entry point for the Dynatrace Vulnerability Report Generator.
Generates PDF and HTML reports for security vulnerabilities grouped by Management Zones (teams).
"""

import sys
import os
import logging
from argparse import ArgumentParser
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv

from src.api.dynatrace_api import DynatraceApi
from src.generators.html_generator import HtmlReportGenerator
from src.generators.pdf_generator import PdfReportGenerator
from src.utils.logger import setup_logging
from src.utils.helpers import ensure_output_directory


def parse_arguments():
    """Parse command line arguments."""
    # Load environment variables from .env file
    load_dotenv()
    
    parser = ArgumentParser(description='Generate Dynatrace vulnerability reports by Management Zone')
    parser.add_argument("-e", "--env", dest="environment", 
                       help="The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)", 
                       default=os.getenv('DYNATRACE_ENV'))
    parser.add_argument("-t", "--token", dest="token", 
                       help="The Dynatrace API Token to use", 
                       default=os.getenv('DYNATRACE_TOKEN'))
    parser.add_argument("-d", "--days", dest="days", 
                       help="Number of days to look back for vulnerabilities (default: 7)", 
                       type=int, default=int(os.getenv('DAYS', '7')))
    parser.add_argument("-o", "--output", dest="output", 
                       help="Output directory for reports (default: ./reports)", 
                       default=os.getenv('OUTPUT_DIR', './reports'))
    parser.add_argument("--html-only", dest="html_only", 
                       help="Generate only HTML reports", 
                       action='store_true')
    parser.add_argument("--pdf-only", dest="pdf_only", 
                       help="Generate only PDF reports", 
                       action='store_true')
    parser.add_argument("-k", "--insecure", dest="insecure", 
                       help="Skip SSL certificate validation", 
                       action='store_true', 
                       default=os.getenv('INSECURE', 'false').lower() == 'true')
    parser.add_argument("--debug", dest="debug", 
                       help="Set log level to DEBUG", 
                       action='store_true', 
                       default=os.getenv('DEBUG', 'false').lower() == 'true')
    
    args = parser.parse_args()
    
    # Validate required arguments
    if not args.environment:
        parser.error("Dynatrace environment URL is required (use -e or set DYNATRACE_ENV in .env)")
    if not args.token:
        parser.error("Dynatrace API token is required (use -t or set DYNATRACE_TOKEN in .env)")
    
    return args


def main():
    """Main execution flow."""
    args = parse_arguments()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level)
    
    logging.info("="*100)
    logging.info("Starting Dynatrace Vulnerability Report Generation")
    logging.info("Environment: %s", args.environment)
    logging.info("Days to look back: %d", args.days)
    logging.info("="*100)
    
    try:
        # Initialize Dynatrace API
        verify_ssl = not args.insecure
        dt_api = DynatraceApi(args.environment, args.token, verify_ssl)
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(days=args.days)
        
        logging.info("Fetching management zones...")
        management_zones = dt_api.get_management_zones()
        logging.info("Found %d management zones", len(management_zones))
        
        # Prepare output directory
        output_dir = Path(args.output)
        ensure_output_directory(output_dir)
        
        # Generate reports for each management zone
        for mz in management_zones:
            mz_name = mz['name']
            mz_id = mz['id']
            
            logging.info("Processing management zone: %s", mz_name)
            
            # Fetch vulnerabilities for this management zone
            vulnerabilities = dt_api.get_vulnerabilities_by_management_zone(
                mz_id, 
                start_time, 
                end_time
            )
            
            if not vulnerabilities:
                logging.info("No vulnerabilities found for %s, skipping...", mz_name)
                continue
            
            logging.info("Found %d vulnerabilities for %s", len(vulnerabilities), mz_name)
            
            # Prepare report data
            report_data = {
                'management_zone': mz_name,
                'start_time': start_time,
                'end_time': end_time,
                'vulnerabilities': vulnerabilities,
                'generated_at': datetime.now()
            }
            
            # Create management zone specific directory
            mz_output_dir = output_dir / mz_name.replace('/', '_').replace(' ', '_')
            ensure_output_directory(mz_output_dir)
            
            # Generate reports
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if not args.pdf_only:
                html_file = mz_output_dir / f"vulnerability_report_{timestamp}.html"
                html_generator = HtmlReportGenerator()
                html_generator.generate(report_data, html_file)
                logging.info("HTML report generated: %s", html_file)
            
            if not args.html_only:
                pdf_file = mz_output_dir / f"vulnerability_report_{timestamp}.pdf"
                pdf_generator = PdfReportGenerator()
                pdf_generator.generate(report_data, pdf_file)
                logging.info("PDF report generated: %s", pdf_file)
        
        logging.info("="*100)
        logging.info("Report generation completed successfully")
        logging.info("="*100)
        
    except Exception as e:
        logging.error("Error during report generation: %s", str(e), exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
