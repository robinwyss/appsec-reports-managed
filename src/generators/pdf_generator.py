"""
PDF report generator using WeasyPrint.
"""

import logging
from pathlib import Path
from typing import Dict
from weasyprint import HTML

from .html_generator import HtmlReportGenerator


class PdfReportGenerator:
    """Generate PDF vulnerability reports from HTML."""
    
    def __init__(self):
        """Initialize PDF generator."""
        self.html_generator = HtmlReportGenerator()
    
    def generate(self, report_data: Dict, output_file: Path) -> None:
        """
        Generate PDF report from report data.
        
        Args:
            report_data: Dictionary containing report data
            output_file: Path where PDF file should be saved
        """
        logging.info("Generating PDF report: %s", output_file)
        
        # Generate HTML in memory first
        temp_html = output_file.with_suffix('.temp.html')
        
        try:
            # Generate HTML
            self.html_generator.generate(report_data, temp_html)
            
            # Convert HTML to PDF using WeasyPrint
            html = HTML(filename=str(temp_html))
            html.write_pdf(str(output_file))
            
            logging.info("PDF report generated successfully: %s", output_file)
            
        finally:
            # Clean up temporary HTML file
            if temp_html.exists():
                temp_html.unlink()
