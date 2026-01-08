"""
HTML report generator using Jinja2 templates.
"""

import logging
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import Dict

from ..models.vulnerability import VulnerabilityData
from ..models.report_data import ReportData


class HtmlReportGenerator:
    """Generate HTML vulnerability reports."""
    
    def __init__(self):
        """Initialize the HTML generator with Jinja2 environment."""
        # Setup Jinja2 environment
        template_dir = Path(__file__).parent.parent.parent / 'templates'
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Add custom filters
        self.env.filters['format_timestamp'] = self._format_timestamp
        self.env.filters['format_datetime'] = self._format_datetime
    
    def generate(self, report_data_dict: Dict, output_file: Path) -> None:
        """
        Generate HTML report from report data.
        
        Args:
            report_data_dict: Dictionary containing report data
            output_file: Path where HTML file should be saved
        """
        logging.info("Generating HTML report: %s", output_file)
        
        # Convert vulnerability dictionaries to VulnerabilityData objects
        vulnerabilities = [
            VulnerabilityData.from_api_response(vuln) 
            for vuln in report_data_dict['vulnerabilities']
        ]
        
        # Create ReportData object
        report_data = ReportData(
            management_zone=report_data_dict['management_zone'],
            start_time=report_data_dict['start_time'],
            end_time=report_data_dict['end_time'],
            generated_at=report_data_dict['generated_at'],
            vulnerabilities=vulnerabilities
        )
        
        # Load template
        template = self.env.get_template('report_template.html')
        
        # Render template with data
        html_content = template.render(
            report=report_data,
            severity_stats=report_data.overall_severity_stats,
            new_vulnerabilities=report_data.new_vulnerabilities,
            process_groups=report_data.process_group_aggregations,
            hosts=report_data.host_aggregations
        )
        
        # Write to file
        output_file.write_text(html_content, encoding='utf-8')
        logging.info("HTML report generated successfully: %s", output_file)
    
    @staticmethod
    def _format_timestamp(timestamp_ms: int) -> str:
        """Format millisecond timestamp to readable string."""
        from datetime import datetime
        dt = datetime.fromtimestamp(timestamp_ms / 1000)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    @staticmethod
    def _format_datetime(dt) -> str:
        """Format datetime to readable string."""
        return dt.strftime('%Y-%m-%d %H:%M:%S')
