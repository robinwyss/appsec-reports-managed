"""
Data structures for report aggregation and statistics.
"""

from dataclasses import dataclass, field
from typing import List, Dict
from collections import defaultdict, Counter
from datetime import datetime

from .vulnerability import VulnerabilityData, Severity


@dataclass
class SeverityStats:
    """Statistics for vulnerability severity distribution."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    
    @property
    def total(self) -> int:
        """Total number of vulnerabilities."""
        return self.critical + self.high + self.medium + self.low


@dataclass
class ProcessGroupAggregation:
    """Vulnerability aggregation for a process group."""
    process_group_id: str
    process_group_name: str
    severity_stats: SeverityStats
    vulnerabilities: List[VulnerabilityData] = field(default_factory=list)
    
    @property
    def total_vulnerabilities(self) -> int:
        """Total vulnerabilities for this process group."""
        return len(self.vulnerabilities)


@dataclass
class HostAggregation:
    """Vulnerability aggregation for a host."""
    host_id: str
    host_name: str
    severity_stats: SeverityStats
    vulnerabilities: List[VulnerabilityData] = field(default_factory=list)
    
    @property
    def total_vulnerabilities(self) -> int:
        """Total vulnerabilities for this host."""
        return len(self.vulnerabilities)


@dataclass
class ReportData:
    """Complete report data with aggregations and statistics."""
    
    management_zone: str
    start_time: datetime
    end_time: datetime
    generated_at: datetime
    vulnerabilities: List[VulnerabilityData]
    
    @property
    def overall_severity_stats(self) -> SeverityStats:
        """Calculate overall severity statistics."""
        stats = SeverityStats()
        for vuln in self.vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                stats.critical += 1
            elif vuln.severity == Severity.HIGH:
                stats.high += 1
            elif vuln.severity == Severity.MEDIUM:
                stats.medium += 1
            elif vuln.severity == Severity.LOW:
                stats.low += 1
        return stats
    
    @property
    def new_vulnerabilities(self) -> List[VulnerabilityData]:
        """Get vulnerabilities first seen within the reporting timeframe."""
        start_ts = int(self.start_time.timestamp() * 1000)
        return [
            vuln for vuln in self.vulnerabilities 
            if vuln.first_seen_timestamp >= start_ts
        ]
    
    @property
    def process_group_aggregations(self) -> List[ProcessGroupAggregation]:
        """Aggregate vulnerabilities by process group."""
        pg_map: Dict[str, ProcessGroupAggregation] = {}
        
        for vuln in self.vulnerabilities:
            for pg_id in vuln.process_groups:
                if pg_id not in pg_map:
                    pg_map[pg_id] = ProcessGroupAggregation(
                        process_group_id=pg_id,
                        process_group_name=pg_id,  # Would need to fetch actual name
                        severity_stats=SeverityStats()
                    )
                
                pg_map[pg_id].vulnerabilities.append(vuln)
                
                # Update severity stats
                if vuln.severity == Severity.CRITICAL:
                    pg_map[pg_id].severity_stats.critical += 1
                elif vuln.severity == Severity.HIGH:
                    pg_map[pg_id].severity_stats.high += 1
                elif vuln.severity == Severity.MEDIUM:
                    pg_map[pg_id].severity_stats.medium += 1
                elif vuln.severity == Severity.LOW:
                    pg_map[pg_id].severity_stats.low += 1
        
        # Sort by total vulnerabilities descending
        return sorted(
            pg_map.values(), 
            key=lambda x: x.total_vulnerabilities, 
            reverse=True
        )
    
    @property
    def host_aggregations(self) -> List[HostAggregation]:
        """Aggregate vulnerabilities by host."""
        host_map: Dict[str, HostAggregation] = {}
        
        for vuln in self.vulnerabilities:
            for host_id in vuln.hosts:
                if host_id not in host_map:
                    host_map[host_id] = HostAggregation(
                        host_id=host_id,
                        host_name=host_id,  # Would need to fetch actual name
                        severity_stats=SeverityStats()
                    )
                
                host_map[host_id].vulnerabilities.append(vuln)
                
                # Update severity stats
                if vuln.severity == Severity.CRITICAL:
                    host_map[host_id].severity_stats.critical += 1
                elif vuln.severity == Severity.HIGH:
                    host_map[host_id].severity_stats.high += 1
                elif vuln.severity == Severity.MEDIUM:
                    host_map[host_id].severity_stats.medium += 1
                elif vuln.severity == Severity.LOW:
                    host_map[host_id].severity_stats.low += 1
        
        # Sort by total vulnerabilities descending
        return sorted(
            host_map.values(), 
            key=lambda x: x.total_vulnerabilities, 
            reverse=True
        )
