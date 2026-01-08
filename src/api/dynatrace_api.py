"""
Dynatrace API wrapper for fetching vulnerability and entity data.
Based on patterns from robinwyss/appsec_scripts repository.
"""

import requests
import logging
from functools import lru_cache
from datetime import datetime
from typing import List, Dict, Optional


class DynatraceApi:
    """Wrapper for Dynatrace API calls."""
    
    def __init__(self, tenant: str, api_token: str, verify_ssl: bool = True):
        """
        Initialize the Dynatrace API client.
        
        Args:
            tenant: Dynatrace tenant URL (e.g., https://xxxyyyyy.live.dynatrace.com)
            api_token: API token with required scopes
            verify_ssl: Whether to verify SSL certificates
        """
        self.tenant = tenant.rstrip('/')
        self.api_token = api_token
        self.verify_ssl = verify_ssl
    
    def query_api(self, endpoint: str) -> Dict:
        """
        Execute an API call to the specified endpoint.
        
        Args:
            endpoint: API endpoint path (e.g., '/api/v2/securityProblems')
            
        Returns:
            JSON response as dictionary
            
        Raises:
            RuntimeError: If API call fails
        """
        auth_header = {'Authorization': f'Api-Token {self.api_token}'}
        url = f"{self.tenant}{endpoint}"
        
        logging.debug("API Call: %s", url)
        response = requests.get(url, headers=auth_header, verify=self.verify_ssl)
        
        if response.status_code != 200:
            logging.error("Request %s failed", url)
            logging.error("Status Code: %s (%s), Response: %s", 
                         response.status_code, response.reason, response.content)
            raise RuntimeError(
                f'API request failed: {response.status_code} ({response.reason})', 
                response.content
            )
        
        logging.debug("API Call successful: %s", url)
        return response.json()
    
    def get_management_zones(self) -> List[Dict]:
        """
        Retrieve all management zones.
        
        Returns:
            List of management zone dictionaries with 'id' and 'name'
        """
        logging.info("Fetching management zones...")
        response = self.query_api('/api/config/v1/managementZones')
        return response.get('values', [])
    
    def get_vulnerabilities_by_management_zone(
        self, 
        mz_id: str, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict]:
        """
        Get all vulnerabilities for a specific management zone within a time range.
        
        Args:
            mz_id: Management zone ID
            start_time: Start of time range
            end_time: End of time range
            
        Returns:
            List of vulnerability dictionaries with details
        """
        # Convert timestamps to milliseconds
        from_ts = int(start_time.timestamp() * 1000)
        to_ts = int(end_time.timestamp() * 1000)
        
        # Query vulnerabilities with management zone filter
        # Note: +relatedEntities is not available in list endpoint, only in detail endpoint
        selector = f'managementZoneIds("{mz_id}")'
        endpoint = (
            f'/api/v2/securityProblems'
            f'?securityProblemSelector={selector}'
            f'&from={from_ts}'
            f'&to={to_ts}'
            f'&fields=+riskAssessment,+managementZones'
            f'&pageSize=500'
        )
        
        vulnerabilities = self._query_all_security_problems(endpoint)
        
        # Enrich with details
        enriched_vulnerabilities = []
        for vuln in vulnerabilities:
            vuln_id = vuln['securityProblemId']
            details = self.get_security_problem_details(vuln_id)
            enriched_vulnerabilities.append(details)
        
        return enriched_vulnerabilities
    
    def _query_all_security_problems(self, endpoint: str) -> List[Dict]:
        """
        Query security problems handling pagination.
        
        Args:
            endpoint: Initial API endpoint
            
        Returns:
            Complete list of security problems
        """
        security_problems = []
        response = self.query_api(endpoint)
        security_problems.extend(response.get("securityProblems", []))
        
        while "nextPageKey" in response:
            next_endpoint = f'/api/v2/securityProblems?nextPageKey={response["nextPageKey"]}'
            response = self.query_api(next_endpoint)
            security_problems.extend(response.get("securityProblems", []))
        
        return security_problems
    
    @lru_cache(maxsize=None)
    def get_security_problem_details(self, security_problem_id: str) -> Dict:
        """
        Get detailed information for a specific security problem.
        Uses caching to avoid duplicate API calls.
        
        Args:
            security_problem_id: The security problem ID
            
        Returns:
            Detailed security problem data
        """
        endpoint = (
            f'/api/v2/securityProblems/{security_problem_id}'
            f'?fields=+affectedEntities,+relatedEntities,+riskAssessment,+managementZones'
        )
        return self.query_api(endpoint)
    
    def get_process_groups(self, pg_ids: List[str]) -> List[Dict]:
        """
        Get process group details for given IDs.
        
        Args:
            pg_ids: List of process group IDs
            
        Returns:
            List of process group entities
        """
        if not pg_ids:
            return []
        
        # Build entity selector for all process group IDs
        id_selector = ','.join(f'"{pg_id}"' for pg_id in pg_ids)
        endpoint = (
            f'/api/v2/entities'
            f'?entitySelector=entityId({id_selector})'
            f'&fields=+properties,+managementZones'
        )
        
        return self._get_all_entities(endpoint)
    
    def get_hosts(self, host_ids: List[str]) -> List[Dict]:
        """
        Get host details for given IDs.
        
        Args:
            host_ids: List of host IDs
            
        Returns:
            List of host entities
        """
        if not host_ids:
            return []
        
        id_selector = ','.join(f'"{host_id}"' for host_id in host_ids)
        endpoint = (
            f'/api/v2/entities'
            f'?entitySelector=entityId({id_selector})'
            f'&fields=+properties,+managementZones'
        )
        
        return self._get_all_entities(endpoint)
    
    def _get_all_entities(self, endpoint: str) -> List[Dict]:
        """
        Get all entities handling pagination.
        
        Args:
            endpoint: API endpoint
            
        Returns:
            List of entities
        """
        entities = []
        response = self.query_api(endpoint)
        entities.extend(response.get("entities", []))
        
        while "nextPageKey" in response:
            next_endpoint = f'/api/v2/entities?nextPageKey={response["nextPageKey"]}'
            response = self.query_api(next_endpoint)
            entities.extend(response.get("entities", []))
        
        return entities
