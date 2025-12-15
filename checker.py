#!/usr/bin/env python3
"""
AWS Security Baseline Checker (CIS AWS Foundations Benchmark)

Automated tool that checks AWS accounts against CIS AWS Foundations Benchmark
with severity scoring and remediation guidance.
"""

import boto3
import yaml
from datetime import datetime
from typing import Dict, List
from colorama import Fore, Style, init

from checks import iam_checks, logging_checks, monitoring_checks, networking_checks
from report_generator import generate_html_report, generate_json_report

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class CISBenchmarkChecker:
    """Main checker class for CIS AWS Foundations Benchmark."""
    
    def __init__(self, profile_name: str = None, region: str = 'us-east-1'):
        """
        Initialize CIS Benchmark Checker.
        
        Args:
            profile_name: AWS profile name (optional)
            region: AWS region
        """
        self.session = boto3.Session(profile_name=profile_name, region_name=region)
        self.region = region
        self.account_id = self.session.client('sts').get_caller_identity()['Account']
        self.results = []
        self.summary = {
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'manual': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
    
    def run_all_checks(self) -> List[Dict]:
        """
        Run all CIS benchmark checks.
        
        Returns:
            List of check results
        """
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"AWS Security Baseline Checker (CIS Benchmark)")
        print(f"Account: {self.account_id}")
        print(f"Region: {self.region}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}{Style.RESET_ALL}\n")
        
        # Section 1: Identity and Access Management
        print(f"{Fore.YELLOW}Section 1: Identity and Access Management{Style.RESET_ALL}")
        self._run_checks(iam_checks.get_all_checks(self.session))
        
        # Section 2: Logging
        print(f"\n{Fore.YELLOW}Section 2: Logging{Style.RESET_ALL}")
        self._run_checks(logging_checks.get_all_checks(self.session))
        
        # Section 3: Monitoring
        print(f"\n{Fore.YELLOW}Section 3: Monitoring{Style.RESET_ALL}")
        self._run_checks(monitoring_checks.get_all_checks(self.session))
        
        # Section 4: Networking
        print(f"\n{Fore.YELLOW}Section 4: Networking{Style.RESET_ALL}")
        self._run_checks(networking_checks.get_all_checks(self.session))
        
        return self.results
    
    def _run_checks(self, checks: List):
        """Run a list of checks and collect results."""
        for check in checks:
            try:
                result = check()
                self.results.append(result)
                self._update_summary(result)
                self._print_result(result)
            except Exception as e:
                print(f"{Fore.RED}Error running check: {str(e)}{Style.RESET_ALL}")
    
    def _update_summary(self, result: Dict):
        """Update summary statistics."""
        self.summary['total_checks'] += 1
        
        if result['status'] == 'PASS':
            self.summary['passed'] += 1
        elif result['status'] == 'FAIL':
            self.summary['failed'] += 1
        elif result['status'] == 'MANUAL':
            self.summary['manual'] += 1
        
        severity = result.get('severity', '').upper()
        if severity == 'CRITICAL':
            self.summary['critical'] += 1
        elif severity == 'HIGH':
            self.summary['high'] += 1
        elif severity == 'MEDIUM':
            self.summary['medium'] += 1
        elif severity == 'LOW':
            self.summary['low'] += 1
    
    def _print_result(self, result: Dict):
        """Print check result with color coding."""
        status = result['status']
        control_id = result['control_id']
        title = result['title']
        
        # Color code based on status
        if status == 'PASS':
            status_color = Fore.GREEN
        elif status == 'FAIL':
            status_color = Fore.RED
        else:
            status_color = Fore.YELLOW
        
        print(f"{status_color}[{status}]{Style.RESET_ALL} {control_id}: {title}")
        
        if status == 'FAIL' and result.get('details'):
            print(f"  {Fore.RED}→ {result['details']}{Style.RESET_ALL}")
    
    def print_summary(self):
        """Print summary of check results."""
        print(f"\n{Fore.CYAN}{'='*80}")
        print("Summary")
        print(f"{'='*80}{Style.RESET_ALL}\n")
        
        print(f"Total Checks: {self.summary['total_checks']}")
        print(f"{Fore.GREEN}Passed: {self.summary['passed']}{Style.RESET_ALL}")
        print(f"{Fore.RED}Failed: {self.summary['failed']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Manual Review: {self.summary['manual']}{Style.RESET_ALL}\n")
        
        print("Findings by Severity:")
        print(f"{Fore.RED}Critical: {self.summary['critical']}{Style.RESET_ALL}")
        print(f"{Fore.RED}High: {self.summary['high']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium: {self.summary['medium']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Low: {self.summary['low']}{Style.RESET_ALL}\n")
        
        # Calculate compliance percentage
        if self.summary['total_checks'] > 0:
            compliance_pct = (self.summary['passed'] / self.summary['total_checks']) * 100
            print(f"Compliance Score: {compliance_pct:.1f}%\n")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Security Baseline Checker (CIS Benchmark)')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region', default='us-east-1')
    parser.add_argument('--output-html', help='Output HTML report path', default='report.html')
    parser.add_argument('--output-json', help='Output JSON report path', default='report.json')
    
    args = parser.parse_args()
    
    # Run checks
    checker = CISBenchmarkChecker(profile_name=args.profile, region=args.region)
    results = checker.run_all_checks()
    
    # Print summary
    checker.print_summary()
    
    # Generate reports
    print(f"{Fore.CYAN}Generating reports...{Style.RESET_ALL}")
    generate_html_report(results, checker.summary, args.output_html)
    generate_json_report(results, checker.summary, args.output_json)
    
    print(f"{Fore.GREEN}✓ HTML report: {args.output_html}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}✓ JSON report: {args.output_json}{Style.RESET_ALL}\n")


if __name__ == '__main__':
    main()
