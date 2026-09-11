import json
from dataclasses import asdict

from analyzers.ec2_analyzer import EC2Analyzer
from analyzers.iam_analyzer import IAMAnalyzer
from analyzers.s3_analyzer import S3Analyzer
from services.ec2_scanner import EC2Scanner
from services.iam_scanner import IAMScanner
from services.s3_scanner import S3Scanner


def main():
    print("AWS Security Scanner")
    print("====================")

    s3_scanner = S3Scanner()
    s3_scan_results = s3_scanner.scan()

    print("\nS3 Resources Found:", len(s3_scan_results))

    s3_analyzer = S3Analyzer()
    s3_findings = s3_analyzer.analyze(s3_scan_results)

    ec2_scanner = EC2Scanner()
    ec2_scan_results = ec2_scanner.scan()

    print("EC2 Resources Found:", len(ec2_scan_results))

    ec2_analyzer = EC2Analyzer()
    ec2_findings = ec2_analyzer.analyze(ec2_scan_results)

    iam_scanner = IAMScanner()
    iam_scan_results = iam_scanner.scan()

    print("IAM Users Found:", len(iam_scan_results))

    iam_analyzer = IAMAnalyzer()
    iam_findings = iam_analyzer.analyze(iam_scan_results)

    all_findings = s3_findings + ec2_findings + iam_findings

    print("\nSecurity Findings")
    print("-----------------")

    for finding in all_findings:
        print("\nRule:", finding.rule_id)
        print("Service:", finding.service)
        print("Resource:", finding.resource_id)
        print("Severity:", finding.severity)
        print("Status:", finding.status)
        print("Message:", finding.message)

    print("\nFindings JSON")
    print("-------------")

    findings_json = [
        asdict(finding)
        for finding in all_findings
    ]

    print(
        json.dumps(
            findings_json,
            indent=4
        )
    )


if __name__ == "__main__":
    main()
