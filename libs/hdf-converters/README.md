# OHDF Converters

"[OASIS Heimdall Data Format (OHDF)](https://saf.mitre.org/#/normalize)" is our common data exchange format to preserve and transform security data.

OHDF Converters supplies several methods to convert various types of security tool data to and from the OHDF standard. OHDF Converters can be used in a variety of tools, and is currently well integrated with Heimdall itself, and the [SAF CLI](https://github.com/mitre/saf).

## Supported Formats

1.  [**anchore-grype-mapper**] - Anchore Grype container security scanning results file
2.  [**asff-mapper**] - AWS Security Finding Format JSON file, Prowler-derived AWS Security Finding Format results from concatenated JSON blobs, and Trivy-derived AWS Security Finding Format results from concatenated JSON blobs
3.  [**aws-config-mapper**] - AWS Config
4.  [**burpsuite-mapper**] - BurpSuite Pro XML file
5.  [**caat-mapper**] - Compliance Assessment and Audit Tracking (CAAT) file
6.  [**checklist-mapper**] - Checlist Mapper format
7.  [**conveyor-mapper**] - Conveyor JSON file
8.  [**cyclonedx-sbom-mapper**] - CycloneDX SBOM JSON file
9.  [**dbprotect-mapper**] - DBProtect report in "Check Results Details" XML format
10. [**dependency-track-mapper**] - OWASP Dependency-Track Finding Packaging Format (FPF)
11. [**fortify-mapper**] - Fortify results FVDL file
12. [**gosec-mapper**] - gosec results JSON file
13. [**ionchannel-mapper**] - SBOM data from Ion Channel
14. [**jfrog-xray-mapper**] - JFrog Xray results JSON file
15. [**msft-secure-mapper**] - Microsoft Secure Score results file
16. [**nessus-mapper**] - Nessus XML results file
17. [**netsparker-mapper**] - Netsparker XML results file
18. [**neuvector-mapper**] - NeuVector JSON results file
19. [**nikto-mapper**] - Nikto results JSON file
20. [**prisma-mapper**] - Prisma Cloud Scan Report CSV file
21. [**sarif-mapper**] - SARIF JSON file
22. [**scoutsuite-mapper**] - ScoutSuite results from a Javascript object
23. [**snyk-mapper**] - Snyk results JSON file
24. [**sonarqube-mapper**] - SonarQube vulnerabilities for the specified project name and optional branch or pull/merge request ID name from an API
25. [**splunk-mapper**] - Splunk instance
26. [**trufflehog-mapper**] - Trufflehog results json file
27. [**twistlock-mapper**] - Twistlock CLI output file
28. [**veracode-mapper**] - Veracode Scan Results XML file
29. [**xccdf-results-mapper**] - SCAP client XCCDF-Results XML report
30. [**zap-mapper**] - OWASP ZAP results JSON

### NOTICE

© 2022 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.
