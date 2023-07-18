#!/bin/zsh

# generates a somewhat human-readable CSV file you can open in a tool like Excel

# uses a "rules-map" file with four columns
# Vuln ID, CVE ID, test name, description
# V-252464,APPL-12-001003,audit_auditd_enabled,Enable Security Auditing

# report time
ReportTime=$(date "+%Y.%m.%d-%H%M")

# report path
ReportFile="report-${ReportTime}.csv"
ReportPath="/Users/Shared"

# example using DISA-STIG

tail +2 /Library/Logs/DISA-STIG_baseline.log | awk '{print $7}' | while read -r testName
do
	passFail=$(grep "$testName" /Library/Logs/DISA-STIG_baseline.log | awk '{print $8}')
	
	grep "$testName" ./rules-map.csv | (echo -n "$passFail," && cat) >> "$ReportPath/$ReportFile"
done

echo "Audit results written to ${ReportPath}/${ReportFile}"