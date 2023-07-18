#!/bin/zsh

##  This script will attempt to audit all of the settings based on the installed profile.

##  This script is provided as-is and should be fully tested on a system that is not in a production environment.

###################  Variables  ###################

pwpolicy_file=""

###################  DEBUG MODE - hold shift when running the script  ###################

shiftKeyDown=$(osascript -l JavaScript -e "ObjC.import('Cocoa'); ($.NSEvent.modifierFlags & $.NSEventModifierFlagShift) > 1")

if [[ $shiftKeyDown == "true" ]]; then
    echo "-----DEBUG-----"
    set -o xtrace -o verbose
fi

###################  COMMANDS START BELOW THIS LINE  ###################

## Must be run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

ssh_key_check=0
if /usr/sbin/sshd -T &> /dev/null; then
    ssh_key_check=0
else
    /usr/bin/ssh-keygen -q -N "" -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
    ssh_key_check=1
fi

# path to PlistBuddy
plb="/usr/libexec/PlistBuddy"

# get the currently logged in user
CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }')
CURR_USER_UID=$(/usr/bin/id -u $CURRENT_USER)

# get system architecture
arch=$(/usr/bin/arch)

# configure colors for text
RED='\e[31m'
STD='\e[39m'
GREEN='\e[32m'
YELLOW='\e[33m'

audit_plist="/Library/Preferences/org.DISA-STIG.audit.plist"
audit_log="/Library/Logs/DISA-STIG_baseline.log"

# pause function
pause(){
vared -p "Press [Enter] key to continue..." -c fackEnterKey
}

ask() {
    # if fix flag is passed, assume YES for everything
    if [[ $fix ]] || [[ $cfc ]]; then
        return 0
    fi

    while true; do

        if [ "${2:-}" = "Y" ]; then
            prompt="Y/n"
            default=Y
        elif [ "${2:-}" = "N" ]; then
            prompt="y/N"
            default=N
        else
            prompt="y/n"
            default=
        fi

        # Ask the question - use /dev/tty in case stdin is redirected from somewhere else
        printf "${YELLOW} $1 [$prompt] ${STD}"
        read REPLY

        # Default?
        if [ -z "$REPLY" ]; then
            REPLY=$default
        fi

        # Check if the reply is valid
        case "$REPLY" in
            Y*|y*) return 0 ;;
            N*|n*) return 1 ;;
        esac

    done
}

# function to display menus
show_menus() {
    lastComplianceScan=$(defaults read /Library/Preferences/org.DISA-STIG.audit.plist lastComplianceCheck)

    if [[ $lastComplianceScan == "" ]];then
        lastComplianceScan="No scans have been run"
    fi

    /usr/bin/clear
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "        M A I N - M E N U"
    echo "  macOS Security Compliance Tool"
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "Last compliance scan: $lastComplianceScan
"
    echo "1. View Last Compliance Report"
    echo "2. Run New Compliance Scan"
    echo "3. Run Commands to remediate non-compliant settings"
    echo "4. Exit"
}

# function to read options
read_options(){
    local choice
    vared -p "Enter choice [ 1 - 4 ] " -c choice
    case $choice in
        1) view_report ;;
        2) run_scan ;;
        3) run_fix ;;
        4) exit 0;;
        *) echo -e "${RED}Error: please choose an option 1-4...${STD}" && sleep 1
    esac
}

# function to reset and remove plist file.  Used to clear out any previous findings
reset_plist(){
    echo "Clearing results from /Library/Preferences/org.DISA-STIG.audit.plist"
    defaults delete /Library/Preferences/org.DISA-STIG.audit.plist
}

# Generate the Compliant and Non-Compliant counts. Returns: Array (Compliant, Non-Compliant)
compliance_count(){
    compliant=0
    non_compliant=0

    results=$(/usr/libexec/PlistBuddy -c "Print" /Library/Preferences/org.DISA-STIG.audit.plist)

    while IFS= read -r line; do
        if [[ "$line" =~ "finding = false" ]]; then
            compliant=$((compliant+1))
        fi
        if [[ "$line" =~ "finding = true" ]]; then
            non_compliant=$((non_compliant+1))
        fi
    done <<< "$results"

    # Enable output of just the compliant or non-compliant numbers.
    if [[ $1 = "compliant" ]]
    then
        echo $compliant
    elif [[ $1 = "non-compliant" ]]
    then
        echo $non_compliant
    else # no matching args output the array
        array=($compliant $non_compliant)
        echo ${array[@]}
    fi
}

exempt_count(){
    exempt=0

    if [[ -e "/Library/Managed Preferences/org.DISA-STIG.audit.plist" ]];then
        mscp_prefs="/Library/Managed Preferences/org.DISA-STIG.audit.plist"
    else
        mscp_prefs="/Library/Preferences/org.DISA-STIG.audit.plist"
    fi

    results=$(/usr/libexec/PlistBuddy -c "Print" "$mscp_prefs")

    while IFS= read -r line; do
        if [[ "$line" =~ "exempt = true" ]]; then
            exempt=$((exempt+1))
        fi
    done <<< "$results"

    echo $exempt
}


generate_report(){
    count=($(compliance_count))
    exempt_rules=$(exempt_count)
    compliant=${count[1]}
    non_compliant=${count[2]}

    total=$((non_compliant + compliant - exempt_rules))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    echo
    echo "Number of tests passed: ${GREEN}$compliant${STD}"
    echo "Number of test FAILED: ${RED}$non_compliant${STD}"
    echo "Number of exempt rules: ${YELLOW}$exempt_rules${STD}"
    echo "You are ${YELLOW}$percentage%${STD} percent compliant!"
    pause
}

view_report(){

    if [[ $lastComplianceScan == "No scans have been run" ]];then
        echo "no report to run, please run new scan"
        pause
    else
        generate_report
    fi
}

# Designed for use with MDM - single unformatted output of the Compliance Report
generate_stats(){
    count=($(compliance_count))
    compliant=${count[1]}
    non_compliant=${count[2]}

    total=$((non_compliant + compliant))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    echo "PASSED: $compliant FAILED: $non_compliant, $percentage percent compliant!"
}

run_scan(){
# append to existing logfile
if [[ $(/usr/bin/tail -n 1 "$audit_log" 2>/dev/null) = *"Remediation complete" ]]; then
 	echo "$(date -u) Beginning DISA-STIG baseline scan" >> "$audit_log"
else
 	echo "$(date -u) Beginning DISA-STIG baseline scan" > "$audit_log"
fi

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID

# write timestamp of last compliance check
/usr/bin/defaults write "$audit_plist" lastComplianceCheck "$(date)"
    
#####----- Rule: audit_acls_files_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_acls_files_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_acls_files_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_acls_files_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) audit_acls_files_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_acls_files_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_acls_files_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_acls_files_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) audit_acls_files_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_acls_files_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_acls_files_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_acls_folders_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_acls_folders_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -lde /var/audit | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_acls_folders_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_acls_folders_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) audit_acls_folders_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_acls_folders_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_acls_folders_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_acls_folders_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) audit_acls_folders_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_acls_folders_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_acls_folders_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_auditd_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12, AU-12(1), AU-12(3)
# * AU-14(1)
# * AU-3, AU-3(1)
# * AU-8
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_auditd_enabled ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(LAUNCHD_RUNNING=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd)
if [[ $LAUNCHD_RUNNING == 1 ]] && [[ -e /etc/security/audit_control ]]; then
  echo "pass"
else
  echo "fail"
fi
)
    # expected result {'string': 'pass'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_auditd_enabled'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_auditd_enabled'))["exempt_reason"]
EOS
)

    if [[ $result_value == "pass" ]]; then
        echo "$(date -u) audit_auditd_enabled passed (Result: $result_value, Expected: "{'string': 'pass'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_auditd_enabled passed (Result: $result_value, Expected: "{'string': 'pass'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_auditd_enabled failed (Result: $result_value, Expected: "{'string': 'pass'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_auditd_enabled failed (Result: $result_value, Expected: "{'string': 'pass'}")"
        else
            echo "$(date -u) audit_auditd_enabled failed (Result: $result_value, Expected: "{'string': 'pass'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_auditd_enabled failed (Result: $result_value, Expected: "{'string': 'pass'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_auditd_enabled does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool NO
fi
    
#####----- Rule: audit_configure_capacity_notify -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_configure_capacity_notify ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F: '/^minfree/{print $2}' /etc/security/audit_control
)
    # expected result {'integer': 25}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_configure_capacity_notify'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_configure_capacity_notify'))["exempt_reason"]
EOS
)

    if [[ $result_value == "25" ]]; then
        echo "$(date -u) audit_configure_capacity_notify passed (Result: $result_value, Expected: "{'integer': 25}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_configure_capacity_notify -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_configure_capacity_notify passed (Result: $result_value, Expected: "{'integer': 25}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_configure_capacity_notify failed (Result: $result_value, Expected: "{'integer': 25}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_configure_capacity_notify -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_configure_capacity_notify failed (Result: $result_value, Expected: "{'integer': 25}")"
        else
            echo "$(date -u) audit_configure_capacity_notify failed (Result: $result_value, Expected: "{'integer': 25}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_configure_capacity_notify -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_configure_capacity_notify failed (Result: $result_value, Expected: "{'integer': 25}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_configure_capacity_notify does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_configure_capacity_notify -dict-add finding -bool NO
fi
    
#####----- Rule: audit_failure_halt -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_failure_halt ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^policy/ {print $NF}' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ahlt'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_failure_halt'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_failure_halt'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) audit_failure_halt passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_failure_halt -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_failure_halt passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_failure_halt failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_failure_halt -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_failure_halt failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) audit_failure_halt failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_failure_halt -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_failure_halt failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_failure_halt does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_failure_halt -dict-add finding -bool NO
fi
    
#####----- Rule: audit_files_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_files_group_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_group_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_group_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) audit_files_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_files_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_files_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_files_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) audit_files_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_files_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_files_group_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_files_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_files_mode_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_mode_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_mode_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) audit_files_mode_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_files_mode_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_files_mode_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_files_mode_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) audit_files_mode_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_files_mode_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_files_mode_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_files_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_files_owner_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_owner_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_owner_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) audit_files_owner_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_files_owner_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_files_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_files_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) audit_files_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_files_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_files_owner_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_aa_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_aa_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'aa'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_aa_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_aa_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) audit_flags_aa_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_flags_aa_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_flags_aa_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_aa_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) audit_flags_aa_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_aa_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_flags_aa_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_ad_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12), AC-2(4)
# * AC-6(9)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_ad_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ad'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_ad_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_ad_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) audit_flags_ad_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_flags_ad_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_flags_ad_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_ad_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) audit_flags_ad_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_ad_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_flags_ad_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fd_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fd_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fd'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fd_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fd_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) audit_flags_fd_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fd_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_flags_fd_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fd_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) audit_flags_fd_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fd_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_flags_fd_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fm_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fm_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^fm'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fm_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fm_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) audit_flags_fm_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_fm_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fm_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_flags_fm_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fm_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fm_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) audit_flags_fm_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fm_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fm_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_flags_fm_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_fm_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fr_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fr_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fr'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fr_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fr_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) audit_flags_fr_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fr_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_flags_fr_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fr_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) audit_flags_fr_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fr_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_flags_fr_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fw_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fw_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fw'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fw_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fw_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) audit_flags_fw_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fw_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_flags_fw_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fw_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) audit_flags_fw_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_fw_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_flags_fw_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_lo_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(1)
# * AC-2(12)
# * AU-12
# * AU-2
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_lo_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^lo'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_lo_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_lo_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) audit_flags_lo_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_flags_lo_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_flags_lo_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_lo_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) audit_flags_lo_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_flags_lo_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_flags_lo_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_folder_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_folder_group_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $4}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folder_group_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folder_group_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) audit_folder_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_folder_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_folder_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_folder_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) audit_folder_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_folder_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_folder_group_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_folder_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_folder_owner_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $3}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folder_owner_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folder_owner_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) audit_folder_owner_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_folder_owner_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_folder_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_folder_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) audit_folder_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_folder_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_folder_owner_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_folders_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_folders_mode_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
)
    # expected result {'integer': 700}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folders_mode_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folders_mode_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "700" ]]; then
        echo "$(date -u) audit_folders_mode_configure passed (Result: $result_value, Expected: "{'integer': 700}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_folders_mode_configure passed (Result: $result_value, Expected: "{'integer': 700}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_folders_mode_configure failed (Result: $result_value, Expected: "{'integer': 700}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_folders_mode_configure failed (Result: $result_value, Expected: "{'integer': 700}")"
        else
            echo "$(date -u) audit_folders_mode_configure failed (Result: $result_value, Expected: "{'integer': 700}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_folders_mode_configure failed (Result: $result_value, Expected: "{'integer': 700}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_folders_mode_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_settings_failure_notify -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5, AU-5(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_settings_failure_notify ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -c "logger -s -p" /etc/security/audit_warn
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_settings_failure_notify'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_settings_failure_notify'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) audit_settings_failure_notify passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_settings_failure_notify -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - audit_settings_failure_notify passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) audit_settings_failure_notify failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_settings_failure_notify -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_settings_failure_notify failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) audit_settings_failure_notify failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_settings_failure_notify -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - audit_settings_failure_notify failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) audit_settings_failure_notify does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_settings_failure_notify -dict-add finding -bool NO
fi
    
#####----- Rule: auth_pam_login_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_pam_login_smartcard_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/login
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_login_smartcard_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_login_smartcard_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "2" ]]; then
        echo "$(date -u) auth_pam_login_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" auth_pam_login_smartcard_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - auth_pam_login_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) auth_pam_login_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_pam_login_smartcard_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_pam_login_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            echo "$(date -u) auth_pam_login_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_pam_login_smartcard_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_pam_login_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) auth_pam_login_smartcard_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" auth_pam_login_smartcard_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: auth_pam_su_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_pam_su_smartcard_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_rootok.so)' /etc/pam.d/su
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_su_smartcard_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_su_smartcard_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "2" ]]; then
        echo "$(date -u) auth_pam_su_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" auth_pam_su_smartcard_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - auth_pam_su_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) auth_pam_su_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_pam_su_smartcard_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_pam_su_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            echo "$(date -u) auth_pam_su_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_pam_su_smartcard_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_pam_su_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) auth_pam_su_smartcard_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" auth_pam_su_smartcard_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: auth_pam_sudo_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_pam_sudo_smartcard_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/sudo
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_sudo_smartcard_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_sudo_smartcard_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "2" ]]; then
        echo "$(date -u) auth_pam_sudo_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - auth_pam_sudo_smartcard_enforce passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) auth_pam_sudo_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_pam_sudo_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            echo "$(date -u) auth_pam_sudo_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_pam_sudo_smartcard_enforce failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) auth_pam_sudo_smartcard_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" auth_pam_sudo_smartcard_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: auth_smartcard_allow -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(12), IA-2(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_smartcard_allow ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('allowSmartCard').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_smartcard_allow'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_smartcard_allow'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) auth_smartcard_allow passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" auth_smartcard_allow -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - auth_smartcard_allow passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) auth_smartcard_allow failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_smartcard_allow -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_smartcard_allow failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) auth_smartcard_allow failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_smartcard_allow -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_smartcard_allow failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) auth_smartcard_allow does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" auth_smartcard_allow -dict-add finding -bool NO
fi
    
#####----- Rule: auth_smartcard_certificate_trust_enforce_moderate -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(2)
# * SC-17
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_smartcard_certificate_trust_enforce_moderate ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('checkCertificateTrust').js
EOS
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_smartcard_certificate_trust_enforce_moderate'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_smartcard_certificate_trust_enforce_moderate'))["exempt_reason"]
EOS
)

    if [[ $result_value == "2" ]]; then
        echo "$(date -u) auth_smartcard_certificate_trust_enforce_moderate passed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - auth_smartcard_certificate_trust_enforce_moderate passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) auth_smartcard_certificate_trust_enforce_moderate failed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_smartcard_certificate_trust_enforce_moderate failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            echo "$(date -u) auth_smartcard_certificate_trust_enforce_moderate failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_smartcard_certificate_trust_enforce_moderate failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) auth_smartcard_certificate_trust_enforce_moderate does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" auth_smartcard_certificate_trust_enforce_moderate -dict-add finding -bool NO
fi
    
#####----- Rule: auth_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(1), IA-2(12), IA-2(2), IA-2(6), IA-2(8)
# * IA-5(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: auth_smartcard_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('enforceSmartCard').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_smartcard_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_smartcard_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) auth_smartcard_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" auth_smartcard_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - auth_smartcard_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) auth_smartcard_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_smartcard_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_smartcard_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) auth_smartcard_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" auth_smartcard_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - auth_smartcard_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) auth_smartcard_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" auth_smartcard_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_addressbook_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_addressbook_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudAddressBook').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_addressbook_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_addressbook_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) icloud_addressbook_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_addressbook_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_addressbook_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_addressbook_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) icloud_addressbook_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_addressbook_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_addressbook_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_appleid_preference_pane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_appleid_preference_pane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledPreferencePanes"]/following-sibling::*[1]' - | /usr/bin/grep -c "com.apple.preferences.AppleIDPrefPane"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_appleid_preference_pane_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_appleid_preference_pane_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) icloud_appleid_preference_pane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_appleid_preference_pane_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_appleid_preference_pane_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_appleid_preference_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_appleid_preference_pane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_appleid_preference_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) icloud_appleid_preference_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_appleid_preference_pane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_appleid_preference_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_appleid_preference_pane_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_appleid_preference_pane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_bookmarks_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_bookmarks_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudBookmarks').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_bookmarks_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_bookmarks_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) icloud_bookmarks_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_bookmarks_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_bookmarks_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_bookmarks_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) icloud_bookmarks_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_bookmarks_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_bookmarks_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_calendar_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_calendar_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudCalendar').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_calendar_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_calendar_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) icloud_calendar_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_calendar_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_calendar_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_calendar_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) icloud_calendar_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_calendar_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_calendar_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_drive_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_drive_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDocumentSync').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_drive_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_drive_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) icloud_drive_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_drive_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_drive_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_drive_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) icloud_drive_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_drive_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_drive_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_keychain_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_keychain_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudKeychainSync').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_keychain_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_keychain_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) icloud_keychain_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_keychain_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_keychain_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_keychain_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) icloud_keychain_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_keychain_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_keychain_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_mail_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_mail_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudMail').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_mail_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_mail_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) icloud_mail_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_mail_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_mail_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_mail_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) icloud_mail_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_mail_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_mail_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_notes_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_notes_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudNotes').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_notes_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_notes_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) icloud_notes_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_notes_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_notes_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_notes_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) icloud_notes_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_notes_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_notes_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_photos_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_photos_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPhotoLibrary').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_photos_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_photos_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) icloud_photos_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_photos_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_photos_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_photos_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) icloud_photos_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_photos_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_photos_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_reminders_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_reminders_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudReminders').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_reminders_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('icloud_reminders_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) icloud_reminders_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - icloud_reminders_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) icloud_reminders_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_reminders_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) icloud_reminders_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - icloud_reminders_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) icloud_reminders_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_airdrop_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_airdrop_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirDrop').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_airdrop_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_airdrop_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) os_airdrop_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_airdrop_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_airdrop_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_anti_virus_installed -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_anti_virus_installed ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl list | /usr/bin/grep -cE "(com.apple.XprotectFramework.PluginService$|com.apple.XProtect.daemon.scan$)"
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_anti_virus_installed'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_anti_virus_installed'))["exempt_reason"]
EOS
)

    if [[ $result_value == "2" ]]; then
        echo "$(date -u) os_anti_virus_installed passed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_anti_virus_installed passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_anti_virus_installed failed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_anti_virus_installed failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            echo "$(date -u) os_anti_virus_installed failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_anti_virus_installed failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_anti_virus_installed does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add finding -bool NO
fi
    
#####----- Rule: os_appleid_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_appleid_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipCloudSetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_appleid_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_appleid_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_appleid_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_appleid_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_appleid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_appleid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_appleid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_appleid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_appleid_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_asl_log_files_owner_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_asl_log_files_owner_group_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_asl_log_files_owner_group_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_asl_log_files_owner_group_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) os_asl_log_files_owner_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_asl_log_files_owner_group_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_asl_log_files_owner_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_asl_log_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_asl_log_files_owner_group_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_asl_log_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) os_asl_log_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_asl_log_files_owner_group_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_asl_log_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_asl_log_files_owner_group_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_asl_log_files_owner_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_asl_log_files_permissions_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_asl_log_files_permissions_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_asl_log_files_permissions_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_asl_log_files_permissions_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) os_asl_log_files_permissions_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_asl_log_files_permissions_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_asl_log_files_permissions_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_asl_log_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_asl_log_files_permissions_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_asl_log_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) os_asl_log_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_asl_log_files_permissions_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_asl_log_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_asl_log_files_permissions_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_asl_log_files_permissions_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_blank_bluray_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_blank_bluray_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver')\
.objectForKey('mount-controls'))["blankbd"]
EOS
)
    # expected result {'string': 'deny'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_blank_bluray_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_blank_bluray_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "deny" ]]; then
        echo "$(date -u) os_blank_bluray_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_blank_bluray_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_blank_bluray_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_blank_bluray_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_blank_bluray_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_blank_bluray_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")"
        else
            echo "$(date -u) os_blank_bluray_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_blank_bluray_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_blank_bluray_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_blank_bluray_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_blank_bluray_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_blank_cd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_blank_cd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver')\
.objectForKey('mount-controls'))["blankcd"]
EOS
)
    # expected result {'string': 'deny'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_blank_cd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_blank_cd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "deny" ]]; then
        echo "$(date -u) os_blank_cd_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_blank_cd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_blank_cd_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_blank_cd_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_blank_cd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_blank_cd_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")"
        else
            echo "$(date -u) os_blank_cd_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_blank_cd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_blank_cd_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_blank_cd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_blank_cd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_blank_dvd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_blank_dvd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver')\
.objectForKey('mount-controls'))["blankdvd"]
EOS
)
    # expected result {'string': 'deny'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_blank_dvd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_blank_dvd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "deny" ]]; then
        echo "$(date -u) os_blank_dvd_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_blank_dvd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_blank_dvd_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_blank_dvd_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_blank_dvd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_blank_dvd_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")"
        else
            echo "$(date -u) os_blank_dvd_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_blank_dvd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_blank_dvd_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_blank_dvd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_blank_dvd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_bluray_read_only_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_bluray_read_only_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver')\
.objectForKey('mount-controls'))["bd"]
EOS
)
    # expected result {'string': 'read-only'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_bluray_read_only_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_bluray_read_only_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "read-only" ]]; then
        echo "$(date -u) os_bluray_read_only_enforce passed (Result: $result_value, Expected: "{'string': 'read-only'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_bluray_read_only_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_bluray_read_only_enforce passed (Result: $result_value, Expected: "{'string': 'read-only'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_bluray_read_only_enforce failed (Result: $result_value, Expected: "{'string': 'read-only'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_bluray_read_only_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_bluray_read_only_enforce failed (Result: $result_value, Expected: "{'string': 'read-only'}")"
        else
            echo "$(date -u) os_bluray_read_only_enforce failed (Result: $result_value, Expected: "{'string': 'read-only'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_bluray_read_only_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_bluray_read_only_enforce failed (Result: $result_value, Expected: "{'string': 'read-only'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_bluray_read_only_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_bluray_read_only_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_bonjour_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_bonjour_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.mDNSResponder')\
.objectForKey('NoMulticastAdvertisements').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_bonjour_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_bonjour_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_bonjour_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_bonjour_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_bonjour_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_bonjour_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_bonjour_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_bonjour_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_bonjour_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_burn_support_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_burn_support_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(BurnSupport = off;|ProhibitBurn = 1;)'
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_burn_support_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_burn_support_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "2" ]]; then
        echo "$(date -u) os_burn_support_disable passed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_burn_support_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_burn_support_disable passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_burn_support_disable failed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_burn_support_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_burn_support_disable failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            echo "$(date -u) os_burn_support_disable failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_burn_support_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_burn_support_disable failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_burn_support_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_burn_support_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_camera_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_camera_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCamera').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_camera_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_camera_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) os_camera_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_camera_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_camera_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_camera_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_camera_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_camera_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) os_camera_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_camera_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_camera_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_camera_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_camera_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_cd_read_only_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_cd_read_only_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver')\
.objectForKey('mount-controls'))["cd"]
EOS
)
    # expected result {'string': 'read-only'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_cd_read_only_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_cd_read_only_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "read-only" ]]; then
        echo "$(date -u) os_cd_read_only_enforce passed (Result: $result_value, Expected: "{'string': 'read-only'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_cd_read_only_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_cd_read_only_enforce passed (Result: $result_value, Expected: "{'string': 'read-only'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_cd_read_only_enforce failed (Result: $result_value, Expected: "{'string': 'read-only'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_cd_read_only_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_cd_read_only_enforce failed (Result: $result_value, Expected: "{'string': 'read-only'}")"
        else
            echo "$(date -u) os_cd_read_only_enforce failed (Result: $result_value, Expected: "{'string': 'read-only'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_cd_read_only_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_cd_read_only_enforce failed (Result: $result_value, Expected: "{'string': 'read-only'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_cd_read_only_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_cd_read_only_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_config_data_install_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-2(5)
# * SI-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_config_data_install_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('ConfigDataInstall').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_config_data_install_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_config_data_install_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_config_data_install_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_config_data_install_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_config_data_install_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_directory_services_configured -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_directory_services_configured ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/dscl localhost -list . | /usr/bin/grep -qvE '(Contact|Search|Local|^$)'; /bin/echo $?
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_directory_services_configured'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_directory_services_configured'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) os_directory_services_configured passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_directory_services_configured -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_directory_services_configured passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_directory_services_configured failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_directory_services_configured -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_directory_services_configured failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) os_directory_services_configured failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_directory_services_configured -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_directory_services_configured failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_directory_services_configured does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_directory_services_configured -dict-add finding -bool NO
fi
    
#####----- Rule: os_disk_image_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_disk_image_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver')\
.objectForKey('mount-controls'))["disk-image"]
EOS
)
    # expected result {'string': 'deny'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_disk_image_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_disk_image_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "deny" ]]; then
        echo "$(date -u) os_disk_image_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_disk_image_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_disk_image_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_disk_image_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_disk_image_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_disk_image_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")"
        else
            echo "$(date -u) os_disk_image_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_disk_image_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_disk_image_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_disk_image_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_disk_image_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_dvdram_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_dvdram_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver')\
.objectForKey('mount-controls'))["dvdram"]
EOS
)
    # expected result {'string': 'deny'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_dvdram_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_dvdram_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "deny" ]]; then
        echo "$(date -u) os_dvdram_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_dvdram_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_dvdram_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_dvdram_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_dvdram_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_dvdram_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")"
        else
            echo "$(date -u) os_dvdram_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_dvdram_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_dvdram_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_dvdram_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_dvdram_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_erase_content_and_settings_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_erase_content_and_settings_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowEraseContentAndSettings').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_erase_content_and_settings_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_erase_content_and_settings_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) os_erase_content_and_settings_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_erase_content_and_settings_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_erase_content_and_settings_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_erase_content_and_settings_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_erase_content_and_settings_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_erase_content_and_settings_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) os_erase_content_and_settings_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_erase_content_and_settings_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_erase_content_and_settings_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_erase_content_and_settings_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_erase_content_and_settings_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_filevault_autologin_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(11)
# * AC-3
# * IA-5(13)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_filevault_autologin_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('DisableFDEAutoLogin').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_filevault_autologin_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_filevault_autologin_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_filevault_autologin_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_filevault_autologin_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_filevault_autologin_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_filevault_autologin_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_filevault_autologin_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_filevault_autologin_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_filevault_autologin_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_filevault_autologin_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_filevault_autologin_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_filevault_autologin_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_filevault_autologin_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_firmware_password_require -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6
rule_arch="i386"
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_firmware_password_require ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/firmwarepasswd -check | /usr/bin/grep -c "Password Enabled: Yes"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_firmware_password_require'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_firmware_password_require'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_firmware_password_require passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_firmware_password_require -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_firmware_password_require passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_firmware_password_require failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_firmware_password_require -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_firmware_password_require failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_firmware_password_require failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_firmware_password_require -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_firmware_password_require failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_firmware_password_require does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_firmware_password_require -dict-add finding -bool NO
fi
    
#####----- Rule: os_gatekeeper_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-3
# * SI-7(1), SI-7(15)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_gatekeeper_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_gatekeeper_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_gatekeeper_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_gatekeeper_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_gatekeeper_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_gatekeeper_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_handoff_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_handoff_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowActivityContinuation').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_handoff_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_handoff_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) os_handoff_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_handoff_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_handoff_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_handoff_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) os_handoff_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_handoff_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_handoff_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_httpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_httpd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_httpd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_httpd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_httpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_httpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_httpd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_icloud_storage_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_icloud_storage_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipiCloudStorageSetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_icloud_storage_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_icloud_storage_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_icloud_storage_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_icloud_storage_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_icloud_storage_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_icloud_storage_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_icloud_storage_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_icloud_storage_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_icloud_storage_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_newsyslog_files_owner_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_newsyslog_files_owner_group_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_newsyslog_files_owner_group_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_newsyslog_files_owner_group_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) os_newsyslog_files_owner_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_newsyslog_files_owner_group_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_newsyslog_files_owner_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_newsyslog_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_newsyslog_files_owner_group_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_newsyslog_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) os_newsyslog_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_newsyslog_files_owner_group_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_newsyslog_files_owner_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_newsyslog_files_owner_group_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_newsyslog_files_owner_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_newsyslog_files_permissions_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_newsyslog_files_permissions_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_newsyslog_files_permissions_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_newsyslog_files_permissions_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) os_newsyslog_files_permissions_configure passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_newsyslog_files_permissions_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_newsyslog_files_permissions_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_newsyslog_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_newsyslog_files_permissions_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_newsyslog_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) os_newsyslog_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_newsyslog_files_permissions_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_newsyslog_files_permissions_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_newsyslog_files_permissions_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_newsyslog_files_permissions_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_nfsd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_nfsd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.nfsd" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_nfsd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_nfsd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_nfsd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_nfsd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_nfsd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_password_proximity_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_password_proximity_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordProximityRequests').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_password_proximity_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_password_proximity_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) os_password_proximity_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_password_proximity_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_password_proximity_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_password_proximity_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) os_password_proximity_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_password_proximity_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_password_proximity_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_policy_banner_loginwindow_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-8
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_policy_banner_loginwindow_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | /usr/bin/tr -d ' '
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_loginwindow_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_loginwindow_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_policy_banner_loginwindow_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_policy_banner_loginwindow_enforce passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_policy_banner_loginwindow_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_policy_banner_loginwindow_enforce failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_policy_banner_loginwindow_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_policy_banner_loginwindow_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_policy_banner_loginwindow_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_policy_banner_loginwindow_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_policy_banner_ssh_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-8
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_policy_banner_ssh_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(bannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
test "$(cat /etc/banner)" = "$bannerText" && echo "1" || echo "0"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_ssh_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_ssh_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_policy_banner_ssh_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_policy_banner_ssh_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_policy_banner_ssh_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_policy_banner_ssh_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_policy_banner_ssh_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_policy_banner_ssh_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_policy_banner_ssh_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_policy_banner_ssh_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_policy_banner_ssh_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_policy_banner_ssh_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_policy_banner_ssh_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_policy_banner_ssh_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-8
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_policy_banner_ssh_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/sshd -T | /usr/bin/grep -c "^banner /etc/banner"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_ssh_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_ssh_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_policy_banner_ssh_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_policy_banner_ssh_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_policy_banner_ssh_enforce passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_policy_banner_ssh_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_policy_banner_ssh_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_policy_banner_ssh_enforce failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_policy_banner_ssh_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_policy_banner_ssh_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_policy_banner_ssh_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_policy_banner_ssh_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_policy_banner_ssh_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_privacy_setup_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_privacy_setup_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipPrivacySetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_privacy_setup_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_privacy_setup_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_privacy_setup_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_privacy_setup_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_privacy_setup_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_privacy_setup_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_privacy_setup_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_privacy_setup_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_privacy_setup_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_privacy_setup_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_privacy_setup_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_privacy_setup_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_privacy_setup_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_removable_media_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * MP-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_removable_media_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver')\
.objectForKey('mount-controls'))["harddisk-external"]
EOS
)
    # expected result {'string': 'deny'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_removable_media_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_removable_media_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "deny" ]]; then
        echo "$(date -u) os_removable_media_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_removable_media_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_removable_media_disable passed (Result: $result_value, Expected: "{'string': 'deny'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_removable_media_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_removable_media_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_removable_media_disable failed (Result: $result_value, Expected: "{'string': 'deny'}")"
        else
            echo "$(date -u) os_removable_media_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_removable_media_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_removable_media_disable failed (Result: $result_value, Expected: "{'string': 'deny'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_removable_media_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_removable_media_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_screensaver_loginwindow_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_screensaver_loginwindow_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('moduleName').js
EOS
)
    # expected result {'string': 'ventura'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_screensaver_loginwindow_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_screensaver_loginwindow_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "Ventura" ]]; then
        echo "$(date -u) os_screensaver_loginwindow_enforce passed (Result: $result_value, Expected: "{'string': 'ventura'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_screensaver_loginwindow_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_screensaver_loginwindow_enforce passed (Result: $result_value, Expected: "{'string': 'ventura'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_screensaver_loginwindow_enforce failed (Result: $result_value, Expected: "{'string': 'ventura'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_screensaver_loginwindow_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_screensaver_loginwindow_enforce failed (Result: $result_value, Expected: "{'string': 'ventura'}")"
        else
            echo "$(date -u) os_screensaver_loginwindow_enforce failed (Result: $result_value, Expected: "{'string': 'ventura'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_screensaver_loginwindow_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_screensaver_loginwindow_enforce failed (Result: $result_value, Expected: "{'string': 'ventura'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_screensaver_loginwindow_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_screensaver_loginwindow_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_screensaver_timeout_loginwindow_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
# * IA-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_screensaver_timeout_loginwindow_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('loginWindowIdleTime'))
  if ( timeout <= 900 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_screensaver_timeout_loginwindow_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_screensaver_timeout_loginwindow_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_screensaver_timeout_loginwindow_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_screensaver_timeout_loginwindow_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_screensaver_timeout_loginwindow_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_screensaver_timeout_loginwindow_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_screensaver_timeout_loginwindow_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_screensaver_timeout_loginwindow_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_screensaver_timeout_loginwindow_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_screensaver_timeout_loginwindow_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_screensaver_timeout_loginwindow_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_screensaver_timeout_loginwindow_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_screensaver_timeout_loginwindow_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_sip_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * AU-9, AU-9(3)
# * CM-5, CM-5(6)
# * SC-4
# * SI-2
# * SI-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sip_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sip_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sip_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_sip_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_sip_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_sip_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sip_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_sip_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sip_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_sip_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_siri_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_siri_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSiriSetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_siri_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_siri_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_siri_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_siri_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_siri_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_siri_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_siri_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_siri_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_siri_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_skip_screen_time_prompt_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_skip_screen_time_prompt_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipScreenTime').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_skip_screen_time_prompt_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_skip_screen_time_prompt_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_skip_screen_time_prompt_enable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_skip_screen_time_prompt_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_skip_screen_time_prompt_enable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_skip_screen_time_prompt_enable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_skip_screen_time_prompt_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_skip_screen_time_prompt_enable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_skip_screen_time_prompt_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_skip_screen_time_prompt_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_skip_screen_time_prompt_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_skip_screen_time_prompt_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_skip_screen_time_prompt_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_skip_unlock_with_watch_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_skip_unlock_with_watch_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipUnlockWithWatch').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_skip_unlock_with_watch_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_skip_unlock_with_watch_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_skip_unlock_with_watch_enable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_skip_unlock_with_watch_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_skip_unlock_with_watch_enable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_skip_unlock_with_watch_enable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_skip_unlock_with_watch_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_skip_unlock_with_watch_enable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_skip_unlock_with_watch_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_skip_unlock_with_watch_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_skip_unlock_with_watch_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_skip_unlock_with_watch_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_skip_unlock_with_watch_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_sshd_client_alive_count_max_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-10
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sshd_client_alive_count_max_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/sshd -T | /usr/bin/awk '/clientalivecountmax/{print $2}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_client_alive_count_max_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_client_alive_count_max_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_sshd_client_alive_count_max_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_sshd_client_alive_count_max_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_sshd_client_alive_count_max_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_sshd_client_alive_count_max_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_client_alive_count_max_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_client_alive_count_max_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_sshd_client_alive_count_max_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_client_alive_count_max_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_client_alive_count_max_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_sshd_client_alive_count_max_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_sshd_client_alive_count_max_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_sshd_client_alive_interval_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-12
# * SC-10
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sshd_client_alive_interval_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/sshd -T | /usr/bin/awk '/clientaliveinterval/{print $2}'
)
    # expected result {'integer': 900}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_client_alive_interval_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_client_alive_interval_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "900" ]]; then
        echo "$(date -u) os_sshd_client_alive_interval_configure passed (Result: $result_value, Expected: "{'integer': 900}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_sshd_client_alive_interval_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_sshd_client_alive_interval_configure passed (Result: $result_value, Expected: "{'integer': 900}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_sshd_client_alive_interval_configure failed (Result: $result_value, Expected: "{'integer': 900}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_client_alive_interval_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_client_alive_interval_configure failed (Result: $result_value, Expected: "{'integer': 900}")"
        else
            echo "$(date -u) os_sshd_client_alive_interval_configure failed (Result: $result_value, Expected: "{'integer': 900}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_client_alive_interval_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_client_alive_interval_configure failed (Result: $result_value, Expected: "{'integer': 900}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_sshd_client_alive_interval_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_sshd_client_alive_interval_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_sshd_fips_140_ciphers -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * SC-13
# * SC-8(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sshd_fips_140_ciphers ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/sshd -T | /usr/bin/grep -ci "^Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_fips_140_ciphers'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_fips_140_ciphers'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_sshd_fips_140_ciphers passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_sshd_fips_140_ciphers -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_sshd_fips_140_ciphers passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_sshd_fips_140_ciphers failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_fips_140_ciphers -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_fips_140_ciphers failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_sshd_fips_140_ciphers failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_fips_140_ciphers -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_fips_140_ciphers failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_sshd_fips_140_ciphers does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_sshd_fips_140_ciphers -dict-add finding -bool NO
fi
    
#####----- Rule: os_sshd_fips_140_macs -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * SC-13
# * SC-8(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sshd_fips_140_macs ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/sshd -T | /usr/bin/grep -ci "^MACs hmac-sha2-256,hmac-sha2-512"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_fips_140_macs'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_fips_140_macs'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_sshd_fips_140_macs passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_sshd_fips_140_macs -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_sshd_fips_140_macs passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_sshd_fips_140_macs failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_fips_140_macs -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_fips_140_macs failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_sshd_fips_140_macs failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_fips_140_macs -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_fips_140_macs failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_sshd_fips_140_macs does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_sshd_fips_140_macs -dict-add finding -bool NO
fi
    
#####----- Rule: os_sshd_key_exchange_algorithm_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * MA-4(6)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sshd_key_exchange_algorithm_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/sshd -T | /usr/bin/grep -ci "^KexAlgorithms diffie-hellman-group-exchange-sha256"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_key_exchange_algorithm_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_key_exchange_algorithm_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_sshd_key_exchange_algorithm_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_sshd_key_exchange_algorithm_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_sshd_key_exchange_algorithm_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_sshd_key_exchange_algorithm_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_key_exchange_algorithm_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_key_exchange_algorithm_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_sshd_key_exchange_algorithm_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_key_exchange_algorithm_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_key_exchange_algorithm_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_sshd_key_exchange_algorithm_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_sshd_key_exchange_algorithm_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_sshd_login_grace_time_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-10
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sshd_login_grace_time_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/sshd -T | /usr/bin/awk '/logingracetime/{print $2}'
)
    # expected result {'integer': 30}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_login_grace_time_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_login_grace_time_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "30" ]]; then
        echo "$(date -u) os_sshd_login_grace_time_configure passed (Result: $result_value, Expected: "{'integer': 30}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_sshd_login_grace_time_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_sshd_login_grace_time_configure passed (Result: $result_value, Expected: "{'integer': 30}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_sshd_login_grace_time_configure failed (Result: $result_value, Expected: "{'integer': 30}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_login_grace_time_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_login_grace_time_configure failed (Result: $result_value, Expected: "{'integer': 30}")"
        else
            echo "$(date -u) os_sshd_login_grace_time_configure failed (Result: $result_value, Expected: "{'integer': 30}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_login_grace_time_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_login_grace_time_configure failed (Result: $result_value, Expected: "{'integer': 30}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_sshd_login_grace_time_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_sshd_login_grace_time_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_sshd_permit_root_login_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sshd_permit_root_login_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/sshd -T | /usr/bin/awk '/permitrootlogin/{print $2}'
)
    # expected result {'string': 'no'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_permit_root_login_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_permit_root_login_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "no" ]]; then
        echo "$(date -u) os_sshd_permit_root_login_configure passed (Result: $result_value, Expected: "{'string': 'no'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_sshd_permit_root_login_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_sshd_permit_root_login_configure passed (Result: $result_value, Expected: "{'string': 'no'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_sshd_permit_root_login_configure failed (Result: $result_value, Expected: "{'string': 'no'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_permit_root_login_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_permit_root_login_configure failed (Result: $result_value, Expected: "{'string': 'no'}")"
        else
            echo "$(date -u) os_sshd_permit_root_login_configure failed (Result: $result_value, Expected: "{'string': 'no'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sshd_permit_root_login_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sshd_permit_root_login_configure failed (Result: $result_value, Expected: "{'string': 'no'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_sshd_permit_root_login_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_sshd_permit_root_login_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_sudo_timeout_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_sudo_timeout_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c "Authentication timestamp timeout: 0.0 minutes"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sudo_timeout_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sudo_timeout_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_sudo_timeout_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_sudo_timeout_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_sudo_timeout_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sudo_timeout_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_sudo_timeout_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_sudo_timeout_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_sudo_timeout_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_tftpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_tftpd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.tftpd" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_tftpd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_tftpd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_tftpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_tftpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_tftpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_tftpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_tftpd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_tftpd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_tftpd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_time_server_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_time_server_enabled ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl list | /usr/bin/grep -c com.apple.timed
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_time_server_enabled'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_time_server_enabled'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_time_server_enabled passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_time_server_enabled passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_time_server_enabled failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_time_server_enabled failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_time_server_enabled failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_time_server_enabled failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_time_server_enabled does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool NO
fi
    
#####----- Rule: os_touchid_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_touchid_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipTouchIDSetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_touchid_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_touchid_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) os_touchid_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_touchid_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_touchid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_touchid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) os_touchid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_touchid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_touchid_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_uucp_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_uucp_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.uucp" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_uucp_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_uucp_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) os_uucp_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - os_uucp_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) os_uucp_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_uucp_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) os_uucp_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - os_uucp_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) os_uucp_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_account_lockout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_account_lockout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 <= 3) {print "yes"} else {print "no"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_account_lockout_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_account_lockout_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "yes" ]]; then
        echo "$(date -u) pwpolicy_account_lockout_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_account_lockout_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) pwpolicy_account_lockout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_account_lockout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            echo "$(date -u) pwpolicy_account_lockout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_account_lockout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) pwpolicy_account_lockout_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_account_lockout_timeout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_account_lockout_timeout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="autoEnableInSeconds"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1/60 >= 15 ) {print "yes"} else {print "no"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_account_lockout_timeout_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_account_lockout_timeout_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "yes" ]]; then
        echo "$(date -u) pwpolicy_account_lockout_timeout_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_account_lockout_timeout_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) pwpolicy_account_lockout_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_account_lockout_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            echo "$(date -u) pwpolicy_account_lockout_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_account_lockout_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) pwpolicy_account_lockout_timeout_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_alpha_numeric_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_alpha_numeric_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyIdentifier"]/following-sibling::*[1]/text()' - | /usr/bin/grep "requireAlphanumeric" -c
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_alpha_numeric_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_alpha_numeric_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) pwpolicy_alpha_numeric_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_alpha_numeric_enforce passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) pwpolicy_alpha_numeric_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_alpha_numeric_enforce failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) pwpolicy_alpha_numeric_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_alpha_numeric_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) pwpolicy_alpha_numeric_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_history_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_history_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributePasswordHistoryDepth"]/following-sibling::*[1]/text()' - | /usr/bin/awk '{ if ($1 >= 5 ) {print "yes"} else {print "no"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_history_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_history_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "yes" ]]; then
        echo "$(date -u) pwpolicy_history_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_history_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) pwpolicy_history_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_history_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            echo "$(date -u) pwpolicy_history_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_history_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) pwpolicy_history_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_max_lifetime_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_max_lifetime_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeExpiresEveryNDays"]/following-sibling::*[1]/text()' -
)
    # expected result {'integer': 60}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_max_lifetime_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_max_lifetime_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "60" ]]; then
        echo "$(date -u) pwpolicy_max_lifetime_enforce passed (Result: $result_value, Expected: "{'integer': 60}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_max_lifetime_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_max_lifetime_enforce passed (Result: $result_value, Expected: "{'integer': 60}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) pwpolicy_max_lifetime_enforce failed (Result: $result_value, Expected: "{'integer': 60}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_max_lifetime_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_max_lifetime_enforce failed (Result: $result_value, Expected: "{'integer': 60}")"
        else
            echo "$(date -u) pwpolicy_max_lifetime_enforce failed (Result: $result_value, Expected: "{'integer': 60}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_max_lifetime_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_max_lifetime_enforce failed (Result: $result_value, Expected: "{'integer': 60}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) pwpolicy_max_lifetime_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_max_lifetime_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_minimum_length_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_minimum_length_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''.{15,}'\''")])' -
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_minimum_length_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_minimum_length_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) pwpolicy_minimum_length_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_minimum_length_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) pwpolicy_minimum_length_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_minimum_length_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) pwpolicy_minimum_length_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_minimum_length_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) pwpolicy_minimum_length_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_simple_sequence_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_simple_sequence_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyIdentifier"]/following-sibling::*[1]/text()' - | /usr/bin/grep "allowSimple" -c
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_simple_sequence_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_simple_sequence_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) pwpolicy_simple_sequence_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_simple_sequence_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) pwpolicy_simple_sequence_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_simple_sequence_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) pwpolicy_simple_sequence_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_simple_sequence_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) pwpolicy_simple_sequence_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_special_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_special_character_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''(.*[^a-zA-Z0-9].*){1,}'\''")])' -
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_special_character_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('pwpolicy_special_character_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) pwpolicy_special_character_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_special_character_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) pwpolicy_special_character_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_special_character_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) pwpolicy_special_character_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - pwpolicy_special_character_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) pwpolicy_special_character_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_apple_watch_unlock_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_apple_watch_unlock_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAutoUnlock').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_apple_watch_unlock_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_apple_watch_unlock_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) system_settings_apple_watch_unlock_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_apple_watch_unlock_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_apple_watch_unlock_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_apple_watch_unlock_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_apple_watch_unlock_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_apple_watch_unlock_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) system_settings_apple_watch_unlock_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_apple_watch_unlock_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_apple_watch_unlock_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_apple_watch_unlock_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_apple_watch_unlock_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_assistant_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_assistant_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.ironwood.support')\
.objectForKey('Assistant Allowed').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_assistant_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_assistant_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) system_settings_assistant_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_assistant_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_assistant_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_assistant_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_assistant_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_assistant_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) system_settings_assistant_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_assistant_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_assistant_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_assistant_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_assistant_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_automatic_login_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2
# * IA-5(13)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_automatic_login_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('com.apple.login.mcx.DisableAutoLoginClient').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_automatic_login_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_automatic_login_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_automatic_login_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_automatic_login_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_automatic_login_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_automatic_login_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_automatic_login_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_automatic_login_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_automatic_login_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_bluetooth_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18, AC-18(3)
# * SC-8
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_bluetooth_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCXBluetooth')\
.objectForKey('DisableBluetooth').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_bluetooth_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_bluetooth_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_bluetooth_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_bluetooth_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_bluetooth_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_bluetooth_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_bluetooth_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_bluetooth_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_bluetooth_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_bluetooth_prefpane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_bluetooth_prefpane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledPreferencePanes"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.preferences.Bluetooth
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_bluetooth_prefpane_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_bluetooth_prefpane_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_bluetooth_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_prefpane_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_bluetooth_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_bluetooth_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_bluetooth_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_bluetooth_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_bluetooth_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_bluetooth_prefpane_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_prefpane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_diagnostics_reports_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * SC-7(10)
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_diagnostics_reports_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.SubmitDiagInfo')\
.objectForKey('AutoSubmit').js
let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowDiagnosticSubmission').js
if ( pref1 == false && pref2 == false ){
    return("true")
} else {
    return("false")
}
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_diagnostics_reports_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_diagnostics_reports_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_diagnostics_reports_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_diagnostics_reports_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_diagnostics_reports_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_diagnostics_reports_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_diagnostics_reports_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_diagnostics_reports_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_diagnostics_reports_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_diagnostics_reports_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_diagnostics_reports_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_diagnostics_reports_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_diagnostics_reports_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_filevault_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-28, SC-28(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_filevault_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(dontAllowDisable=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('dontAllowFDEDisable').js
EOS
)
fileVault=$(/usr/bin/fdesetup status | /usr/bin/grep -c "FileVault is On.")
if [[ "$dontAllowDisable" == "true" ]] && [[ "$fileVault" == 1 ]]; then
  echo "1"
else
  echo "0"
fi
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_filevault_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_filevault_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_filevault_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_filevault_enforce passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_filevault_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_firewall_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-4
# * CM-7, CM-7(1)
# * SC-7, SC-7(12)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_firewall_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(profile="$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
.objectForKey('EnableFirewall').js
EOS
)"

plist="$(/usr/bin/defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)"

if [[ "$profile" == "true" ]] && [[ "$plist" =~ [1,2] ]]; then
  echo "true"
else
  echo "false"
fi
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_firewall_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_firewall_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_firewall_enable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_firewall_enable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_firewall_enable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_firewall_enable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_firewall_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_firewall_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_firewall_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_firewall_stealth_mode_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7, SC-7(16)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_firewall_stealth_mode_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(profile="$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
.objectForKey('EnableStealthMode').js
EOS
)"

plist=$(/usr/bin/defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)

if [[ "$profile" == "true" ]] && [[ $plist == 1 ]]; then
  echo "true"
else
  echo "false"
fi
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_firewall_stealth_mode_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_firewall_stealth_mode_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_firewall_stealth_mode_enable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_firewall_stealth_mode_enable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_firewall_stealth_mode_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_gatekeeper_identified_developers_allowed -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-7(1), SI-7(15)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_gatekeeper_identified_developers_allowed ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/spctl --status --verbose | /usr/bin/grep -c "developer id enabled"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_gatekeeper_identified_developers_allowed'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_gatekeeper_identified_developers_allowed'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_gatekeeper_identified_developers_allowed passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_gatekeeper_identified_developers_allowed -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_gatekeeper_identified_developers_allowed passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_gatekeeper_identified_developers_allowed failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_gatekeeper_identified_developers_allowed -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_gatekeeper_identified_developers_allowed failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_gatekeeper_identified_developers_allowed failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_gatekeeper_identified_developers_allowed -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_gatekeeper_identified_developers_allowed failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_gatekeeper_identified_developers_allowed does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_gatekeeper_identified_developers_allowed -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_guest_account_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_guest_account_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('DisableGuestAccount'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('EnableGuestAccount'))
  if ( pref1 == true && pref2 == false ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_guest_account_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_guest_account_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_guest_account_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_guest_account_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_guest_account_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_hot_corners_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_hot_corners_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '"wvous-bl-corner" = 0|"wvous-br-corner" = 0|"wvous-tl-corner" = 0|"wvous-tr-corner" = 0'
)
    # expected result {'integer': 4}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_hot_corners_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_hot_corners_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "4" ]]; then
        echo "$(date -u) system_settings_hot_corners_disable passed (Result: $result_value, Expected: "{'integer': 4}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_hot_corners_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_hot_corners_disable passed (Result: $result_value, Expected: "{'integer': 4}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_hot_corners_disable failed (Result: $result_value, Expected: "{'integer': 4}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_hot_corners_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_hot_corners_disable failed (Result: $result_value, Expected: "{'integer': 4}")"
        else
            echo "$(date -u) system_settings_hot_corners_disable failed (Result: $result_value, Expected: "{'integer': 4}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_hot_corners_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_hot_corners_disable failed (Result: $result_value, Expected: "{'integer': 4}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_hot_corners_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_hot_corners_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_improve_siri_dictation_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_improve_siri_dictation_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support')\
.objectForKey('Siri Data Sharing Opt-In Status').js
EOS
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_improve_siri_dictation_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_improve_siri_dictation_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "2" ]]; then
        echo "$(date -u) system_settings_improve_siri_dictation_disable passed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_improve_siri_dictation_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_improve_siri_dictation_disable passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_improve_siri_dictation_disable failed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_improve_siri_dictation_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_improve_siri_dictation_disable failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            echo "$(date -u) system_settings_improve_siri_dictation_disable failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_improve_siri_dictation_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_improve_siri_dictation_disable failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_improve_siri_dictation_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_improve_siri_dictation_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_internet_accounts_preference_pane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_internet_accounts_preference_pane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledPreferencePanes"]/following-sibling::*[1]' - | /usr/bin/grep -c "com.apple.preferences.internetaccounts"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_internet_accounts_preference_pane_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_internet_accounts_preference_pane_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_internet_accounts_preference_pane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_internet_accounts_preference_pane_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_internet_accounts_preference_pane_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_internet_accounts_preference_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_internet_accounts_preference_pane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_internet_accounts_preference_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_internet_accounts_preference_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_internet_accounts_preference_pane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_internet_accounts_preference_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_internet_accounts_preference_pane_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_internet_accounts_preference_pane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_internet_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-4
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_internet_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('forceInternetSharingOff').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_internet_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_internet_sharing_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_internet_sharing_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_internet_sharing_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_internet_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_location_services_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_location_services_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/sudo -u _locationd /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.locationd')\
.objectForKey('LocationServicesEnabled').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_location_services_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_location_services_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) system_settings_location_services_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_location_services_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_location_services_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_location_services_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_location_services_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_location_services_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) system_settings_location_services_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_location_services_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_location_services_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_location_services_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_location_services_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_loginwindow_prompt_username_password_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_loginwindow_prompt_username_password_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('SHOWFULLNAME').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_loginwindow_prompt_username_password_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_loginwindow_prompt_username_password_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_loginwindow_prompt_username_password_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_loginwindow_prompt_username_password_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_loginwindow_prompt_username_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_loginwindow_prompt_username_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_loginwindow_prompt_username_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_loginwindow_prompt_username_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_loginwindow_prompt_username_password_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_password_hints_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_password_hints_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('RetriesUntilHint').js
EOS
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_password_hints_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_password_hints_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        echo "$(date -u) system_settings_password_hints_disable passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_password_hints_disable passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_password_hints_disable failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_password_hints_disable failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            echo "$(date -u) system_settings_password_hints_disable failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_password_hints_disable failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_password_hints_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_rae_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_rae_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AEServer" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_rae_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_rae_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_rae_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_rae_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_rae_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_screen_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_screen_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.screensharing" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screen_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screen_sharing_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_screen_sharing_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_screen_sharing_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_screen_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_screensaver_ask_for_password_delay_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_screensaver_ask_for_password_delay_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let delay = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPasswordDelay'))
  if ( delay <= 5 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screensaver_ask_for_password_delay_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screensaver_ask_for_password_delay_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_screensaver_ask_for_password_delay_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_screensaver_ask_for_password_delay_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_screensaver_ask_for_password_delay_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_screensaver_ask_for_password_delay_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_screensaver_ask_for_password_delay_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_screensaver_ask_for_password_delay_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_screensaver_ask_for_password_delay_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_screensaver_password_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_screensaver_password_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPassword').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screensaver_password_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screensaver_password_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_screensaver_password_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_screensaver_password_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_screensaver_password_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_screensaver_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_password_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_screensaver_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_screensaver_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_password_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_screensaver_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_screensaver_password_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_screensaver_password_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_screensaver_timeout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
# * IA-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_screensaver_timeout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('idleTime'))
  if ( timeout <= 900 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screensaver_timeout_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screensaver_timeout_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_screensaver_timeout_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_screensaver_timeout_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_screensaver_timeout_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_siri_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_siri_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.ironwood.support')\
.objectForKey('Ironwood Allowed').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_siri_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_siri_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        echo "$(date -u) system_settings_siri_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_siri_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_siri_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_siri_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_siri_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_siri_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            echo "$(date -u) system_settings_siri_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_siri_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_siri_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_siri_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_siri_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_siri_prefpane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_siri_prefpane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledPreferencePanes"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.preference.speech
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_siri_prefpane_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_siri_prefpane_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_siri_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_siri_prefpane_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_siri_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_siri_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_siri_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_siri_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_siri_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_siri_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_siri_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_siri_prefpane_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_siri_prefpane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_smbd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_smbd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.smbd" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_smbd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_smbd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_smbd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_smbd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_smbd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_ssh_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_ssh_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.openssh.sshd" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_ssh_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_ssh_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_ssh_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_ssh_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_ssh_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_ssh_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_ssh_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_ssh_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_ssh_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_system_wide_preferences_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6, AC-6(1), AC-6(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_system_wide_preferences_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")
result="1"
for section in ${authDBs[@]}; do
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "shared")]/following-sibling::*[1])' -) != "false" ]]; then
    result="0"
  fi
done
echo $result
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_system_wide_preferences_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_system_wide_preferences_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_system_wide_preferences_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_system_wide_preferences_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_system_wide_preferences_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_system_wide_preferences_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_system_wide_preferences_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_system_wide_preferences_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_system_wide_preferences_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_time_server_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_time_server_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('timeServer').js
EOS
)
    # expected result {'string': 'time-a.nist.gov,time-b.nist.gov'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_time_server_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_time_server_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "time-a.nist.gov,time-b.nist.gov" ]]; then
        echo "$(date -u) system_settings_time_server_configure passed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_time_server_configure passed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")"
        else
            echo "$(date -u) system_settings_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_time_server_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_time_server_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_time_server_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.timed')\
.objectForKey('TMAutomaticTimeOnlyEnabled').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_time_server_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_time_server_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        echo "$(date -u) system_settings_time_server_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_time_server_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            echo "$(date -u) system_settings_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_time_server_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_token_removal_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_token_removal_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('tokenRemovalAction').js
EOS
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_token_removal_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_token_removal_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_token_removal_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_token_removal_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_token_removal_enforce passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_token_removal_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_token_removal_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_token_removal_enforce failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_token_removal_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_token_removal_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_token_removal_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_token_removal_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_token_removal_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_touch_id_pane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_touch_id_pane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledPreferencePanes"]/following-sibling::*[1]' - | /usr/bin/grep -c "com.apple.preferences.password"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_touch_id_pane_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_touch_id_pane_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_touch_id_pane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_touch_id_pane_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_touch_id_pane_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_touch_id_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_touch_id_pane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_touch_id_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_touch_id_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_touch_id_pane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_touch_id_pane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_touch_id_pane_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_touch_id_pane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_wallet_applepay_prefpane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_wallet_applepay_prefpane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledPreferencePanes"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.preferences.wallet
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_wallet_applepay_prefpane_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_wallet_applepay_prefpane_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_wallet_applepay_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_wallet_applepay_prefpane_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_wallet_applepay_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_wallet_applepay_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_wallet_applepay_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_wallet_applepay_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_wallet_applepay_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_wallet_applepay_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_wallet_applepay_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_wallet_applepay_prefpane_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_wallet_applepay_prefpane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_wallet_applepay_prefpane_hide -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: system_settings_wallet_applepay_prefpane_hide ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="HiddenPreferencePanes"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.preferences.wallet
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_wallet_applepay_prefpane_hide'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_wallet_applepay_prefpane_hide'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        echo "$(date -u) system_settings_wallet_applepay_prefpane_hide passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" system_settings_wallet_applepay_prefpane_hide -dict-add finding -bool NO
        /usr/bin/logger "mSCP: DISA-STIG - system_settings_wallet_applepay_prefpane_hide passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            echo "$(date -u) system_settings_wallet_applepay_prefpane_hide failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_wallet_applepay_prefpane_hide -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_wallet_applepay_prefpane_hide failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            echo "$(date -u) system_settings_wallet_applepay_prefpane_hide failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" system_settings_wallet_applepay_prefpane_hide -dict-add finding -bool YES
            /usr/bin/logger "mSCP: DISA-STIG - system_settings_wallet_applepay_prefpane_hide failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    echo "$(date -u) system_settings_wallet_applepay_prefpane_hide does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" system_settings_wallet_applepay_prefpane_hide -dict-add finding -bool NO
fi
    
lastComplianceScan=$(defaults read "$audit_plist" lastComplianceCheck)
echo "Results written to $audit_plist"

if [[ ! $check ]] && [[ ! $cfc ]];then
    pause
fi

}

run_fix(){

if [[ ! -e "$audit_plist" ]]; then
    echo "Audit plist doesn't exist, please run Audit Check First" | tee -a "$audit_log"

    if [[ ! $fix ]]; then
        pause
        show_menus
        read_options
    else
        exit 1
    fi
fi

if [[ ! $fix ]] && [[ ! $cfc ]]; then
    ask 'THE SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER. WOULD YOU LIKE TO CONTINUE? ' N

    if [[ $? != 0 ]]; then
        show_menus
        read_options
    fi
fi

# append to existing logfile
echo "$(date -u) Beginning remediation of non-compliant settings" >> "$audit_log"

# remove uchg on audit_control
/usr/bin/chflags nouchg /etc/security/audit_control

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID


    
#####----- Rule: audit_acls_files_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_acls_files_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_acls_files_configure'))["exempt_reason"]
EOS
)

audit_acls_files_configure_audit_score=$($plb -c "print audit_acls_files_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_acls_files_configure_audit_score == "true" ]]; then
        ask 'audit_acls_files_configure - Run the command(s)-> /bin/chmod -RN /var/audit ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_acls_files_configure ..." | /usr/bin/tee -a "$audit_log"
            /bin/chmod -RN /var/audit
        fi
    else
        echo "$(date -u) Settings for: audit_acls_files_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_acls_files_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_acls_folders_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_acls_folders_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_acls_folders_configure'))["exempt_reason"]
EOS
)

audit_acls_folders_configure_audit_score=$($plb -c "print audit_acls_folders_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_acls_folders_configure_audit_score == "true" ]]; then
        ask 'audit_acls_folders_configure - Run the command(s)-> /bin/chmod -N /var/audit ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_acls_folders_configure ..." | /usr/bin/tee -a "$audit_log"
            /bin/chmod -N /var/audit
        fi
    else
        echo "$(date -u) Settings for: audit_acls_folders_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_acls_folders_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_auditd_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12, AU-12(1), AU-12(3)
# * AU-14(1)
# * AU-3, AU-3(1)
# * AU-8
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_auditd_enabled'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_auditd_enabled'))["exempt_reason"]
EOS
)

audit_auditd_enabled_audit_score=$($plb -c "print audit_auditd_enabled:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_auditd_enabled_audit_score == "true" ]]; then
        ask 'audit_auditd_enabled - Run the command(s)-> LAUNCHD_RUNNING=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd)

if [[ ! $LAUNCHD_RUNNING == 1 ]]; then
  /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
fi

if [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]];then
  /bin/cp /etc/security/audit_control.example /etc/security/audit_control
else
  /usr/bin/touch /etc/security/audit_control
fi ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_auditd_enabled ..." | /usr/bin/tee -a "$audit_log"
            LAUNCHD_RUNNING=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd)

if [[ ! $LAUNCHD_RUNNING == 1 ]]; then
  /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
fi

if [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]];then
  /bin/cp /etc/security/audit_control.example /etc/security/audit_control
else
  /usr/bin/touch /etc/security/audit_control
fi
        fi
    else
        echo "$(date -u) Settings for: audit_auditd_enabled already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_auditd_enabled has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_configure_capacity_notify -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_configure_capacity_notify'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_configure_capacity_notify'))["exempt_reason"]
EOS
)

audit_configure_capacity_notify_audit_score=$($plb -c "print audit_configure_capacity_notify:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_configure_capacity_notify_audit_score == "true" ]]; then
        ask 'audit_configure_capacity_notify - Run the command(s)-> /usr/bin/sed -i.bak '"'"'s/.*minfree.*/minfree:25/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_configure_capacity_notify ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_configure_capacity_notify already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_configure_capacity_notify has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_failure_halt -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_failure_halt'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_failure_halt'))["exempt_reason"]
EOS
)

audit_failure_halt_audit_score=$($plb -c "print audit_failure_halt:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_failure_halt_audit_score == "true" ]]; then
        ask 'audit_failure_halt - Run the command(s)-> /usr/bin/sed -i.bak '"'"'s/^policy.*/policy: ahlt,argv/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_failure_halt ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/sed -i.bak 's/^policy.*/policy: ahlt,argv/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_failure_halt already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_failure_halt has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_files_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_group_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_group_configure'))["exempt_reason"]
EOS
)

audit_files_group_configure_audit_score=$($plb -c "print audit_files_group_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_files_group_configure_audit_score == "true" ]]; then
        ask 'audit_files_group_configure - Run the command(s)-> /usr/bin/chgrp -R wheel /var/audit/* ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_files_group_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/chgrp -R wheel /var/audit/*
        fi
    else
        echo "$(date -u) Settings for: audit_files_group_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_files_group_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_files_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_mode_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_mode_configure'))["exempt_reason"]
EOS
)

audit_files_mode_configure_audit_score=$($plb -c "print audit_files_mode_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_files_mode_configure_audit_score == "true" ]]; then
        ask 'audit_files_mode_configure - Run the command(s)-> /bin/chmod 440 /var/audit/* ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_files_mode_configure ..." | /usr/bin/tee -a "$audit_log"
            /bin/chmod 440 /var/audit/*
        fi
    else
        echo "$(date -u) Settings for: audit_files_mode_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_files_mode_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_files_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_owner_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_files_owner_configure'))["exempt_reason"]
EOS
)

audit_files_owner_configure_audit_score=$($plb -c "print audit_files_owner_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_files_owner_configure_audit_score == "true" ]]; then
        ask 'audit_files_owner_configure - Run the command(s)-> /usr/sbin/chown -R root /var/audit/* ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_files_owner_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/sbin/chown -R root /var/audit/*
        fi
    else
        echo "$(date -u) Settings for: audit_files_owner_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_files_owner_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_aa_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_aa_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_aa_configure'))["exempt_reason"]
EOS
)

audit_flags_aa_configure_audit_score=$($plb -c "print audit_flags_aa_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_aa_configure_audit_score == "true" ]]; then
        ask 'audit_flags_aa_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*[^-]aa" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,aa/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_flags_aa_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*[^-]aa" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_flags_aa_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_aa_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_ad_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12), AC-2(4)
# * AC-6(9)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_ad_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_ad_configure'))["exempt_reason"]
EOS
)

audit_flags_ad_configure_audit_score=$($plb -c "print audit_flags_ad_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_ad_configure_audit_score == "true" ]]; then
        ask 'audit_flags_ad_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*[^-]ad" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,ad/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_flags_ad_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*[^-]ad" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_flags_ad_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_ad_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fd_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fd_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fd_configure'))["exempt_reason"]
EOS
)

audit_flags_fd_configure_audit_score=$($plb -c "print audit_flags_fd_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fd_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fd_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fd" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fd/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_flags_fd_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fd" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fd/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_flags_fd_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_fd_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fm_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fm_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fm_configure'))["exempt_reason"]
EOS
)

audit_flags_fm_configure_audit_score=$($plb -c "print audit_flags_fm_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fm_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fm_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*fm" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,fm/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_flags_fm_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*fm" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,fm/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_flags_fm_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_fm_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fr_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fr_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fr_configure'))["exempt_reason"]
EOS
)

audit_flags_fr_configure_audit_score=$($plb -c "print audit_flags_fr_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fr_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fr_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fr" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fr/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_flags_fr_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fr" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fr/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_flags_fr_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_fr_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fw_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fw_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_fw_configure'))["exempt_reason"]
EOS
)

audit_flags_fw_configure_audit_score=$($plb -c "print audit_flags_fw_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fw_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fw_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fw" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fw/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_flags_fw_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fw" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fw/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_flags_fw_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_fw_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_lo_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(1)
# * AC-2(12)
# * AU-12
# * AU-2
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_lo_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_flags_lo_configure'))["exempt_reason"]
EOS
)

audit_flags_lo_configure_audit_score=$($plb -c "print audit_flags_lo_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_lo_configure_audit_score == "true" ]]; then
        ask 'audit_flags_lo_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*[^-]lo" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,lo/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_flags_lo_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*[^-]lo" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_flags_lo_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_flags_lo_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_folder_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folder_group_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folder_group_configure'))["exempt_reason"]
EOS
)

audit_folder_group_configure_audit_score=$($plb -c "print audit_folder_group_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_folder_group_configure_audit_score == "true" ]]; then
        ask 'audit_folder_group_configure - Run the command(s)-> /usr/bin/chgrp wheel /var/audit ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_folder_group_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/chgrp wheel /var/audit
        fi
    else
        echo "$(date -u) Settings for: audit_folder_group_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_folder_group_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_folder_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folder_owner_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folder_owner_configure'))["exempt_reason"]
EOS
)

audit_folder_owner_configure_audit_score=$($plb -c "print audit_folder_owner_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_folder_owner_configure_audit_score == "true" ]]; then
        ask 'audit_folder_owner_configure - Run the command(s)-> /usr/sbin/chown root /var/audit ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_folder_owner_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/sbin/chown root /var/audit
        fi
    else
        echo "$(date -u) Settings for: audit_folder_owner_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_folder_owner_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_folders_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folders_mode_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_folders_mode_configure'))["exempt_reason"]
EOS
)

audit_folders_mode_configure_audit_score=$($plb -c "print audit_folders_mode_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_folders_mode_configure_audit_score == "true" ]]; then
        ask 'audit_folders_mode_configure - Run the command(s)-> /bin/chmod 700 /var/audit ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_folders_mode_configure ..." | /usr/bin/tee -a "$audit_log"
            /bin/chmod 700 /var/audit
        fi
    else
        echo "$(date -u) Settings for: audit_folders_mode_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_folders_mode_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_settings_failure_notify -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-5, AU-5(2)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_settings_failure_notify'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('audit_settings_failure_notify'))["exempt_reason"]
EOS
)

audit_settings_failure_notify_audit_score=$($plb -c "print audit_settings_failure_notify:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_settings_failure_notify_audit_score == "true" ]]; then
        ask 'audit_settings_failure_notify - Run the command(s)-> /usr/bin/sed -i.bak '"'"'s/logger -p/logger -s -p/'"'"' /etc/security/audit_warn; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: audit_settings_failure_notify ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/sbin/audit -s
        fi
    else
        echo "$(date -u) Settings for: audit_settings_failure_notify already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) audit_settings_failure_notify has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: auth_pam_login_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_login_smartcard_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_login_smartcard_enforce'))["exempt_reason"]
EOS
)

auth_pam_login_smartcard_enforce_audit_score=$($plb -c "print auth_pam_login_smartcard_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $auth_pam_login_smartcard_enforce_audit_score == "true" ]]; then
        ask 'auth_pam_login_smartcard_enforce - Run the command(s)-> /bin/cat > /etc/pam.d/login << LOGIN_END
# login: auth account password session
auth        sufficient    pam_smartcard.so
auth        optional      pam_krb5.so use_kcminit
auth        optional      pam_ntlm.so try_first_pass
auth        optional      pam_mount.so try_first_pass
auth        required      pam_opendirectory.so try_first_pass
auth        required      pam_deny.so
account     required      pam_nologin.so
account     required      pam_opendirectory.so
password    required      pam_opendirectory.so
session     required      pam_launchd.so
session     required      pam_uwtmp.so
session     optional      pam_mount.so
LOGIN_END


/bin/chmod 644 /etc/pam.d/login
/usr/sbin/chown root:wheel /etc/pam.d/login ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: auth_pam_login_smartcard_enforce ..." | /usr/bin/tee -a "$audit_log"
            /bin/cat > /etc/pam.d/login << LOGIN_END
# login: auth account password session
auth        sufficient    pam_smartcard.so
auth        optional      pam_krb5.so use_kcminit
auth        optional      pam_ntlm.so try_first_pass
auth        optional      pam_mount.so try_first_pass
auth        required      pam_opendirectory.so try_first_pass
auth        required      pam_deny.so
account     required      pam_nologin.so
account     required      pam_opendirectory.so
password    required      pam_opendirectory.so
session     required      pam_launchd.so
session     required      pam_uwtmp.so
session     optional      pam_mount.so
LOGIN_END


/bin/chmod 644 /etc/pam.d/login
/usr/sbin/chown root:wheel /etc/pam.d/login
        fi
    else
        echo "$(date -u) Settings for: auth_pam_login_smartcard_enforce already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) auth_pam_login_smartcard_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: auth_pam_su_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_su_smartcard_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_su_smartcard_enforce'))["exempt_reason"]
EOS
)

auth_pam_su_smartcard_enforce_audit_score=$($plb -c "print auth_pam_su_smartcard_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $auth_pam_su_smartcard_enforce_audit_score == "true" ]]; then
        ask 'auth_pam_su_smartcard_enforce - Run the command(s)-> /bin/cat > /etc/pam.d/su << SU_END
# su: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_rootok.so
auth        required      pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account     required      pam_permit.so
account     required      pam_opendirectory.so no_check_shell
password    required      pam_opendirectory.so
session     required      pam_launchd.so
SU_END

# Fix new file ownership and permissions
/bin/chmod 644 /etc/pam.d/su
/usr/sbin/chown root:wheel /etc/pam.d/su ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: auth_pam_su_smartcard_enforce ..." | /usr/bin/tee -a "$audit_log"
            /bin/cat > /etc/pam.d/su << SU_END
# su: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_rootok.so
auth        required      pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account     required      pam_permit.so
account     required      pam_opendirectory.so no_check_shell
password    required      pam_opendirectory.so
session     required      pam_launchd.so
SU_END

# Fix new file ownership and permissions
/bin/chmod 644 /etc/pam.d/su
/usr/sbin/chown root:wheel /etc/pam.d/su
        fi
    else
        echo "$(date -u) Settings for: auth_pam_su_smartcard_enforce already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) auth_pam_su_smartcard_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: auth_pam_sudo_smartcard_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(1), IA-2(2), IA-2(8)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_sudo_smartcard_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('auth_pam_sudo_smartcard_enforce'))["exempt_reason"]
EOS
)

auth_pam_sudo_smartcard_enforce_audit_score=$($plb -c "print auth_pam_sudo_smartcard_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $auth_pam_sudo_smartcard_enforce_audit_score == "true" ]]; then
        ask 'auth_pam_sudo_smartcard_enforce - Run the command(s)-> /bin/cat > /etc/pam.d/sudo << SUDO_END
# sudo: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_opendirectory.so
auth        required      pam_deny.so
account     required      pam_permit.so
password    required      pam_deny.so
session     required      pam_permit.so
SUDO_END

/bin/chmod 444 /etc/pam.d/sudo
/usr/sbin/chown root:wheel /etc/pam.d/sudo ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: auth_pam_sudo_smartcard_enforce ..." | /usr/bin/tee -a "$audit_log"
            /bin/cat > /etc/pam.d/sudo << SUDO_END
# sudo: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_opendirectory.so
auth        required      pam_deny.so
account     required      pam_permit.so
password    required      pam_deny.so
session     required      pam_permit.so
SUDO_END

/bin/chmod 444 /etc/pam.d/sudo
/usr/sbin/chown root:wheel /etc/pam.d/sudo
        fi
    else
        echo "$(date -u) Settings for: auth_pam_sudo_smartcard_enforce already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) auth_pam_sudo_smartcard_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_anti_virus_installed -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_anti_virus_installed'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_anti_virus_installed'))["exempt_reason"]
EOS
)

os_anti_virus_installed_audit_score=$($plb -c "print os_anti_virus_installed:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_anti_virus_installed_audit_score == "true" ]]; then
        ask 'os_anti_virus_installed - Run the command(s)-> /bin/launchctl load -w /Library/Apple/System/Library/LaunchDaemons/com.apple.XProtect.daemon.scan.plist
/bin/launchctl load -w /Library/Apple/System/Library/LaunchDaemons/com.apple.XprotectFramework.PluginService.plist ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_anti_virus_installed ..." | /usr/bin/tee -a "$audit_log"
            /bin/launchctl load -w /Library/Apple/System/Library/LaunchDaemons/com.apple.XProtect.daemon.scan.plist
/bin/launchctl load -w /Library/Apple/System/Library/LaunchDaemons/com.apple.XprotectFramework.PluginService.plist
        fi
    else
        echo "$(date -u) Settings for: os_anti_virus_installed already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_anti_virus_installed has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_asl_log_files_owner_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_asl_log_files_owner_group_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_asl_log_files_owner_group_configure'))["exempt_reason"]
EOS
)

os_asl_log_files_owner_group_configure_audit_score=$($plb -c "print os_asl_log_files_owner_group_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_asl_log_files_owner_group_configure_audit_score == "true" ]]; then
        ask 'os_asl_log_files_owner_group_configure - Run the command(s)-> /usr/sbin/chown root:wheel $(/usr/bin/stat -f '"'"'%%Su:%%Sg:%%N'"'"' $(/usr/bin/grep -e '"'"'^>'"'"' /etc/asl.conf /etc/asl/* | /usr/bin/awk '"'"'{ print $2 }'"'"') 2> /dev/null | /usr/bin/awk '"'"'!/^root:wheel:/{print $1}'"'"' | /usr/bin/awk -F":" '"'"'!/^root:wheel:/{print $3}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_asl_log_files_owner_group_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/sbin/chown root:wheel $(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/awk -F":" '!/^root:wheel:/{print $3}')
        fi
    else
        echo "$(date -u) Settings for: os_asl_log_files_owner_group_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_asl_log_files_owner_group_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_asl_log_files_permissions_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_asl_log_files_permissions_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_asl_log_files_permissions_configure'))["exempt_reason"]
EOS
)

os_asl_log_files_permissions_configure_audit_score=$($plb -c "print os_asl_log_files_permissions_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_asl_log_files_permissions_configure_audit_score == "true" ]]; then
        ask 'os_asl_log_files_permissions_configure - Run the command(s)-> /bin/chmod 640 $(/usr/bin/stat -f '"'"'%%A:%%N'"'"' $(/usr/bin/grep -e '"'"'^>'"'"' /etc/asl.conf /etc/asl/* | /usr/bin/awk '"'"'{ print $2 }'"'"') 2> /dev/null | /usr/bin/awk -F":" '"'"'!/640/{print $2}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_asl_log_files_permissions_configure ..." | /usr/bin/tee -a "$audit_log"
            /bin/chmod 640 $(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk -F":" '!/640/{print $2}')
        fi
    else
        echo "$(date -u) Settings for: os_asl_log_files_permissions_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_asl_log_files_permissions_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_gatekeeper_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-3
# * SI-7(1), SI-7(15)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_gatekeeper_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_gatekeeper_enable'))["exempt_reason"]
EOS
)

os_gatekeeper_enable_audit_score=$($plb -c "print os_gatekeeper_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_gatekeeper_enable_audit_score == "true" ]]; then
        ask 'os_gatekeeper_enable - Run the command(s)-> /usr/sbin/spctl --global-enable ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_gatekeeper_enable ..." | /usr/bin/tee -a "$audit_log"
            /usr/sbin/spctl --global-enable
        fi
    else
        echo "$(date -u) Settings for: os_gatekeeper_enable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_gatekeeper_enable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_httpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_httpd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_httpd_disable'))["exempt_reason"]
EOS
)

os_httpd_disable_audit_score=$($plb -c "print os_httpd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_httpd_disable_audit_score == "true" ]]; then
        ask 'os_httpd_disable - Run the command(s)-> /bin/launchctl disable system/org.apache.httpd ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_httpd_disable ..." | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/org.apache.httpd
        fi
    else
        echo "$(date -u) Settings for: os_httpd_disable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_httpd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_newsyslog_files_owner_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_newsyslog_files_owner_group_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_newsyslog_files_owner_group_configure'))["exempt_reason"]
EOS
)

os_newsyslog_files_owner_group_configure_audit_score=$($plb -c "print os_newsyslog_files_owner_group_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_newsyslog_files_owner_group_configure_audit_score == "true" ]]; then
        ask 'os_newsyslog_files_owner_group_configure - Run the command(s)-> /usr/sbin/chown root:wheel $(/usr/bin/stat -f '"'"'%%Su:%%Sg:%%N'"'"' $(/usr/bin/grep -v '"'"'^#'"'"' /etc/newsyslog.conf | /usr/bin/awk '"'"'{ print $1 }'"'"') 2> /dev/null | /usr/bin/awk -F":" '"'"'!/^root:wheel:/{print $3}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_newsyslog_files_owner_group_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/sbin/chown root:wheel $(/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk -F":" '!/^root:wheel:/{print $3}')
        fi
    else
        echo "$(date -u) Settings for: os_newsyslog_files_owner_group_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_newsyslog_files_owner_group_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_newsyslog_files_permissions_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-11

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_newsyslog_files_permissions_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_newsyslog_files_permissions_configure'))["exempt_reason"]
EOS
)

os_newsyslog_files_permissions_configure_audit_score=$($plb -c "print os_newsyslog_files_permissions_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_newsyslog_files_permissions_configure_audit_score == "true" ]]; then
        ask 'os_newsyslog_files_permissions_configure - Run the command(s)-> /bin/chmod 640 $(/usr/bin/stat -f '"'"'%%A:%%N'"'"' $(/usr/bin/grep -v '"'"'^#'"'"' /etc/newsyslog.conf | /usr/bin/awk '"'"'{ print $1 }'"'"') 2> /dev/null | /usr/bin/awk '"'"'!/640/{print $1}'"'"' | awk -F":" '"'"'!/640/{print $2}'"'"') ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_newsyslog_files_permissions_configure ..." | /usr/bin/tee -a "$audit_log"
            /bin/chmod 640 $(/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | awk -F":" '!/640/{print $2}')
        fi
    else
        echo "$(date -u) Settings for: os_newsyslog_files_permissions_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_newsyslog_files_permissions_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_nfsd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_nfsd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_nfsd_disable'))["exempt_reason"]
EOS
)

os_nfsd_disable_audit_score=$($plb -c "print os_nfsd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_nfsd_disable_audit_score == "true" ]]; then
        ask 'os_nfsd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.nfsd ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_nfsd_disable ..." | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.nfsd
        fi
    else
        echo "$(date -u) Settings for: os_nfsd_disable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_nfsd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_policy_banner_loginwindow_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-8

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_loginwindow_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_loginwindow_enforce'))["exempt_reason"]
EOS
)

os_policy_banner_loginwindow_enforce_audit_score=$($plb -c "print os_policy_banner_loginwindow_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_policy_banner_loginwindow_enforce_audit_score == "true" ]]; then
        ask 'os_policy_banner_loginwindow_enforce - Run the command(s)-> bannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: 

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 

-At any time, the USG may inspect and seize data stored on this IS. 

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose. 

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
/bin/mkdir /Library/Security/PolicyBanner.rtfd
/usr/bin/textutil -convert rtf -output /Library/Security/PolicyBanner.rtfd/TXT.rtf -stdin <<EOF
$bannerText
EOF ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_policy_banner_loginwindow_enforce ..." | /usr/bin/tee -a "$audit_log"
            bannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: 

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 

-At any time, the USG may inspect and seize data stored on this IS. 

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose. 

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
/bin/mkdir /Library/Security/PolicyBanner.rtfd
/usr/bin/textutil -convert rtf -output /Library/Security/PolicyBanner.rtfd/TXT.rtf -stdin <<EOF
$bannerText
EOF
        fi
    else
        echo "$(date -u) Settings for: os_policy_banner_loginwindow_enforce already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_policy_banner_loginwindow_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_policy_banner_ssh_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-8

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_ssh_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_ssh_configure'))["exempt_reason"]
EOS
)

os_policy_banner_ssh_configure_audit_score=$($plb -c "print os_policy_banner_ssh_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_policy_banner_ssh_configure_audit_score == "true" ]]; then
        ask 'os_policy_banner_ssh_configure - Run the command(s)-> bannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
/bin/echo "${bannerText}" > /etc/banner ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_policy_banner_ssh_configure ..." | /usr/bin/tee -a "$audit_log"
            bannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
/bin/echo "${bannerText}" > /etc/banner
        fi
    else
        echo "$(date -u) Settings for: os_policy_banner_ssh_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_policy_banner_ssh_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_policy_banner_ssh_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-8

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_ssh_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_policy_banner_ssh_enforce'))["exempt_reason"]
EOS
)

os_policy_banner_ssh_enforce_audit_score=$($plb -c "print os_policy_banner_ssh_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_policy_banner_ssh_enforce_audit_score == "true" ]]; then
        ask 'os_policy_banner_ssh_enforce - Run the command(s)-> include_dir=$(/usr/bin/awk '"'"'/^Include/ {print $2}'"'"' /etc/ssh/sshd_config | /usr/bin/tr -d '"'"'*'"'"')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF '"'"'banner /etc/banner'"'"' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "banner /etc/banner" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_policy_banner_ssh_enforce ..." | /usr/bin/tee -a "$audit_log"
            include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'banner /etc/banner' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "banner /etc/banner" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done
        fi
    else
        echo "$(date -u) Settings for: os_policy_banner_ssh_enforce already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_policy_banner_ssh_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_sip_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * AU-9, AU-9(3)
# * CM-5, CM-5(6)
# * SC-4
# * SI-2
# * SI-7

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sip_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sip_enable'))["exempt_reason"]
EOS
)

os_sip_enable_audit_score=$($plb -c "print os_sip_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sip_enable_audit_score == "true" ]]; then
        ask 'os_sip_enable - Run the command(s)-> /usr/bin/csrutil enable ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_sip_enable ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/csrutil enable
        fi
    else
        echo "$(date -u) Settings for: os_sip_enable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sip_enable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_sshd_client_alive_count_max_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-10

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_client_alive_count_max_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_client_alive_count_max_configure'))["exempt_reason"]
EOS
)

os_sshd_client_alive_count_max_configure_audit_score=$($plb -c "print os_sshd_client_alive_count_max_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sshd_client_alive_count_max_configure_audit_score == "true" ]]; then
        ask 'os_sshd_client_alive_count_max_configure - Run the command(s)-> include_dir=$(/usr/bin/awk '"'"'/^Include/ {print $2}'"'"' /etc/ssh/sshd_config | /usr/bin/tr -d '"'"'*'"'"')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF '"'"'clientalivecountmax 1'"'"' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "clientalivecountmax 1" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_sshd_client_alive_count_max_configure ..." | /usr/bin/tee -a "$audit_log"
            include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'clientalivecountmax 1' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "clientalivecountmax 1" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done
        fi
    else
        echo "$(date -u) Settings for: os_sshd_client_alive_count_max_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sshd_client_alive_count_max_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_sshd_client_alive_interval_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-12
# * SC-10

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_client_alive_interval_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_client_alive_interval_configure'))["exempt_reason"]
EOS
)

os_sshd_client_alive_interval_configure_audit_score=$($plb -c "print os_sshd_client_alive_interval_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sshd_client_alive_interval_configure_audit_score == "true" ]]; then
        ask 'os_sshd_client_alive_interval_configure - Run the command(s)-> include_dir=$(/usr/bin/awk '"'"'/^Include/ {print $2}'"'"' /etc/ssh/sshd_config | /usr/bin/tr -d '"'"'*'"'"')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF '"'"'clientaliveinterval 900'"'"' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "clientaliveinterval 900" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_sshd_client_alive_interval_configure ..." | /usr/bin/tee -a "$audit_log"
            include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'clientaliveinterval 900' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "clientaliveinterval 900" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done
        fi
    else
        echo "$(date -u) Settings for: os_sshd_client_alive_interval_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sshd_client_alive_interval_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_sshd_fips_140_ciphers -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * SC-13
# * SC-8(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_fips_140_ciphers'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_fips_140_ciphers'))["exempt_reason"]
EOS
)

os_sshd_fips_140_ciphers_audit_score=$($plb -c "print os_sshd_fips_140_ciphers:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sshd_fips_140_ciphers_audit_score == "true" ]]; then
        ask 'os_sshd_fips_140_ciphers - Run the command(s)-> include_dir=$(/usr/bin/awk '"'"'/^Include/ {print $2}'"'"' /etc/ssh/sshd_config | /usr/bin/tr -d '"'"'*'"'"')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF '"'"'Ciphers aes256-ctr,aes192-ctr,aes128-ctr'"'"' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "Ciphers aes256-ctr,aes192-ctr,aes128-ctr" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_sshd_fips_140_ciphers ..." | /usr/bin/tee -a "$audit_log"
            include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "Ciphers aes256-ctr,aes192-ctr,aes128-ctr" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done
        fi
    else
        echo "$(date -u) Settings for: os_sshd_fips_140_ciphers already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sshd_fips_140_ciphers has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_sshd_fips_140_macs -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * SC-13
# * SC-8(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_fips_140_macs'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_fips_140_macs'))["exempt_reason"]
EOS
)

os_sshd_fips_140_macs_audit_score=$($plb -c "print os_sshd_fips_140_macs:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sshd_fips_140_macs_audit_score == "true" ]]; then
        ask 'os_sshd_fips_140_macs - Run the command(s)-> include_dir=$(/usr/bin/awk '"'"'/^Include/ {print $2}'"'"' /etc/ssh/sshd_config | /usr/bin/tr -d '"'"'*'"'"')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF '"'"'MACs hmac-sha2-256,hmac-sha2-512'"'"' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "MACs hmac-sha2-256,hmac-sha2-512" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_sshd_fips_140_macs ..." | /usr/bin/tee -a "$audit_log"
            include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'MACs hmac-sha2-256,hmac-sha2-512' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "MACs hmac-sha2-256,hmac-sha2-512" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done
        fi
    else
        echo "$(date -u) Settings for: os_sshd_fips_140_macs already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sshd_fips_140_macs has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_sshd_key_exchange_algorithm_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(2)
# * IA-7
# * MA-4(6)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_key_exchange_algorithm_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_key_exchange_algorithm_configure'))["exempt_reason"]
EOS
)

os_sshd_key_exchange_algorithm_configure_audit_score=$($plb -c "print os_sshd_key_exchange_algorithm_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sshd_key_exchange_algorithm_configure_audit_score == "true" ]]; then
        ask 'os_sshd_key_exchange_algorithm_configure - Run the command(s)-> include_dir=$(/usr/bin/awk '"'"'/^Include/ {print $2}'"'"' /etc/ssh/sshd_config | /usr/bin/tr -d '"'"'*'"'"')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF '"'"'KexAlgorithms diffie-hellman-group-exchange-sha256'"'"' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "KexAlgorithms diffie-hellman-group-exchange-sha256" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_sshd_key_exchange_algorithm_configure ..." | /usr/bin/tee -a "$audit_log"
            include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'KexAlgorithms diffie-hellman-group-exchange-sha256' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "KexAlgorithms diffie-hellman-group-exchange-sha256" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done
        fi
    else
        echo "$(date -u) Settings for: os_sshd_key_exchange_algorithm_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sshd_key_exchange_algorithm_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_sshd_login_grace_time_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-10

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_login_grace_time_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_login_grace_time_configure'))["exempt_reason"]
EOS
)

os_sshd_login_grace_time_configure_audit_score=$($plb -c "print os_sshd_login_grace_time_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sshd_login_grace_time_configure_audit_score == "true" ]]; then
        ask 'os_sshd_login_grace_time_configure - Run the command(s)-> include_dir=$(/usr/bin/awk '"'"'/^Include/ {print $2}'"'"' /etc/ssh/sshd_config | /usr/bin/tr -d '"'"'*'"'"')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF '"'"'logingracetime 30'"'"' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "logingracetime 30" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_sshd_login_grace_time_configure ..." | /usr/bin/tee -a "$audit_log"
            include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'logingracetime 30' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "logingracetime 30" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done
        fi
    else
        echo "$(date -u) Settings for: os_sshd_login_grace_time_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sshd_login_grace_time_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_sshd_permit_root_login_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2(5)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_permit_root_login_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sshd_permit_root_login_configure'))["exempt_reason"]
EOS
)

os_sshd_permit_root_login_configure_audit_score=$($plb -c "print os_sshd_permit_root_login_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sshd_permit_root_login_configure_audit_score == "true" ]]; then
        ask 'os_sshd_permit_root_login_configure - Run the command(s)-> include_dir=$(/usr/bin/awk '"'"'/^Include/ {print $2}'"'"' /etc/ssh/sshd_config | /usr/bin/tr -d '"'"'*'"'"')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF '"'"'permitrootlogin no'"'"' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "permitrootlogin no" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_sshd_permit_root_login_configure ..." | /usr/bin/tee -a "$audit_log"
            include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')

if [[ -z $include_dir ]]; then
  /usr/bin/sed -i.bk "1s/.*/Include \/etc\/ssh\/sshd_config.d\/\*/" /etc/ssh/sshd_config
fi

/usr/bin/grep -qxF 'permitrootlogin no' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "permitrootlogin no" >> "${include_dir}01-mscp-sshd.conf"

for file in $(ls ${include_dir}); do
  if [[ "$file" == "100-macos.conf" ]]; then
      continue
  fi
  if [[ "$file" == "01-mscp-sshd.conf" ]]; then
      break
  fi
  /bin/mv ${include_dir}${file} ${include_dir}20-${file}
done
        fi
    else
        echo "$(date -u) Settings for: os_sshd_permit_root_login_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sshd_permit_root_login_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_sudo_timeout_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sudo_timeout_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_sudo_timeout_configure'))["exempt_reason"]
EOS
)

os_sudo_timeout_configure_audit_score=$($plb -c "print os_sudo_timeout_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sudo_timeout_configure_audit_score == "true" ]]; then
        ask 'os_sudo_timeout_configure - Run the command(s)-> /usr/bin/find /etc/sudoers* -type f -exec sed -i '"'"''"'"' '"'"'/timestamp_timeout/d'"'"' '"'"'{}'"'"' \;
/bin/echo "Defaults timestamp_timeout=0" >> /etc/sudoers.d/mscp ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_sudo_timeout_configure ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/find /etc/sudoers* -type f -exec sed -i '' '/timestamp_timeout/d' '{}' \;
/bin/echo "Defaults timestamp_timeout=0" >> /etc/sudoers.d/mscp
        fi
    else
        echo "$(date -u) Settings for: os_sudo_timeout_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_sudo_timeout_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_tftpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
# * IA-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_tftpd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_tftpd_disable'))["exempt_reason"]
EOS
)

os_tftpd_disable_audit_score=$($plb -c "print os_tftpd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_tftpd_disable_audit_score == "true" ]]; then
        ask 'os_tftpd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.tftpd ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_tftpd_disable ..." | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.tftpd
        fi
    else
        echo "$(date -u) Settings for: os_tftpd_disable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_tftpd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_time_server_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_time_server_enabled'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_time_server_enabled'))["exempt_reason"]
EOS
)

os_time_server_enabled_audit_score=$($plb -c "print os_time_server_enabled:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_time_server_enabled_audit_score == "true" ]]; then
        ask 'os_time_server_enabled - Run the command(s)-> /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_time_server_enabled ..." | /usr/bin/tee -a "$audit_log"
            /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist
        fi
    else
        echo "$(date -u) Settings for: os_time_server_enabled already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_time_server_enabled has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_uucp_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_uucp_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('os_uucp_disable'))["exempt_reason"]
EOS
)

os_uucp_disable_audit_score=$($plb -c "print os_uucp_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_uucp_disable_audit_score == "true" ]]; then
        ask 'os_uucp_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.uucp ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: os_uucp_disable ..." | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.uucp
        fi
    else
        echo "$(date -u) Settings for: os_uucp_disable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) os_uucp_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: system_settings_firewall_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-4
# * CM-7, CM-7(1)
# * SC-7, SC-7(12)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_firewall_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_firewall_enable'))["exempt_reason"]
EOS
)

system_settings_firewall_enable_audit_score=$($plb -c "print system_settings_firewall_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_firewall_enable_audit_score == "true" ]]; then
        ask 'system_settings_firewall_enable - Run the command(s)-> /usr/bin/defaults write /Library/Preferences/com.apple.alf globalstate -int 1 ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: system_settings_firewall_enable ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write /Library/Preferences/com.apple.alf globalstate -int 1
        fi
    else
        echo "$(date -u) Settings for: system_settings_firewall_enable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) system_settings_firewall_enable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: system_settings_firewall_stealth_mode_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7, SC-7(16)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_firewall_stealth_mode_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_firewall_stealth_mode_enable'))["exempt_reason"]
EOS
)

system_settings_firewall_stealth_mode_enable_audit_score=$($plb -c "print system_settings_firewall_stealth_mode_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_firewall_stealth_mode_enable_audit_score == "true" ]]; then
        ask 'system_settings_firewall_stealth_mode_enable - Run the command(s)-> /usr/bin/defaults write /Library/Preferences/com.apple.alf stealthenabled -int 1 ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: system_settings_firewall_stealth_mode_enable ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write /Library/Preferences/com.apple.alf stealthenabled -int 1
        fi
    else
        echo "$(date -u) Settings for: system_settings_firewall_stealth_mode_enable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) system_settings_firewall_stealth_mode_enable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: system_settings_gatekeeper_identified_developers_allowed -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-7(1), SI-7(15)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_gatekeeper_identified_developers_allowed'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_gatekeeper_identified_developers_allowed'))["exempt_reason"]
EOS
)

system_settings_gatekeeper_identified_developers_allowed_audit_score=$($plb -c "print system_settings_gatekeeper_identified_developers_allowed:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_gatekeeper_identified_developers_allowed_audit_score == "true" ]]; then
        ask 'system_settings_gatekeeper_identified_developers_allowed - Run the command(s)-> /usr/sbin/spctl --global-enable; /usr/sbin/spctl --enable ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: system_settings_gatekeeper_identified_developers_allowed ..." | /usr/bin/tee -a "$audit_log"
            /usr/sbin/spctl --global-enable; /usr/sbin/spctl --enable
        fi
    else
        echo "$(date -u) Settings for: system_settings_gatekeeper_identified_developers_allowed already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) system_settings_gatekeeper_identified_developers_allowed has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: system_settings_location_services_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7(10)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_location_services_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_location_services_disable'))["exempt_reason"]
EOS
)

system_settings_location_services_disable_audit_score=$($plb -c "print system_settings_location_services_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_location_services_disable_audit_score == "true" ]]; then
        ask 'system_settings_location_services_disable - Run the command(s)-> /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false; /bin/launchctl kickstart -k system/com.apple.locationd ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: system_settings_location_services_disable ..." | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false; /bin/launchctl kickstart -k system/com.apple.locationd
        fi
    else
        echo "$(date -u) Settings for: system_settings_location_services_disable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) system_settings_location_services_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: system_settings_rae_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_rae_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_rae_disable'))["exempt_reason"]
EOS
)

system_settings_rae_disable_audit_score=$($plb -c "print system_settings_rae_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_rae_disable_audit_score == "true" ]]; then
        ask 'system_settings_rae_disable - Run the command(s)-> /usr/sbin/systemsetup -setremoteappleevents off
/bin/launchctl disable system/com.apple.AEServer ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: system_settings_rae_disable ..." | /usr/bin/tee -a "$audit_log"
            /usr/sbin/systemsetup -setremoteappleevents off
/bin/launchctl disable system/com.apple.AEServer
        fi
    else
        echo "$(date -u) Settings for: system_settings_rae_disable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) system_settings_rae_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: system_settings_screen_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screen_sharing_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_screen_sharing_disable'))["exempt_reason"]
EOS
)

system_settings_screen_sharing_disable_audit_score=$($plb -c "print system_settings_screen_sharing_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_screen_sharing_disable_audit_score == "true" ]]; then
        ask 'system_settings_screen_sharing_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.screensharing ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: system_settings_screen_sharing_disable ..." | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.screensharing
        fi
    else
        echo "$(date -u) Settings for: system_settings_screen_sharing_disable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) system_settings_screen_sharing_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: system_settings_smbd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_smbd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_smbd_disable'))["exempt_reason"]
EOS
)

system_settings_smbd_disable_audit_score=$($plb -c "print system_settings_smbd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_smbd_disable_audit_score == "true" ]]; then
        ask 'system_settings_smbd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.smbd ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: system_settings_smbd_disable ..." | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.smbd
        fi
    else
        echo "$(date -u) Settings for: system_settings_smbd_disable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) system_settings_smbd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: system_settings_ssh_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_ssh_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_ssh_disable'))["exempt_reason"]
EOS
)

system_settings_ssh_disable_audit_score=$($plb -c "print system_settings_ssh_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_ssh_disable_audit_score == "true" ]]; then
        ask 'system_settings_ssh_disable - Run the command(s)-> /usr/sbin/systemsetup -f -setremotelogin off >/dev/null
/bin/launchctl disable system/com.openssh.sshd ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: system_settings_ssh_disable ..." | /usr/bin/tee -a "$audit_log"
            /usr/sbin/systemsetup -f -setremotelogin off >/dev/null
/bin/launchctl disable system/com.openssh.sshd
        fi
    else
        echo "$(date -u) Settings for: system_settings_ssh_disable already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) system_settings_ssh_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: system_settings_system_wide_preferences_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6, AC-6(1), AC-6(2)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_system_wide_preferences_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.DISA-STIG.audit').objectForKey('system_settings_system_wide_preferences_configure'))["exempt_reason"]
EOS
)

system_settings_system_wide_preferences_configure_audit_score=$($plb -c "print system_settings_system_wide_preferences_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_system_wide_preferences_configure_audit_score == "true" ]]; then
        ask 'system_settings_system_wide_preferences_configure - Run the command(s)-> authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")

for section in ${authDBs[@]}; do
/usr/bin/security -q authorizationdb read "$section" > "/tmp/$section.plist"
key_value=$(/usr/libexec/PlistBuddy -c "Print :shared" "/tmp/$section.plist" 2>&1)
	if [[ "$key_value" == *"Does Not Exist"* ]]; then
  		/usr/libexec/PlistBuddy -c "Add :shared bool false" "/tmp/$section.plist"
	else
  		/usr/libexec/PlistBuddy -c "Set :shared false" "/tmp/$section.plist"
	fi
  	/usr/bin/security -q authorizationdb write "$section" < "/tmp/$section.plist"
done ' N
        if [[ $? == 0 ]]; then
            echo "$(date -u) Running the command to configure the settings for: system_settings_system_wide_preferences_configure ..." | /usr/bin/tee -a "$audit_log"
            authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")

for section in ${authDBs[@]}; do
/usr/bin/security -q authorizationdb read "$section" > "/tmp/$section.plist"
key_value=$(/usr/libexec/PlistBuddy -c "Print :shared" "/tmp/$section.plist" 2>&1)
	if [[ "$key_value" == *"Does Not Exist"* ]]; then
  		/usr/libexec/PlistBuddy -c "Add :shared bool false" "/tmp/$section.plist"
	else
  		/usr/libexec/PlistBuddy -c "Set :shared false" "/tmp/$section.plist"
	fi
  	/usr/bin/security -q authorizationdb write "$section" < "/tmp/$section.plist"
done
        fi
    else
        echo "$(date -u) Settings for: system_settings_system_wide_preferences_configure already configured, continuing..." | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) system_settings_system_wide_preferences_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
echo "$(date -u) Remediation complete" >> "$audit_log"

}

zparseopts -D -E -check=check -fix=fix -stats=stats -compliant=compliant_opt -non_compliant=non_compliant_opt -reset=reset -cfc=cfc

if [[ $reset ]]; then reset_plist; fi

if [[ $check ]] || [[ $fix ]] || [[ $cfc ]] || [[ $stats ]] || [[ $compliant_opt ]] || [[ $non_compliant_opt ]]; then
    if [[ $fix ]]; then run_fix; fi
    if [[ $check ]]; then run_scan; fi
    if [[ $cfc ]]; then run_scan; run_fix; run_scan; fi
    if [[ $stats ]];then generate_stats; fi
    if [[ $compliant_opt ]];then compliance_count "compliant"; fi
    if [[ $non_compliant_opt ]];then compliance_count "non-compliant"; fi
else
    while true; do
        show_menus
        read_options
    done
fi

if [[ "$ssh_key_check" -ne 0 ]]; then
    /bin/rm /etc/ssh/ssh_host_rsa_key
    /bin/rm /etc/ssh/ssh_host_rsa_key.public
    ssh_key_check=0
fi
    