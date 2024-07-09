resource "zentral_munki_script_check" "mcs-auditing-audit_acls_files_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Files to Not Contain Access Control Lists"
  description = trimspace(<<EODESC
The audit log files _MUST_ not contain access control lists (ACLs).

This rule ensures that audit information and audit files are configured to be readable and writable only by system administrators, thereby preventing unauthorized access, modification, and deletion of files.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_acls_folders_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Folder to Not Contain Access Control Lists"
  description = trimspace(<<EODESC
The audit log folder _MUST_ not contain access control lists (ACLs).

Audit logs contain sensitive data about the system and users. This rule ensures that the audit service is configured to create log folders that are readable and writable only by system administrators in order to prevent normal users from reading audit logs.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -lde /var/audit | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_auditd_enabled" {
  name = "[mSCP] - Auditing - Enable Security Auditing"
  description = trimspace(<<EODESC
The information system _MUST_ be configured to generate audit records.

Audit records establish what types of events have occurred, when they occurred, and which users were involved. These records aid an organization in their efforts to establish, correlate, and investigate the events leading up to an outage or attack.

The content required to be captured in an audit record varies based on the impact level of an organization's system. Content that may be necessary to satisfy this requirement includes, for example, time stamps, source addresses, destination addresses, user identifiers, event descriptions, success/fail indications, filenames involved, and access or flow control rules invoked.

The information system initiates session audits at system start-up.

NOTE: Security auditing is NOT enabled by default on macOS Sonoma.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
LAUNCHD_RUNNING=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd)
AUDITD_RUNNING=$(/usr/sbin/audit -c | /usr/bin/grep -c "AUC_AUDITING")
if [[ $LAUNCHD_RUNNING == 1 ]] && [[ -e /etc/security/audit_control ]] && [[ $AUDITD_RUNNING == 1 ]]; then
  echo "pass"
else
  echo "fail"
fi
EOSRC
  )
  expected_result = "pass"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_control_acls_configure" {
  name = "[mSCP] - Auditing - Configure Audit_Control to Not Contain Access Control Lists"
  description = trimspace(<<EODESC
/etc/security/audit_control _MUST_ not contain Access Control Lists (ACLs).
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -le /etc/security/audit_control | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_control_group_configure" {
  name = "[mSCP] - Auditing - Configure Audit_Control Group to Wheel"
  description = trimspace(<<EODESC
/etc/security/audit_control _MUST_ have the group set to wheel.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print $4}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_control_mode_configure" {
  name = "[mSCP] - Auditing - Configure Audit_Control Owner to Mode 440 or Less Permissive"
  description = trimspace(<<EODESC
/etc/security/audit_control _MUST_ be configured so that it is readable only by the root user and group wheel.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -l /etc/security/audit_control | /usr/bin/awk '!/-r--[r-]-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/xargs
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_control_owner_configure" {
  name = "[mSCP] - Auditing - Configure Audit_Control Owner to Root"
  description = trimspace(<<EODESC
/etc/security/audit_control _MUST_ have the owner set to root.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print $3}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_files_group_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Files Group to Wheel"
  description = trimspace(<<EODESC
Audit log files _MUST_ have the group set to wheel.

The audit service _MUST_ be configured to create log files with the correct group ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_files_mode_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Files to Mode 440 or Less Permissive"
  description = trimspace(<<EODESC
The audit service _MUST_ be configured to create log files that are readable only by the root user and group wheel. To achieve this, audit log files _MUST_ be configured to mode 440 or less permissive; thereby preventing normal users from reading, modifying or deleting audit logs.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_files_owner_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Files to be Owned by Root"
  description = trimspace(<<EODESC
Audit log files _MUST_ be owned by root.

The audit service _MUST_ be configured to create log files with the correct ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_folder_group_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Folders Group to Wheel"
  description = trimspace(<<EODESC
Audit log files _MUST_ have the group set to wheel.

The audit service _MUST_ be configured to create log files with the correct group ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $4}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_folder_owner_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Folders to be Owned by Root"
  description = trimspace(<<EODESC
Audit log folders _MUST_ be owned by root.

The audit service _MUST_ be configured to create log folders with the correct ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log folders are set to only be readable and writable by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $3}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_folders_mode_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Folders to Mode 700 or Less Permissive"
  description = trimspace(<<EODESC
The audit log folder _MUST_ be configured to mode 700 or less permissive so that only the root user is able to read, write, and execute changes to folders.

Because audit logs contain sensitive data about the system and users, the audit service _MUST_ be configured to mode 700 or less permissive; thereby preventing normal users from reading, modifying or deleting audit logs.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
EOSRC
  )
  expected_result = "700"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_retention_configure" {
  name = "[mSCP] - Auditing - Configure Audit Retention to 7d"
  description = trimspace(<<EODESC
The audit service _MUST_ be configured to require records be kept for a organizational defined value before deletion, unless the system uses a central audit record storage facility.

When "expire-after" is set to "7d", the audit service will not delete audit logs until the log data criteria is met.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control
EOSRC
  )
  expected_result = "7d"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_airdrop_disable" {
  name = "[mSCP] - macOS - Disable AirDrop"
  description = trimspace(<<EODESC
AirDrop _MUST_ be disabled to prevent file transfers to or from unauthorized devices.
AirDrop allows users to share and receive files from other nearby Apple devices.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirDrop').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_anti_virus_installed" {
  name = "[mSCP] - macOS - Must Use an Approved Antivirus Program"
  description = trimspace(<<EODESC
An approved antivirus product _MUST_ be installed and configured to run.

Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl list | /usr/bin/grep -cE "(com.apple.XprotectFramework.PluginService$|com.apple.XProtect.daemon.scan$)"
EOSRC
  )
  expected_result = "2"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_authenticated_root_enable" {
  name = "[mSCP] - macOS - Enable Authenticated Root"
  description = trimspace(<<EODESC
Authenticated Root _MUST_ be enabled.

When Authenticated Root is enabled the macOS is booted from a signed volume that is cryptographically protected to prevent tampering with the system volume.

NOTE: Authenticated Root is enabled by default on macOS systems.

WARNING: If more than one partition with macOS is detected, the csrutil command will hang awaiting input.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/csrutil authenticated-root | /usr/bin/grep -c 'enabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_config_data_install_enforce" {
  name = "[mSCP] - macOS - Enforce Installation of XProtect Remediator and Gatekeeper Updates Automatically"
  description = trimspace(<<EODESC
Software Update _MUST_ be configured to update XProtect Remediator and Gatekeeper automatically.

This setting enforces definition updates for XProtect Remediator and Gatekeeper; with this setting in place, new malware and adware that Apple has added to the list of malware or untrusted software will not execute. These updates do not require the computer to be restarted.

link:https://support.apple.com/en-us/HT207005[]

NOTE: Software update will automatically update XProtect Remediator and Gatekeeper by default in the macOS.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('ConfigDataInstall').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_firewall_log_enable" {
  name = "[mSCP] - macOS - Enable Firewall Logging"
  description = trimspace(<<EODESC
Firewall logging _MUST_ be enabled.

Firewall logging ensures that malicious network activity will be logged to the system.

NOTE: The firewall data is logged to Apple's Unified Logging with the subsystem `com.apple.alf` and the data is marked as private. In order to enable private data, review the `com.apple.alf.private_data.mobileconfig` file in the project's `includes` folder.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
  .objectForKey('EnableLogging').js
  let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
  .objectForKey('LoggingOption').js
  if ( pref1 == true && pref2 == "detail" ){
    return("true")
  } else {
    return("false")
  }
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_gatekeeper_enable" {
  name = "[mSCP] - macOS - Enable Gatekeeper"
  description = trimspace(<<EODESC
Gatekeeper _MUST_ be enabled.

Gatekeeper is a security feature that ensures that applications are digitally signed by an Apple-issued certificate before they are permitted to run. Digital signatures allow the macOS host to verify that the application has not been modified by a malicious third party.

Administrator users will still have the option to override these settings on a case-by-case basis.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_guest_folder_removed" {
  name = "[mSCP] - macOS - Remove Guest Folder if Present"
  description = trimspace(<<EODESC
The guest folder _MUST_ be deleted if present.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls /Users/ | /usr/bin/grep -c "Guest"
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_home_folders_secure" {
  name = "[mSCP] - macOS - Secure User's Home Folders"
  description = trimspace(<<EODESC
The system _MUST_ be configured to prevent access to other user's home folders.

The default behavior of macOS is to allow all valid users access to the top level of every other user's home folder while restricting access only to the Apple default folders within.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" | /usr/bin/wc -l | /usr/bin/xargs
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_httpd_disable" {
  name = "[mSCP] - macOS - Disable the Built-in Web Server"
  description = trimspace(<<EODESC
The built-in web server is a non-essential service built into macOS and _MUST_ be disabled.

NOTE: The built in web server service is disabled at startup by default macOS.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_install_log_retention_configure" {
  name = "[mSCP] - macOS - Configure Install.log Retention to 365"
  description = trimspace(<<EODESC
The install.log _MUST_ be configured to require records be kept for a organizational defined value before deletion, unless the system uses a central audit record storage facility.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/sbin/aslmanager -dd 2>&1 | /usr/bin/awk '/\/var\/log\/install.log$/ {count++} /Processing module com.apple.install/,/Finished/ { for (i=1;i<=NR;i++) { if ($i == "TTL" && $(i+2) >= 365) { ttl="True" }; if ($i == "MAX") {max="True"}}} END{if (count > 1) { print "Multiple config files for /var/log/install, manually remove the extra files"} else if (max == "True") { print "all_max setting is configured, must be removed" } if (ttl != "True") { print "TTL not configured" } else { print "Yes" }}'
EOSRC
  )
  expected_result = "Yes"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_mdm_require" {
  name = "[mSCP] - macOS - Enforce Enrollment in Mobile Device Management"
  description = trimspace(<<EODESC
You _MUST_ enroll your Mac in a Mobile Device Management (MDM) software.

User Approved MDM (UAMDM) enrollment or enrollment via Apple Business Manager (ABM)/Apple School Manager (ASM) is required to manage certain security settings. Currently these include:

* Allowed Kernel Extensions
* Allowed Approved System Extensions
* Privacy Preferences Policy Control Payload
* ExtensibleSingleSignOn
* FDEFileVault

In macOS 11, UAMDM grants Supervised status on a Mac, unlocking the following MDM features, which were previously locked behind ABM:

* Activation Lock Bypass
* Access to Bootstrap Tokens
* Scheduling Software Updates
* Query list and delete local users
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print $2}' | /usr/bin/grep -c "Yes (User Approved)"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_mobile_file_integrity_enable" {
  name = "[mSCP] - macOS - Enable Apple Mobile File Integrity"
  description = trimspace(<<EODESC
Mobile file integrity _MUST_ be ebabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/nvram -p | /usr/bin/grep -c "amfi_get_out_of_my_way=1"
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_nfsd_disable" {
  name = "[mSCP] - macOS - Disable Network File System Service"
  description = trimspace(<<EODESC
Support for Network File Systems (NFS) services is non-essential and, therefore, _MUST_ be disabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.nfsd" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_on_device_dictation_enforce" {
  name = "[mSCP] - macOS - Enforce On Device Dictation"
  description = trimspace(<<EODESC
Dictation _MUST_ be restricted to on device only to prevent potential data exfiltration.

The information system _MUST_ be configured to provide only essential capabilities.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('forceOnDeviceOnlyDictation').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = false
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_password_hint_remove" {
  name = "[mSCP] - macOS - Remove Password Hint From User Accounts"
  description = trimspace(<<EODESC
User accounts _MUST_ not contain password hints.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
HINT=$(/usr/bin/dscl . -list /Users hint | /usr/bin/awk '{ print $2 }')

if [ -z "$HINT" ]; then
  echo "PASS"
else
  echo "FAIL"
fi
EOSRC
  )
  expected_result = "PASS"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_power_nap_disable" {
  name = "[mSCP] - macOS - Disable Power Nap"
  description = trimspace(<<EODESC
Power Nap _MUST_ be disabled.

NOTE: Power Nap allows your Mac to perform actions while a Mac is asleep. This can interfere with USB power and may cause devices such as smartcards to stop functioning until a reboot and must therefore be disabled on all applicable systems.

The following Macs support Power Nap:

* MacBook (Early 2015 and later)
* MacBook Air (Late 2010 and later)
* MacBook Pro (all models with Retina display)
* Mac mini (Late 2012 and later)
* iMac (Late 2012 and later)
* Mac Pro (Late 2013 and later)
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/pmset -g custom | /usr/bin/awk '/powernap/ { sum+=$2 } END {print sum}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = false
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_root_disable" {
  name = "[mSCP] - macOS - Disable Root Login"
  description = trimspace(<<EODESC
To assure individual accountability and prevent unauthorized access, logging in as root at the login window _MUST_ be disabled.

The macOS system _MUST_ require individuals to be authenticated with an individual authenticator prior to using a group authenticator, and administrator users _MUST_ never log in directly as root.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c "/usr/bin/false"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_safari_advertising_privacy_protection_enable" {
  name = "[mSCP] - macOS - Ensure Advertising Privacy Protection in Safari Is Enabled"
  description = trimspace(<<EODESC
Allow privacy-preserving measurement of ad effectiveness _MUST_ be enabled in Safari.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"WebKitPreferences.privateClickMeasurementEnabled" = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_safari_open_safe_downloads_disable" {
  name = "[mSCP] - macOS - Disable Automatic Opening of Safe Files in Safari"
  description = trimspace(<<EODESC
Open "safe" files after downloading _MUST_ be disabled in Safari.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'AutoOpenSafeDownloads = 0' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_safari_popups_disabled" {
  name = "[mSCP] - macOS - Ensure Pop-Up Windows are Blocked in Safari"
  description = trimspace(<<EODESC
Safari _MUST_ be configured to block Pop-Up windows.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'safariAllowPopups = 0' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_safari_prevent_cross-site_tracking_enable" {
  name = "[mSCP] - macOS - Ensure Prevent Cross-site Tracking in Safari Is Enabled"
  description = trimspace(<<EODESC
Prevent cross-site tracking _MUST_ be enabled in Safari.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles -P -o stdout | /usr/bin/grep -cE '"WebKitPreferences.storageBlockingPolicy" = 1|"WebKitStorageBlockingPolicy" = 1|"BlockStoragePolicy" =2' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_safari_show_full_website_address_enable" {
  name = "[mSCP] - macOS - Ensure Show Full Website Address in Safari Is Enabled"
  description = trimspace(<<EODESC
Show full website address _MUST_ be enabled in Safari.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'ShowFullURLInSmartSearchField = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_safari_show_status_bar_enabled" {
  name = "[mSCP] - macOS - Ensure Show Safari shows the Status Bar is Enabled"
  description = trimspace(<<EODESC
Safari _MUST_ be configured to show the status bar.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'ShowOverlayStatusBar = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_safari_warn_fraudulent_website_enable" {
  name = "[mSCP] - macOS - Ensure Warn When Visiting A Fraudulent Website in Safari Is Enabled"
  description = trimspace(<<EODESC
Warn when visiting a fraudulent website _MUST_ be enabled in Safari.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'WarnAboutFraudulentWebsites = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_show_filename_extensions_enable" {
  name = "[mSCP] - macOS - Enable Show All Filename Extensions"
  description = trimspace(<<EODESC
Show all filename extensions _MUST_ be enabled in the Finder.

[NOTE]
====
The check and fix are for the currently logged in user. To get the currently logged in user, run the following.
[source,bash]
----
CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' )
----
====
EODESC
  )
  type = "ZSH_BOOL"
  source = trimspace(<<EOSRC
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults read .GlobalPreferences AppleShowAllExtensions 2>/dev/null
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sip_enable" {
  name = "[mSCP] - macOS - Ensure System Integrity Protection is Enabled"
  description = trimspace(<<EODESC
System Integrity Protection (SIP) _MUST_ be enabled.

SIP is vital to protecting the integrity of the system as it prevents malicious users and software from making unauthorized and/or unintended modifications to protected files and folders; ensures the presence of an audit record generation capability for defined auditable events for all operating system components; protects audit tools from unauthorized access, modification, and deletion; restricts the root user account and limits the actions that the root user can perform on protected parts of the macOS; and prevents non-privileged users from granting other users direct access to the contents of their home directories and folders.

NOTE: SIP is enabled by default in macOS.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_software_update_deferral" {
  name = "[mSCP] - macOS - Ensure Software Update Deferment Is Less Than or Equal to 30 Days"
  description = trimspace(<<EODESC
Software updates _MUST_ be deferred for 30 days or less.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('enforcedSoftwareUpdateDelay')) || 0
  if ( timeout <= 30 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sudo_timeout_configure" {
  name = "[mSCP] - macOS - Configure Sudo Timeout Period to 0"
  description = trimspace(<<EODESC
The file /etc/sudoers _MUST_ include a timestamp_timeout of 0.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c "Authentication timestamp timeout: 0.0 minutes"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sudoers_timestamp_type_configure" {
  name = "[mSCP] - macOS - Configure Sudoers Timestamp Type"
  description = trimspace(<<EODESC
The file /etc/sudoers _MUST_ be configured to not include a timestamp_type of global or ppid and be configured for timestamp record types of tty.

This rule ensures that the "sudo" command will prompt for the administrator's password at least once in each newly opened terminal window. This prevents a malicious user from taking advantage of an unlocked computer or an abandoned logon session by bypassing the normal password prompt requirement.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/awk -F": " '/Type of authentication timestamp record/{print $2}'
EOSRC
  )
  expected_result = "tty"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_system_wide_applications_configure" {
  name = "[mSCP] - macOS - Ensure Appropriate Permissions Are Enabled for System Wide Applications"
  description = trimspace(<<EODESC
Applications in the System Applications Directory (/Applications) _MUST_ not be world-writable.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/find /Applications -iname "*\.app" -type d -perm -2 -ls | /usr/bin/wc -l | /usr/bin/xargs
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_terminal_secure_keyboard_enable" {
  name = "[mSCP] - macOS - Ensure Secure Keyboard Entry Terminal.app is Enabled"
  description = trimspace(<<EODESC
Secure keyboard entry _MUST_ be enabled in Terminal.app.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Terminal')\
.objectForKey('SecureKeyboardEntry').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_time_offset_limit_configure" {
  name = "[mSCP] - macOS - Ensure Time Offset Within Limits"
  description = trimspace(<<EODESC
The macOS system time  _MUST_ be monitored to not drift more than four minutes and thirty seconds.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/sntp $(/usr/sbin/systemsetup -getnetworktimeserver | /usr/bin/awk '{print $4}') | /usr/bin/awk -F'.' '/\+\/\-/{if (substr($1,2) >= 270) {print "No"} else {print "Yes"}}'
EOSRC
  )
  expected_result = "Yes"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_unlock_active_user_session_disable" {
  name = "[mSCP] - macOS - Disable Login to Other User's Active and Locked Sessions"
  description = trimspace(<<EODESC
The ability to log in to another user's active or locked session _MUST_ be disabled.

macOS has a privilege that can be granted to any user that will allow that user to unlock active user's sessions. Disabling the admins and/or user's ability to log into another user's active and locked session prevents unauthorized persons from viewing potentially sensitive and/or personal information.

NOTE: Configuring this setting will change the user experience and disable TouchID from unlocking the screensaver. To restore the user experience and allow TouchID to unlock the screensaver, you can run `/usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.loginwindow screenUnlockMode -int 1`. This setting can also be deployed with a configuration profile.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/security authorizationdb read system.login.screensaver 2>&1 | /usr/bin/grep -c '<string>authenticate-session-owner</string>'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_world_writable_system_folder_configure" {
  name = "[mSCP] - macOS - Ensure No World Writable Files Exist in the System Folder"
  description = trimspace(<<EODESC
Folders in /System/Volumes/Data/System _MUST_ not be world-writable.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/find /System/Volumes/Data/System -type d -perm -2 -ls | /usr/bin/grep -vE "downloadDir|locks" | /usr/bin/wc -l | /usr/bin/xargs
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_account_lockout_enforce" {
  name = "[mSCP] - Password Policy - Limit Consecutive Failed Login Attempts to 3"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to limit the number of failed login attempts to a maximum of 3. When the maximum number of failed attempts is reached, the account _MUST_ be locked for a period of time after.

This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 <= 3) {print "yes"} else {print "no"}}'
EOSRC
  )
  expected_result = "yes"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_account_lockout_timeout_enforce" {
  name = "[mSCP] - Password Policy - Set Account Lockout Time to 15 Minutes"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to enforce a lockout time period of at least 15 minutes when the maximum number of failed logon attempts is reached.

This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="autoEnableInSeconds"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1/60 >= 15 ) {print "yes"} else {print "no"}}'
EOSRC
  )
  expected_result = "yes"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_history_enforce" {
  name = "[mSCP] - Password Policy - Prohibit Password Reuse for a Minimum of 5 Generations"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to enforce a password history of at least 5 previous passwords when a password is created.

This rule ensures that users are  not allowed to re-use a password that was used in any of the 5 previous password generations.

Limiting password reuse protects against malicious users attempting to gain access to the system via brute-force hacking methods.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributePasswordHistoryDepth"]/following-sibling::*[1]/text()' - | /usr/bin/awk '{ if ($1 >= 5 ) {print "yes"} else {print "no"}}'
EOSRC
  )
  expected_result = "yes"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_max_lifetime_enforce" {
  name = "[mSCP] - Password Policy - Restrict Maximum Password Lifetime to 60 Days"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to enforce a maximum password lifetime limit of at least 60 days.

This rule ensures that users are forced to change their passwords frequently enough to prevent malicious users from gaining and maintaining access to the system.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeExpiresEveryNDays"]/following-sibling::*[1]/text()' -
EOSRC
  )
  expected_result = "60"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_minimum_length_enforce" {
  name = "[mSCP] - Password Policy - Require a Minimum Password Length of 15 Characters"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to require a minimum of 15 characters be used when a password is created.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''.{15,}'\''")])' -
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_airplay_receiver_disable" {
  name = "[mSCP] - System Settings - Disable Airplay Receiver"
  description = trimspace(<<EODESC
Airplay Receiver allows you to send content from another Apple device to be displayed on the screen as it's being played from your other device.

Support for Airplay Receiver is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirPlayIncomingRequests').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_automatic_login_disable" {
  name = "[mSCP] - System Settings - Disable Unattended or Automatic Logon to the System"
  description = trimspace(<<EODESC
Automatic logon _MUST_ be disabled.

When automatic logons are enabled, the default user account is automatically logged on at boot time without prompting the user for a password. Even if the screen is later locked, a malicious user would be able to reboot the computer and find it already logged in. Disabling automatic logons mitigates this risk.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('com.apple.login.mcx.DisableAutoLoginClient').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_bluetooth_menu_enable" {
  name = "[mSCP] - System Settings - Enable Bluetooth Menu"
  description = trimspace(<<EODESC
The bluetooth menu _MUST_ be enabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.controlcenter')\
.objectForKey('Bluetooth').js
EOS
EOSRC
  )
  expected_result = "18"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_bluetooth_sharing_disable" {
  name = "[mSCP] - System Settings - Disable Bluetooth Sharing"
  description = trimspace(<<EODESC
Bluetooth Sharing _MUST_ be disabled.

Bluetooth Sharing allows users to wirelessly transmit files between the macOS and Bluetooth-enabled devices, including personally owned cellphones and tablets. A malicious user might introduce viruses or malware onto the system or extract sensitive files via Bluetooth Sharing. When Bluetooth Sharing is disabled, this risk is mitigated.

[NOTE]
====
The check and fix are for the currently logged in user. To get the currently logged in user, run the following.
[source,bash]
----
CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' )
----
====
EODESC
  )
  type = "ZSH_BOOL"
  source = trimspace(<<EOSRC
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_cd_dvd_sharing_disable" {
  name = "[mSCP] - System Settings - Disable CD/DVD Sharing"
  description = trimspace(<<EODESC
CD/DVD Sharing _MUST_ be disabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/pgrep -q ODSAgent; /bin/echo $?
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_critical_update_install_enforce" {
  name = "[mSCP] - System Settings - Enforce Critical Security Updates to be Installed"
  description = trimspace(<<EODESC
Ensure that security updates are installed as soon as they are available from Apple.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('CriticalUpdateInstall').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_filevault_enforce" {
  name = "[mSCP] - System Settings - Enforce FileVault"
  description = trimspace(<<EODESC
FileVault _MUST_ be enforced.

The information system implements cryptographic mechanisms to protect the confidentiality and integrity of information stored on digital media during transport outside of controlled areas.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
dontAllowDisable=$(/usr/bin/osascript -l JavaScript << EOS
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
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_firewall_enable" {
  name = "[mSCP] - System Settings - Enable macOS Application Firewall"
  description = trimspace(<<EODESC
The macOS Application Firewall is the built-in firewall that comes with macOS, and it _MUST_ be enabled.

When the macOS Application Firewall is enabled, the flow of information within the information system and between interconnected systems will be controlled by approved authorizations.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
profile="$(/usr/bin/osascript -l JavaScript << EOS
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
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_firewall_stealth_mode_enable" {
  name = "[mSCP] - System Settings - Enable Firewall Stealth Mode"
  description = trimspace(<<EODESC
Firewall Stealth Mode _MUST_ be enabled.

When stealth mode is enabled, the Mac will not respond to any probing requests, and only requests from authorized applications will still be authorized.

[IMPORTANT]
====
Enabling firewall stealth mode may prevent certain remote mechanisms used for maintenance and compliance scanning from properly functioning. Information System Security Officers (ISSOs) are advised to first fully weigh the potential risks posed to their organization before opting not to enable stealth mode.
====
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
profile="$(/usr/bin/osascript -l JavaScript << EOS
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
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_guest_access_smb_disable" {
  name = "[mSCP] - System Settings - Disable Guest Access to Shared SMB Folders"
  description = trimspace(<<EODESC
Guest access to shared Server Message Block (SMB) folders _MUST_ be disabled.

Turning off guest access prevents anonymous users from accessing files shared via SMB.
EODESC
  )
  type = "ZSH_BOOL"
  source = trimspace(<<EOSRC
/usr/bin/defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_guest_account_disable" {
  name = "[mSCP] - System Settings - Disable the Guest Account"
  description = trimspace(<<EODESC
Guest access _MUST_ be disabled.

Turning off guest access prevents anonymous users from accessing files.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
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
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_install_macos_updates_enforce" {
  name = "[mSCP] - System Settings - Enforce macOS Updates are Automatically Installed"
  description = trimspace(<<EODESC
Software Update _MUST_ be configured to enforce automatic installation of macOS updates is enabled.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticallyInstallMacOSUpdates').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_internet_sharing_disable" {
  name = "[mSCP] - System Settings - Disable Internet Sharing"
  description = trimspace(<<EODESC
If the system does not require Internet sharing, support for it is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling Internet sharing helps prevent the unauthorized connection of devices, unauthorized transfer of information, and unauthorized tunneling.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('forceInternetSharingOff').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_loginwindow_loginwindowtext_enable" {
  name = "[mSCP] - System Settings - Configure Login Window to Show A Custom Message"
  description = trimspace(<<EODESC
The login window _MUST_ be configured to show a custom access warning message.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS | /usr/bin/base64
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('LoginwindowText').js
EOS
EOSRC
  )
  expected_result = base64encode("Center for Internet Security Test Message\n")
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_loginwindow_prompt_username_password_enforce" {
  name = "[mSCP] - System Settings - Configure Login Window to Prompt for Username and Password"
  description = trimspace(<<EODESC
The login window _MUST_ be configured to prompt all users for both a username and a password.

By default, the system displays a list of known users on the login window, which can make it easier for a malicious user to gain access to someone else's account. Requiring users to type in both their username and password mitigates the risk of unauthorized users gaining access to the information system.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('SHOWFULLNAME').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_password_hints_disable" {
  name = "[mSCP] - System Settings - Disable Password Hints"
  description = trimspace(<<EODESC
Password hints _MUST_ be disabled.

Password hints leak information about passwords that are currently in use and can lead to loss of confidentiality.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('RetriesUntilHint').js
EOS
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_personalized_advertising_disable" {
  name = "[mSCP] - System Settings - Disable Personalized Advertising"
  description = trimspace(<<EODESC
Ad tracking and targeted ads _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling ad tracking ensures that applications and advertisers are unable to track users' interests and deliver targeted advertisements.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowApplePersonalizedAdvertising').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_printer_sharing_disable" {
  name = "[mSCP] - System Settings - Disable Printer Sharing"
  description = trimspace(<<EODESC
Printer Sharing _MUST_ be disabled.
EODESC
  )
  type = "ZSH_BOOL"
  source = trimspace(<<EOSRC
/usr/sbin/cupsctl | /usr/bin/grep -c "_share_printers=0"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_rae_disable" {
  name = "[mSCP] - System Settings - Disable Remote Apple Events"
  description = trimspace(<<EODESC
If the system does not require Remote Apple Events, support for Apple Remote Events is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling Remote Apple Events helps prevent the unauthorized connection of devices, the unauthorized transfer of information, and unauthorized tunneling.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AEServer" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_remote_management_disable" {
  name = "[mSCP] - System Settings - Disable Remote Management"
  description = trimspace(<<EODESC
Remote Management _MUST_ be disabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "RemoteDesktopEnabled = 0"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_screen_sharing_disable" {
  name = "[mSCP] - System Settings - Disable Screen Sharing and Apple Remote Desktop"
  description = trimspace(<<EODESC
Support for both Screen Sharing and Apple Remote Desktop (ARD) is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling screen sharing and ARD helps prevent the unauthorized connection of devices, the unauthorized transfer of information, and unauthorized tunneling.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.screensharing" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_screensaver_ask_for_password_delay_enforce" {
  name = "[mSCP] - System Settings - Enforce Session Lock After Screen Saver is Started"
  description = trimspace(<<EODESC
A screen saver _MUST_ be enabled and the system _MUST_ be configured to require a password to unlock once the screensaver has been on for a maximum of 5 seconds.

An unattended system with an excessive grace period is vulnerable to a malicious user.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
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
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_screensaver_timeout_enforce" {
  name = "[mSCP] - System Settings - Enforce Screen Saver Timeout"
  description = trimspace(<<EODESC
The screen saver timeout _MUST_ be set to 1200 seconds or a shorter length of time.

This rule ensures that a full session lock is triggered within no more than 1200 seconds of inactivity.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('idleTime'))
  if ( timeout <= 1200 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_smbd_disable" {
  name = "[mSCP] - System Settings - Disable Server Message Block Sharing"
  description = trimspace(<<EODESC
Support for Server Message Block (SMB) file sharing is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.smbd" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_software_update_app_update_enforce" {
  name = "[mSCP] - System Settings - Enforce Software Update App Update Updates Automatically"
  description = trimspace(<<EODESC
Software Update _MUST_ be configured to enforce automatic updates of App Updates is enabled.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticallyInstallAppUpdates').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_software_update_download_enforce" {
  name = "[mSCP] - System Settings - Enforce Software Update Downloads Updates Automatically"
  description = trimspace(<<EODESC
Software Update _MUST_ be configured to enforce automatic downloads of updates is enabled.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticDownload').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_software_update_enforce" {
  name = "[mSCP] - System Settings - Enforce Software Update Automatically"
  description = trimspace(<<EODESC
Software Update _MUST_ be configured to enforce automatic update is enabled.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticCheckEnabled').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_softwareupdate_current" {
  name = "[mSCP] - System Settings - Ensure Software Update is Updated and Current"
  description = trimspace(<<EODESC
Make sure Software Update is updated and current.

NOTE: Automatic fix can cause unplanned restarts and may lose work.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
softwareupdate_date_epoch=$(/bin/date -j -f "%Y-%m-%d" "$(/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist LastFullSuccessfulDate | /usr/bin/awk '{print $1}')" "+%s")
thirty_days_epoch=$(/bin/date -v -30d "+%s")
if [[ $softwareupdate_date_epoch -lt $thirty_days_epoch ]]; then
  /bin/echo "0"
else
  /bin/echo "1"
fi
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_ssh_disable" {
  name = "[mSCP] - System Settings - Disable SSH Server for Remote Access Sessions"
  description = trimspace(<<EODESC
SSH service _MUST_ be disabled for remote access.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.openssh.sshd" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_system_wide_preferences_configure" {
  name = "[mSCP] - System Settings - Require Administrator Password to Modify System-Wide Preferences"
  description = trimspace(<<EODESC
The system _MUST_ be configured to require an administrator password in order to modify the system-wide preferences in System Settings.

Some Preference Panes in System Settings contain settings that affect the entire system. Requiring a password to unlock these system-wide settings reduces the risk of a non-authorized user modifying system configurations.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")
result="1"
for section in $${authDBs[@]}; do
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "shared")]/following-sibling::*[1])' -) != "false" ]]; then
    result="0"
  fi
  if [[ $(security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath '//*[contains(text(), "group")]/following-sibling::*[1]/text()' - ) != "admin" ]]; then
    result="0"
  fi
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "authenticate-user")]/following-sibling::*[1])' -) != "true" ]]; then
    result="0"
  fi
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "session-owner")]/following-sibling::*[1])' -) != "false" ]]; then
    result="0"
  fi
done
echo $result
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_time_machine_encrypted_configure" {
  name = "[mSCP] - System Settings - Ensure Time Machine Volumes are Encrypted"
  description = trimspace(<<EODESC
Time Machine volumes _MUST_ be encrypted.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
error_count=0
for tm in $(/usr/bin/tmutil destinationinfo 2>/dev/null| /usr/bin/awk -F': ' '/Name/{print $2}'); do
  tmMounted=$(/usr/sbin/diskutil info "$${tm}" 2>/dev/null | /usr/bin/awk '/Mounted/{print $2}')
  tmEncrypted=$(/usr/sbin/diskutil info "$${tm}" 2>/dev/null | /usr/bin/awk '/FileVault/{print $2}')
  if [[ "$tmMounted" = "Yes" && "$tmEncrypted" = "No" ]]; then
      ((error_count++))
  fi
done
echo "$error_count"
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_time_server_configure" {
  name = "[mSCP] - System Settings - Configure macOS to Use an Authorized Time Server"
  description = trimspace(<<EODESC
Approved time server _MUST_ be the only server configured for use. As of macOS 10.13 only one time server is supported.

This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('timeServer').js
EOS
EOSRC
  )
  expected_result = "time.nist.gov"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_time_server_enforce" {
  name = "[mSCP] - System Settings - Enforce macOS Time Synchronization"
  description = trimspace(<<EODESC
Time synchronization _MUST_ be enforced on all networked systems.

This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.timed')\
.objectForKey('TMAutomaticTimeOnlyEnabled').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_wake_network_access_disable" {
  name = "[mSCP] - System Settings - Ensure Wake for Network Access Is Disabled"
  description = trimspace(<<EODESC
Wake for network access _MUST_ be disabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/pmset -g custom | /usr/bin/awk '/womp/ { sum+=$2 } END {print sum}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_wifi_menu_enable" {
  name = "[mSCP] - System Settings - Enable Wifi Menu"
  description = trimspace(<<EODESC
The WiFi menu _MUST_ be enabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.controlcenter')\
.objectForKey('WiFi').js
EOS
EOSRC
  )
  expected_result = "18"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

