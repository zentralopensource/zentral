#!/bin/bash

# Based on 2010 Walter Meyer SUNY Purchase College (c)
# Modified by Nick McSpadden, 2013
# Adapted from Graham Gilbert project
# https://github.com/grahamgilbert/printer-pkginfo, Sept. 2017

# Script to install and setup printers on a Mac OS X system in a "Munki-Friendly" way.
# Make sure to install the required drivers first!

# Variables. Edit these.
printer_name="{{ printer.get_destination }}"
current_version="{{ printer.version }}"

### Determine if receipt is installed ###
if [ -e "/private/etc/cups/deployment/receipts/$printer_name.plist" ]; then
    stored_version=$(/usr/libexec/PlistBuddy -c "Print :version" "/private/etc/cups/deployment/receipts/$printer_name.plist")
    echo "Stored version: $stored_version"
else
    stored_version="0"
fi

version_comparison=$(echo "$stored_version < $current_version" | bc -l)
# This will be 0 if the current receipt is greater than or equal to current version of the script

### Printer Install ###
# If the queue already exists (returns 0), we don't need to reinstall it.
if /usr/bin/lpstat -p "$printer_name" &> /dev/null; then
    if [ "$version_comparison" -eq 0 ]; then
        # We are at the current or greater version
        exit 1
    fi
    # We are of lesser version, and therefore we should delete the printer and reinstall.
    /usr/sbin/lpadmin -x "$printer_name"
fi

# Download the PPD
/usr/bin/curl -o "{{ printer.ppd.get_destination }}" "{{ printer.ppd.get_download_url }}"

# Now we can install the printer.
/usr/sbin/lpadmin \
    -p "$printer_name" \
    -v "{{ printer.scheme }}://{{ printer.address }}" \
    -P "{{ printer.ppd.get_destination }}" \
    -o printer-is-shared={{ printer.shared|lower }} \
    -o printer-error-policy={{ printer.error_policy }} \
    -D "{{ printer.name }}"{% if printer.location %} -L "{{ printer.location }}"{% endif %} \
    -E

# Create a receipt for the printer
mkdir -p /private/etc/cups/deployment/receipts
/usr/libexec/PlistBuddy -c "Add :version string" "/private/etc/cups/deployment/receipts/$printer_name.plist"
/usr/libexec/PlistBuddy -c "Set :version $current_version" "/private/etc/cups/deployment/receipts/$printer_name.plist"

# Permission the directories properly.
chown -R root:_lp /private/etc/cups/deployment
chmod -R 700 /private/etc/cups/deployment

exit 0
