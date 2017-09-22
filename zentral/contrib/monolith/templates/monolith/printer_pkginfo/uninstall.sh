#!/bin/sh

# Based on 2010 Walter Meyer SUNY Purchase College (c)
# Modified by Nick McSpadden, 2013
# Adapted from Graham Gilbert project
# https://github.com/grahamgilbert/printer-pkginfo, Sept. 2017

printer_name="{{ printer.get_destination }}"

/usr/sbin/lpadmin -x $printer_name
rm -f /private/etc/cups/deployment/receipts/$printer_name.plist
rm -f "{{ printer.ppd.get_destination }}"
