#!/bin/sh
printer_name="{{ printer.get_destination }}"

/usr/sbin/lpadmin -x $printer_name
rm -f /private/etc/cups/deployment/receipts/$printer_name.plist
rm -f "{{ printer.ppd.get_destination }}"
