#!/bin/sh

printer_name="{{ printer.get_destination }}"

/usr/bin/lpstat -p "$printer_name"

if [ $? -eq 0 ] || [ -e "/private/etc/cups/deployment/receipts/$printer_name.plist" ];
then
  exit 0
else
  exit 1
fi
