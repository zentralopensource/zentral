#!/bin/bash

printer_name="{{ printer.get_destination }}"

if /usr/bin/lpstat -p "$printer_name" &> /dev/null || [ -e "/private/etc/cups/deployment/receipts/$printer_name.plist" ];
then
  exit 0
else
  exit 1
fi
