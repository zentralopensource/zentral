#!/bin/bash

echo
echo 'Check Zentral configuration'
echo
/usr/bin/python3.4 /home/zentral/zentral/bin/check_configuration.py
if [ "$?" -eq 0 ] && [ "$1" = 'run' ]
then
  echo
  echo 'Launch supervisor'
  echo
  /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
fi
