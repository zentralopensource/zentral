#!/bin/bash

python3 /home/zentral/server/manage.py collectstatic -v0 --noinput
echo
echo 'Check Zentral configuration'
echo
python3.4 /home/zentral/zentral/bin/check_configuration.py
if [ "$?" -eq 0 ] && [ "$1" = 'run' ]
then
    python3 /home/zentral/server/manage.py migrate
fi

exec "$@"
