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

if [ ! -z "$DB_PORT_5432_TCP_ADDR" ] ; then
	sed -i 's/pghostaddress/'"$DB_PORT_5432_TCP_ADDR"'/g' /home/zentral/conf/base.json
fi

exec "$@"
