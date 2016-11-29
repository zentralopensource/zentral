#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import random
import socket
import subprocess
import sys
import time
import warnings
try:
    random = random.SystemRandom()
except NotImplementedError:
    warnings.warn('No secure pseudo random number generator available.')


def check_db_connection(connection):
    try:
        socket.create_connection(connection).close()
    except socket.error:
        return False
    else:
        return True


def wait_for_db():
    connection = (os.environ.get('POSTGRES_HOST', 'localhost'),
                  os.environ.get('POSTGRES_PORT', '5432'))
    while not check_db_connection(connection):
        reconnect_delay = 1000 / random.randint(500, 3000)
        warnings.warn("Can't connect to DB! Sleep {:.2f}s…".format(reconnect_delay))
        time.sleep(reconnect_delay)
    print("DB connection OK")


def django_migrate_db():
    try:
        subprocess.check_call(['python', 'server/manage.py', 'migrate', '--noinput'])
    except subprocess.CalledProcessError:
        return False
    else:
        return True


def wait_for_db_migration():
    wait_for_db()
    while not django_migrate_db():
        retry_delay = 1000 / random.randint(500, 3000)
        warnings.warn("Can't migrate DB! Sleep {:.2f}s…".format(retry_delay))
        time.sleep(retry_delay)
    print("DB migration OK")


KNOWN_COMMANDS = {
    "runserver": ["python", 'server/manage.py', 'runserver', '0.0.0.0:8000'],
    "gunicorn": ["gunicorn", "--chdir", "/zentral/server",
                             "-b", "0.0.0.0:8000",
                             "-w", "4",
                             "--access-logfile", "-",
                             "--error-logfile", "-",
                             "server.wsgi"],
    "inventory_worker": ["python", 'zentral/bin/inventory_worker.py'],
    "store_worker": ["python", 'zentral/bin/store_worker.py'],
    "processor_worker": ["python", 'zentral/bin/processor_worker.py'],
    # extras
    "shell": ["python", 'server/manage.py', 'shell'],
    "tests": ["python", 'server/manage.py', 'test', 'tests/'],
}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        warnings.warn("Not enough arguments.")
        sys.exit(2)
    cmd = sys.argv[1]
    args = KNOWN_COMMANDS.get(cmd, None)
    if args:
        filename = args[0]
        wait_for_db_migration()
        print('Launch known command "{}"'.format(cmd))
    else:
        filename = cmd
        args = sys.argv[1:]
    os.execvp(filename, args)
