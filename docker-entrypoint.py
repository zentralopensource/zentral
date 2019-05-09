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
    i = 0
    while not django_migrate_db():
        retry_delay = (i + 1) * random.uniform(0.8, 1.2)
        warnings.warn("Can't migrate DB! Sleep {:.2f}s…".format(retry_delay))
        time.sleep(retry_delay)
        i += 1
    print("DB migration OK")


def django_collectstatic():
    subprocess.check_call(['python', 'server/manage.py', 'collectstatic', '-v0', '--noinput'])


KNOWN_COMMANDS = {
    "runserver": ["python", 'server/manage.py', 'runserver', '0.0.0.0:8000'],
    "gunicorn": ["gunicorn", "--chdir", "/zentral/server",
                             "-b", "0.0.0.0:8000",
                             "-w", "4",
                             "--access-logfile", "-",
                             "--error-logfile", "-",
                             "server.wsgi"],
    "runworkers": ["python", 'server/manage.py', 'runworkers'],
    "celery": ["/usr/local/bin/celery", "-A", "server", "worker"],
    # extras
    "shell": ["python", 'server/manage.py', 'shell'],
    "tests": ["python", 'server/manage.py', 'test', 'tests/'],
    "createuser": ["python", 'server/manage.py', 'create_zentral_user'],
}

KNOWN_COMMANDS_EXTRA_ENV = {
    "tests": {"ZENTRAL_PROBES_SYNC": "0"}
}

KNOWN_COMMANDS_CHDIR = {
    "celery": "/zentral/server"
}

KNOWN_COMMANDS_TRIGGERING_COLLECTSTATIC = {'runserver', 'gunicorn'}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        warnings.warn("Not enough arguments.")
        sys.exit(2)
    cmd = sys.argv[1]
    env = os.environ.copy()
    args = KNOWN_COMMANDS.get(cmd, None)
    if args:
        filename = args[0]
        args.extend(sys.argv[2:])
        wait_for_db_migration()
        if cmd in KNOWN_COMMANDS_TRIGGERING_COLLECTSTATIC:
            django_collectstatic()
        env.update(KNOWN_COMMANDS_EXTRA_ENV.get(cmd, {}))
        wd = KNOWN_COMMANDS_CHDIR.get(cmd)
        if wd:
            os.chdir(wd)
        print('Launch known command "{}"'.format(cmd))
    else:
        filename = cmd
        args = sys.argv[1:]
    os.execvpe(filename, args, env)
