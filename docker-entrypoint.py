#!/usr/bin/env python
# -*- coding:utf-8 -*-
import multiprocessing
import os
import random
import subprocess
import sys
import time
import warnings
try:
    random = random.SystemRandom()
except NotImplementedError:
    warnings.warn('No secure pseudo random number generator available.')


def wait_for_db_migration():
    i = 0
    while True:
        try:
            subprocess.check_call(['python', 'server/manage.py', 'migrate', '--noinput'])
        except subprocess.CalledProcessError:
            retry_delay = min(20, (i + 1)) * random.uniform(0.8, 1.2)
            warnings.warn("Can't migrate DB! Sleep {:.1f}s…".format(retry_delay))
            time.sleep(retry_delay)
            i += 1
        else:
            break
    print("DB migration OK")


def django_collectstatic():
    subprocess.check_call(['python', 'server/manage.py', 'collectstatic', '-v0', '--noinput'])


KNOWN_COMMANDS = {
    "runserver": ["python", 'server/manage.py', 'runserver', '0.0.0.0:8000'],
    "gunicorn": ["gunicorn", "--chdir", "/zentral/server",
                             "-b", "0.0.0.0:8000",
                             "-w", str(2 * multiprocessing.cpu_count() + 1),
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
