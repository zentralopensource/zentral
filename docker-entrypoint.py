#!/usr/bin/env python
# -*- coding:utf-8 -*-
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


def wait_for_db(env):
    i = 0
    while True:
        try:
            subprocess.run(['python', 'server/manage.py', 'shell', '-c',
                            'import django;django.db.connection.ensure_connection()'],
                           stderr=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,
                           check=True,
                           env=env)
        except subprocess.CalledProcessError:
            retry_delay = min(20, (i + 1)) * random.uniform(0.8, 1.2)
            warnings.warn(f"Cannot connect to DB! Sleep {retry_delay:.1f}s…")
            time.sleep(retry_delay)
            i += 1
        else:
            break
    print("DB connection OK")


def wait_for_db_migration():
    i = 0
    while True:
        try:
            subprocess.run(['python', 'server/manage.py', 'migrate', '--noinput'], check=True)
        except subprocess.CalledProcessError:
            retry_delay = min(20, (i + 1)) * random.uniform(0.8, 1.2)
            warnings.warn(f"Can't migrate DB! Sleep {retry_delay:.1f}s…")
            time.sleep(retry_delay)
            i += 1
        else:
            break
    print("DB migration OK")


def wait_for_provisioning():
    i = 0
    while True:
        try:
            subprocess.run(['python', 'server/manage.py', 'provision'], check=True)
        except subprocess.CalledProcessError:
            retry_delay = min(20, (i + 1)) * random.uniform(0.8, 1.2)
            warnings.warn(f"Can't do provisioning! Sleep {retry_delay:.1f}s…")
            time.sleep(retry_delay)
            i += 1
        else:
            break
    print("Provisioning OK")


def django_collectstatic():
    subprocess.run(['python', 'server/manage.py', 'collectstatic', '-v0', '--noinput'], check=True)


def create_zentral_superuser():
    username = os.environ.get("ZENTRAL_ADMIN_USERNAME")
    email = os.environ.get("ZENTRAL_ADMIN_EMAIL")
    if username and email:
        print("Found admin username and email in environment. "
              "Create superuser if missing.", flush=True)
        args = ['python', 'server/manage.py', 'create_zentral_user', '--superuser']
        force = os.environ.get("ZENTRAL_FORCE_ADMIN_PASSWORD_RESET")
        if not force or force.upper() not in ("1", "TRUE", "YES", "Y"):
            args.append("--skip-if-existing")
        args.extend([username, email])
        try:
            subprocess.run(args, check=True)
        except subprocess.CalledProcessError:
            print("Could not create superuser!!!", flush=True)
    else:
        print("Admin username and email not found", flush=True)


KNOWN_COMMANDS = {
    "runserver": ["python", 'server/manage.py', 'runserver', '0.0.0.0:8000'],
    "gunicorn": ["gunicorn",
                 "--worker-tmp-dir", "/dev/shm",
                 "--error-logfile", "-",
                 "--chdir", "/zentral/server", "server.wsgi"],
    "runworker": ["python", 'server/manage.py', 'runworker'],
    "runworkers": ["python", 'server/manage.py', 'runworkers'],
    "celery": ["celery", "-A", "server", "worker"],
    # extras
    "shell": ["python", 'server/manage.py', 'shell'],
    "tests": ["python", 'server/manage.py', 'test', 'tests/'],
    "tests_with_coverage": ["coverage", "run", 'server/manage.py', 'test', 'tests/'],
    "coverage_lcov": ["coverage", "lcov"],
    "createuser": ["python", 'server/manage.py', 'create_zentral_user'],
}

KNOWN_COMMANDS_EXTRA_ENV = {
    "tests": {"ZENTRAL_CONF_DIR": "/zentral/tests/conf",
              "ZENTRAL_FORCE_ES_OS_INDEX_REFRESH": "1",
              "ZENTRAL_PROBES_SYNC": "0",
              "ZENTRAL_STORES_SYNC": "0"},
    "tests_with_coverage": {"ZENTRAL_CONF_DIR": "/zentral/tests/conf",
                            "ZENTRAL_FORCE_ES_OS_INDEX_REFRESH": "1",
                            "ZENTRAL_PROBES_SYNC": "0",
                            "ZENTRAL_STORES_SYNC": "0"},
}

KNOWN_COMMANDS_CHDIR = {
    "celery": "/zentral/server"
}

KNOWN_COMMANDS_TRIGGERING_COLLECTSTATIC = {
    'gunicorn',  # the staticfiles manifest is needed!
    'runserver',
}


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
        env.update(KNOWN_COMMANDS_EXTRA_ENV.get(cmd, {}))
        if cmd != "tests":
            wait_for_db_migration()
            create_zentral_superuser()
        else:
            wait_for_db(env)
        wait_for_provisioning()
        if cmd in KNOWN_COMMANDS_TRIGGERING_COLLECTSTATIC:
            django_collectstatic()
        wd = KNOWN_COMMANDS_CHDIR.get(cmd)
        if wd:
            os.chdir(wd)
        print('Launch known command "{}"'.format(cmd), flush=True)
    else:
        filename = cmd
        args = sys.argv[1:]
    os.execvpe(filename, args, env)
