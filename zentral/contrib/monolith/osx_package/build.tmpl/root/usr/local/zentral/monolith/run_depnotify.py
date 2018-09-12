#!/usr/bin/python
# -*- coding: utf-8 -*-
import subprocess
import os
import time

MUNKI_LOG_FILE = "/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log"
DEPNOTIFY_APP_DIR = "/Applications/Utilities/DEPNotify.app"


def wait_for_munki_log_file():
    while not os.path.exists(MUNKI_LOG_FILE):
        time.sleep(1)


def launch_depnotify():
    subprocess.call(["/usr/bin/open", DEPNOTIFY_APP_DIR, "--args", "-munki"])


if __name__ == "__main__":
    wait_for_munki_log_file()
    launch_depnotify()
