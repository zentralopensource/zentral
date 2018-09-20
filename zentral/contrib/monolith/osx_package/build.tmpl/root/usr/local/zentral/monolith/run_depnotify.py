#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import shutil
import subprocess
import time

MUNKI_LOG_FILE = "/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log"
DEPNOTIFY_APP_DIR = "/Applications/Utilities/DEPNotify.app"
DEPNOTIFY_CONFIG_SOURCE_PATH = "/usr/local/zentral/monolith/menu.nomad.DEPNotify.plist"
DEPNOTIFY_CONFIG_DEST_PATH = "~/Library/Preferences/menu.nomad.DEPNotify.plist"


def copy_depnotify_configuration():
    if os.path.exists(DEPNOTIFY_CONFIG_SOURCE_PATH):
        try:
            shutil.copy(DEPNOTIFY_CONFIG_SOURCE_PATH,
                        os.path.expanduser(DEPNOTIFY_CONFIG_DEST_PATH))
        except Exception:
            print "Could not copy DEPNotify configuration"
    elif os.path.exists(DEPNOTIFY_CONFIG_DEST_PATH):
        try:
            os.unlink(DEPNOTIFY_CONFIG_DEST_PATH)
        except Exception:
            print "Could not remove existing DEPNotify configuration"


def wait_for_munki_log_file():
    while not os.path.exists(MUNKI_LOG_FILE):
        time.sleep(1)


def launch_depnotify():
    subprocess.call(["/usr/bin/open", DEPNOTIFY_APP_DIR, "--args", "-munki"])


if __name__ == "__main__":
    copy_depnotify_configuration()
    wait_for_munki_log_file()
    launch_depnotify()
