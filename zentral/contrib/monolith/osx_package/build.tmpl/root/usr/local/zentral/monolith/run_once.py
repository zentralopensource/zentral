#!/usr/bin/python
# -*- coding: utf-8 -*-
from SystemConfiguration import SCDynamicStoreCopyConsoleUser
import subprocess
import os
import time

CAFFEINATE = "/usr/bin/caffeinate"
MANAGED_SOFTWARE_UPDATE = "/usr/local/munki/managedsoftwareupdate"

# munki daemons
MUNKI_DAEMONS_CONFIG_FILES = [
    "/Library/LaunchDaemons/com.googlecode.munki.{}.plist".format(name)
    for name in ("managedsoftwareupdate-check",
                 "managedsoftwareupdate-install",
                 "managedsoftwareupdate-manualcheck",
                 "logouthelper")
]


DEPNOTIFY_CONTROL_FILE = "/var/tmp/depnotify.log"
DEPNOTIFY_QUIT_COMMAND = "Command: Quit"
DEPNOTIFY_LAUNCH_AGENT_PLIST = "/Library/LaunchAgents/io.zentral.monolith.depnotify.plist"
DEPNOTIFY_APP_DIR = "/Applications/Utilities/DEPNotify.app"


def get_console_user():
    cfuser = SCDynamicStoreCopyConsoleUser(None, None, None)
    console_user = cfuser[0]
    print "console user:", console_user or "-"
    return console_user


def wait_for_userland():
    while get_console_user() in (None, "loginwindow", "_mbsetupuser"):
        print "wait for real console user..."
        time.sleep(1)


def launch_munki_daemons():
    for config_file in MUNKI_DAEMONS_CONFIG_FILES:
        print "load", config_file
        subprocess.call(['/bin/launchctl', 'load', config_file])


def do_munki_run():
    args = [MANAGED_SOFTWARE_UPDATE, "-a"]
    if os.path.isfile(CAFFEINATE) and os.access(CAFFEINATE, os.X_OK):
        args[0:0] = [CAFFEINATE, "-dium"]
    print " ".join(args)
    subprocess.call(args)


def cleanup_depnotify():
    # write the quit command
    if os.path.exists(DEPNOTIFY_CONTROL_FILE):
        last_line_quit = False
        with open(DEPNOTIFY_CONTROL_FILE, "r") as f:
            for line in f.readlines():
                last_line_quit = line.startswith(DEPNOTIFY_QUIT_COMMAND)
        if not last_line_quit:
            with open(DEPNOTIFY_CONTROL_FILE, "a") as f:
                f.write("{}\n".format(DEPNOTIFY_QUIT_COMMAND))


def launch_depnotify():
    if os.path.isdir(DEPNOTIFY_APP_DIR):
        subprocess.call(["/usr/bin/open", DEPNOTIFY_APP_DIR, "--args", "-munki"])


if __name__ == "__main__":
    wait_for_userland()
    launch_depnotify()
    launch_munki_daemons()
    do_munki_run()
    cleanup_depnotify()
