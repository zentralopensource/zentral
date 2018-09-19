#!/usr/bin/python
# -*- coding: utf-8 -*-
from SystemConfiguration import SCDynamicStoreCopyConsoleUser
import subprocess
import os
import plistlib
import time

CAFFEINATE = "/usr/bin/caffeinate"
MANAGED_SOFTWARE_UPDATE = "/usr/local/munki/managedsoftwareupdate"
MAX_REGISTRATION_WAIT = 7200  # 2 hours

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
DEPNOTIFY_CONFIG_SOURCE_PATH = "/usr/local/zentral/monolith/menu.nomad.DEPNotify.plist"
DEPNOTIFY_REGISTRATION_DATA_PATH = "/Users/Shared/DEPNotify.plist"


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
    subprocess.call(args)


def register():
    """Wait for the DEPNotify registration data and post them.

    returns a boolean to indicate if a new munki run is needed.
    """
    if not os.path.exists(DEPNOTIFY_CONFIG_SOURCE_PATH):
        # no form configured for this run.
        # do not wait, do not trigger another munki run.
        return False
    start_t = time.time()
    while time.time() - start_t < MAX_REGISTRATION_WAIT:
        if os.path.exists(DEPNOTIFY_REGISTRATION_DATA_PATH):
            registration_data = plistlib.readPlist(DEPNOTIFY_REGISTRATION_DATA_PATH)
            # get the token
            # post the data
            # remove the depnotify config if registered = true in the response
            do_munki_run = True  # get the value from the HTTP json response
            return do_munki_run
        else:
            time.sleep(5)
    return False


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
    if os.path.exists(DEPNOTIFY_LAUNCH_AGENT_PLIST):
        subprocess.call(["/bin/launchctl", "unload", DEPNOTIFY_LAUNCH_AGENT_PLIST])
        os.unlink(DEPNOTIFY_LAUNCH_AGENT_PLIST)


def launch_depnotify():
    if os.path.exists(DEPNOTIFY_LAUNCH_AGENT_PLIST) and os.path.isdir(DEPNOTIFY_APP_DIR):
        # can fail if too early. usefull if not in a setup phase.
        subprocess.call(["/usr/bin/open", DEPNOTIFY_APP_DIR, "--args", "-munki"])


if __name__ == "__main__":
    wait_for_userland()
    launch_depnotify()
    launch_munki_daemons()
    do_munki_run()
    if register():
        # do another munki run after the registration if the server tells us to do it.
        # we may have tagged the machine and unlock the access to extra software.
        do_munki_run()
    cleanup_depnotify()
