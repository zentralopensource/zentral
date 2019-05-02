#!/usr/bin/python
# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
import json
import os
import plistlib
import ssl
import subprocess
import time
import urllib2
from Foundation import CFPreferencesCopyAppValue
from SystemConfiguration import SCDynamicStoreCopyConsoleUser

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

MUNKI_APPLICATION_ID = "ManagedInstalls"
MONOLITH_HEADERS_PREF_KEY = "AdditionalHttpHeaders"
MONOLITH_TOKEN_HEADER_KEY = "X-Monolith-Token"
MAX_REGISTRATION_WAIT = 7200  # 2 hours
REGISTRATION_URL = "%REGISTRATION_URL%"
USER_AGENT = "Zentral/monolithrunonce 0.1"
TLS_SERVER_CERTS = "%TLS_SERVER_CERTS%"

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


def cleanup_registration_date(registration_data):
    registration_date = registration_data.get("Registration Date")
    try:
        registration_date = datetime.strptime(registration_date, "%m-%d-%Y %H:%M")
    except (TypeError, ValueError):
        pass
    else:
        utc_offset = timedelta(seconds=time.altzone if time.daylight else time.timezone)
        registration_data["registration_date"] = (registration_date + utc_offset).isoformat()


def get_monolith_auth_header():
    for header in CFPreferencesCopyAppValue(MONOLITH_HEADERS_PREF_KEY, MUNKI_APPLICATION_ID):
        if header.startswith(MONOLITH_TOKEN_HEADER_KEY):
            return MONOLITH_TOKEN_HEADER_KEY, header.split(":", 1)[-1].strip()
    print "Could not get the monolith token"


def post_registration_data(registration_data):
    req = urllib2.Request(REGISTRATION_URL)
    req.add_header(*get_monolith_auth_header())
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Content-Type", "application/json")
    ctx = ssl.create_default_context(cafile=TLS_SERVER_CERTS or None)
    resp = urllib2.urlopen(req, data=json.dumps(registration_data), context=ctx)
    return json.load(resp)


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
            cleanup_registration_date(registration_data)
            try:
                resp_data = post_registration_data(registration_data)
            except Exception:
                print "Could not post the registration data"
                return False
            else:
                try:
                    os.unlink(DEPNOTIFY_REGISTRATION_DATA_PATH)
                except Exception:
                    print "Could not remove the depnotify registration data"
                return resp_data.get("do_munki_run", False)
        else:
            time.sleep(5)
    return False


def cleanup_depnotify():
    # write the quit command
    if os.path.exists(DEPNOTIFY_CONTROL_FILE):
        with open(DEPNOTIFY_CONTROL_FILE, "r") as f:
            command_lines = [l.strip() for l in f.readlines()]
        if not command_lines or not command_lines[-1].startswith(DEPNOTIFY_QUIT_COMMAND):
            command_lines.append(DEPNOTIFY_QUIT_COMMAND)
        with open(DEPNOTIFY_CONTROL_FILE, "w") as f:
            f.write("\n".join(command_lines))
    # remove the launch agent
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
