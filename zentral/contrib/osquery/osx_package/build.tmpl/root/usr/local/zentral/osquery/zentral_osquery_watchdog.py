#!/usr/bin/python
from datetime import datetime
import os
import plistlib
import re
import subprocess
import time


LOG_ERR_RE = re.compile("((Too many open files)|(System performance limits exceeded))")


def inspect_logfile(filename):
    stat_result = os.stat(filename)
    d = {"filename": os.path.realpath(filename),
         "device": stat_result.st_dev,
         "inode": stat_result.st_ino,
         "ctime": datetime.utcfromtimestamp(stat_result.st_ctime),
         "mtime": datetime.utcfromtimestamp(stat_result.st_mtime),
         "timestamp": datetime.utcnow()}

    err_num = 0
    line_num = 0
    with open(filename) as f:
        for line in f.readlines():
            line_num += 1
            if LOG_ERR_RE.search(line):
                err_num += 1

    d["line_num"] = line_num
    d["err_num"] = err_num
    return d


def read_results(filename):
    if os.path.exists(filename):
        return plistlib.readPlist(filename)


def write_results(results, filename):
    plistlib.writePlist(results, filename)


def reset(database_path, launchd_plist):
    # stop osqueryd
    subprocess.check_call(["/bin/launchctl", "unload", launchd_plist])
    time.sleep(1)
    # delete db
    for filename in os.listdir(database_path):
        os.unlink(os.path.join(database_path, filename))
    # start osqueryd
    subprocess.check_call(["/bin/launchctl", "load", launchd_plist])


def run(launchd_plist, database_path, log_file, registry_file):
    pr = read_results(registry_file)
    r = inspect_logfile(log_file)
    if r["err_num"]:
        # errors. reset
        reset(database_path, launchd_plist)
        reset_dict = r.copy()
        reset_dict["timestamp"] = datetime.utcnow()
        r["last_reset"] = reset_dict
    else:
        if pr:
            r["last_reset"] = pr.get("last_reset") or False
        else:
            r["last_reset"] = False
    write_results(r, registry_file)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("launchd_plist", help="osqueryd launchd plist")
    parser.add_argument("database_path", help="osqueryd database path")
    parser.add_argument("log_file", help="osqueryd log file to watch")
    parser.add_argument("registry_file", help="registry file to keep track of the log file inspections")
    args = parser.parse_args()
    run(args.launchd_plist, args.database_path, args.log_file, args.registry_file)
